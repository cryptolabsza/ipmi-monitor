# TRACEWEAVER: file-role=ipmi-account-pairing; req=REQ-PAIR-004; trace=TRACE-PAIR-004; ver=VER-PAIR-004
"""Outbound account pairing, with one encrypted, session-bound SQLite slot."""
import base64
from functools import wraps
import hashlib
import hmac
import json
import re
import secrets
import time
import uuid

from cryptography.fernet import Fernet
from flask import jsonify, request, session
from sqlalchemy.dialects.sqlite import insert


ORIGIN = 'https://www.cryptolabs.co.za'
API = ORIGIN + '/wp-json/cryptolabs/v1'
VERIFY_URI = ORIGIN + '/?clai_pair=1'
CLIENT_ID = 'cryptolabs-ipmi-monitor'


# TRACEWEAVER: entrypoint=register_account_link; req=REQ-PAIR-004; trace=TRACE-PAIR-004; ver=VER-PAIR-004
def register_account_link(runtime):
    """Register the bounded pairing store and local administrator endpoints."""
    app, db = runtime.app, runtime.db

    class AccountLinkAttempt(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        installation_id = db.Column(db.String(36), nullable=False)
        attempt_id = db.Column(db.String(64))
        owner = db.Column(db.String(100))
        session_digest = db.Column(db.String(64))
        config_digest = db.Column(db.String(64))
        expires_at = db.Column(db.Float, default=0)
        next_poll = db.Column(db.Float, default=0)
        interval = db.Column(db.Integer, default=5)
        state = db.Column(db.String(20), default='empty')
        protected = db.Column(db.Text)

    runtime.AccountLinkAttempt = AccountLinkAttempt

    def cipher():
        secret = app.secret_key
        if isinstance(secret, str):
            secret = secret.encode()
        key = hmac.new(secret, b'cryptolabs/account-pairing/storage/v1', hashlib.sha256).digest()
        return Fernet(base64.urlsafe_b64encode(key))

    def encode(value):
        return cipher().encrypt(json.dumps(value, separators=(',', ':')).encode()).decode()

    def decode(value):
        return json.loads(cipher().decrypt(value.encode()))

    def reply(body, status=200):
        response = jsonify(body)
        response.status_code = status
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    def failure(name, status=400):
        return reply({'error': name}, status)

    def live_admin():
        proxy = runtime.is_proxy_authenticated()
        if not session.get('logged_in') or session.get('user_role') != 'admin':
            return False
        if session.get('auth_via') == 'fleet_proxy':
            return proxy
        user = runtime.User.query.filter_by(username=session.get('username')).first()
        return bool(user and user.role == 'admin' and user.password_changed)

    def binding():
        subject = str(session.get('username')) + ':' + str(session.get('auth_via', 'local'))
        if session.get('pair_subject') != subject or not session.get('pair_binding'):
            session['pair_subject'] = subject
            session['pair_binding'] = secrets.token_urlsafe(32)
            session['pair_csrf'] = secrets.token_urlsafe(32)
        return hashlib.sha256(session['pair_binding'].encode()).hexdigest()

    def guarded(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            try:
                if not live_admin():
                    return failure('administrator_required', 403)
                binding()
                origin = request.headers.get('Origin')
                if ((origin and origin != request.host_url.rstrip('/')) or
                        request.headers.get('Sec-Fetch-Site') == 'cross-site'):
                    return failure('invalid_origin', 403)
                if request.method == 'POST':
                    token = request.headers.get('X-CSRF-Token', '')
                    if not token or not hmac.compare_digest(token, session['pair_csrf']):
                        return failure('invalid_csrf', 403)
                    if request.content_length is None or request.content_length > 2048:
                        return failure('invalid_request')
                return function(*args, **kwargs)
            except Exception:
                db.session.rollback()
                # Never log remote bodies, credentials, request headers or exception text.
                app.logger.warning('Account pairing unavailable; saved connection preserved')
                return failure('temporarily_unavailable', 503)
        return wrapped

    def body(fields):
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate field')
                result[key] = value
            return result
        try:
            if not request.is_json:
                return None
            value = json.loads(request.get_data(), object_pairs_hook=unique_object)
        except (ValueError, TypeError):
            return None
        if not isinstance(value, dict) or set(value) != set(fields):
            return None
        return value

    def fingerprint():
        config = runtime.CloudSync.query.first()
        if config is None:
            raise ValueError('cloud configuration no longer exists')
        values = [config.license_key, config.sync_enabled, config.sync_interval,
                  config.subscription_valid, config.subscription_tier, config.features, config.max_servers]
        return hashlib.sha256(json.dumps(values, separators=(',', ':')).encode()).hexdigest()

    def current(attempt_id, states=None):
        if not isinstance(attempt_id, str) or not 20 <= len(attempt_id) <= 64:
            return None
        db.session.expire_all()
        row = db.session.get(AccountLinkAttempt, 1)
        if not row or row.attempt_id != attempt_id:
            return None
        if row.owner != session['username'] or row.session_digest != binding():
            return None
        if row.expires_at <= time.time():
            AccountLinkAttempt.query.filter_by(id=1, attempt_id=attempt_id).update(
                {'state': 'expired', 'protected': None}, synchronize_session=False)
            db.session.commit()
            return None
        if states and row.state not in states:
            return None
        return row

    def cas(row, old_state, **updates):
        return AccountLinkAttempt.query.filter_by(id=1, attempt_id=row.attempt_id,
            owner=row.owner, session_digest=row.session_digest, state=old_state).filter(
                AccountLinkAttempt.expires_at > time.time()).update(updates, synchronize_session=False)

    def remote(path, payload, token=None):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        return runtime.requests.post(API + path, json=payload, headers=headers,
                                     timeout=10, verify=True, allow_redirects=False)

    def email(value):
        return (isinstance(value, str) and len(value) <= 254 and
                re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value))

    def exchange(value, installation_id):
        keys = {'protocol_version', 'status', 'client_id', 'installation_id', 'account',
                'credential', 'service_intent', 'authorization'}
        if not isinstance(value, dict) or set(value) != keys:
            return False
        account, credential = value['account'], value['credential']
        if (type(value['protocol_version']) is not int or value['protocol_version'] != 1 or
                value['status'] != 'complete' or value['client_id'] != CLIENT_ID or
                value['installation_id'] != installation_id or value['service_intent'] != 'ipmi' or
                value['authorization'] != 'existing_service_validation_required' or
                not isinstance(account, dict) or set(account) != {'id', 'email', 'display_name'} or
                type(account['id']) is not int or account['id'] <= 0 or not email(account['email']) or
                not isinstance(account['display_name'], str) or len(account['display_name']) > 250 or
                not isinstance(credential, dict) or set(credential) != {'type', 'api_key', 'scope'}):
            return False
        return (credential['type'] == 'legacy_ipmi_api_key' and credential['scope'] == 'account_wide' and
                isinstance(credential['api_key'], str) and credential['api_key'].startswith('sk-ipmi-') and
                len(credential['api_key']) <= 128)

    def service_validation(key, account):
        """Keep the legacy validator unchanged; bridge only its missing user_id."""
        try:
            config = runtime.CloudSync.get_config()
            endpoint = runtime.urlsplit(config.AI_SERVICE_URL)
            if endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.password:
                return None, 'unavailable'
            response = runtime.requests.post(config.AI_SERVICE_URL.rstrip('/') + '/api/v1/validate',
                json={'license_key': key}, timeout=10, verify=True, allow_redirects=False)
            if response.status_code != 200:
                return None, 'unavailable'
            value = response.json()
            if not isinstance(value, dict) or value.get('valid') is not True:
                return None, 'not_entitled'
            tier = runtime.normalize_tier_name(value.get('tier'))
            if (not value.get('tier') or tier not in runtime.SUBSCRIPTION_TIERS or
                    type(value.get('max_servers')) is not int or value['max_servers'] < -1 or
                    not email(value.get('email')) or value['email'].casefold() != account['email'].casefold() or
                    not isinstance(value.get('customer_id'), str) or not value['customer_id'] or
                    not isinstance(value.get('features'), list) or
                    not all(isinstance(item, str) for item in value['features'])):
                return None, 'unavailable'
            if 'user_id' not in value:
                wp = remote('/ipmi/validate', {}, key)
                identity = wp.json() if wp.status_code == 200 else None
                if (not isinstance(identity, dict) or identity.get('valid') is not True or
                        type(identity.get('user_id')) is not int or identity['user_id'] != account['id'] or
                        not email(identity.get('email')) or identity['email'].casefold() != account['email'].casefold()):
                    return None, 'unavailable'
            elif type(value['user_id']) is not int or value['user_id'] != account['id']:
                return None, 'unavailable'
            return {'valid': True, 'tier': tier, 'max_servers': value['max_servers'],
                    'features': value['features'], 'customer_id': value['customer_id'],
                    'user_id': account['id'], 'email': account['email']}, 'available'
        except Exception:
            return None, 'unavailable'

    def staged_reply(stage):
        return reply({'status': 'awaiting_confirmation', 'account': stage['account'],
            'service_status': stage['service_status'], 'requires_confirmation': True,
            'can_commit': stage['can_commit'], **({} if stage['can_commit'] else
                {'reason': 'service_validation_failed'})})

    @app.route('/api/account-link/config', methods=['GET'])
    @guarded
    def account_link_config():
        return reply({'csrf_token': session['pair_csrf']})

    @app.route('/api/account-link/start', methods=['POST'])
    @guarded
    def account_link_start():
        if body(()) is None:
            return failure('invalid_request')
        config = runtime.CloudSync.get_config()
        digest = fingerprint()
        attempt_id = secrets.token_urlsafe(32)
        db.session.execute(insert(AccountLinkAttempt).values(id=1, installation_id=str(uuid.uuid4()))
                           .on_conflict_do_nothing(index_elements=['id']))
        AccountLinkAttempt.query.filter_by(id=1).update({'attempt_id': attempt_id,
            'owner': session['username'], 'session_digest': binding(), 'config_digest': digest,
            'state': 'starting', 'protected': None, 'expires_at': time.time() + 300,
            'interval': 5, 'next_poll': 0}, synchronize_session=False)
        db.session.commit()
        row = db.session.get(AccountLinkAttempt, 1)
        installation_id = row.installation_id
        label = (config.site_name or 'IPMI Monitor')[:80]
        try:
            response = remote('/pairing/start', {'client_id': CLIENT_ID,
                'installation_id': installation_id, 'installation_name': label})
            value = response.json()
            if (response.status_code != 201 or not isinstance(value, dict) or
                    set(value) != {'protocol_version', 'device_code', 'user_code', 'verification_uri', 'expires_in', 'interval'} or
                    type(value['protocol_version']) is not int or value['protocol_version'] != 1 or
                    not isinstance(value['device_code'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value['device_code']) or
                    not isinstance(value['user_code'], str) or not re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{2}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}', value['user_code']) or
                    value['verification_uri'] != VERIFY_URI or type(value['expires_in']) is not int or
                    not 0 < value['expires_in'] <= 300 or type(value['interval']) is not int or not 5 <= value['interval'] <= 300):
                raise ValueError('unsupported start response')
        except Exception:
            current_row = current(attempt_id, ('starting',))
            if current_row:
                cas(current_row, 'starting', state='failed', protected=None)
                db.session.commit()
            return failure('temporarily_unavailable', 503)
        row = current(attempt_id, ('starting',))
        if not row or fingerprint() != digest:
            return failure('attempt_changed', 409)
        expiry = min(row.expires_at, time.time() + value['expires_in'])
        won = cas(row, 'starting', state='pending', expires_at=expiry,
                  interval=value['interval'], protected=encode(value))
        db.session.commit()
        if won != 1:
            return failure('attempt_changed', 409)
        return reply({'status': 'pending', 'attempt_id': attempt_id, 'user_code': value['user_code'],
            'verification_uri': VERIFY_URI, 'expires_in': max(1, int(expiry - time.time())), 'interval': value['interval']})

    @app.route('/api/account-link/status', methods=['POST'])
    @guarded
    def account_link_status():
        value = body(('attempt_id',))
        if value is None:
            return failure('invalid_request')
        row = current(value['attempt_id'], ('pending', 'polling', 'staged'))
        if not row:
            return failure('invalid_attempt', 409)
        if fingerprint() != row.config_digest:
            cas(row, row.state, state='cancelled', protected=None)
            db.session.commit()
            return failure('configuration_changed', 409)
        if row.state == 'staged':
            return staged_reply(decode(row.protected))
        if row.state == 'polling' or row.next_poll > time.time():
            return reply({'status': 'pending', 'interval': row.interval})
        secret = decode(row.protected)
        attempt_id, config_digest = row.attempt_id, row.config_digest
        if cas(row, 'pending', state='polling') != 1:
            db.session.rollback()
            return failure('attempt_busy', 409)
        db.session.commit()
        try:
            response = remote('/pairing/status', {'client_id': CLIENT_ID, 'user_code': secret['user_code']}, secret['device_code'])
            result = response.json()
        except Exception:
            response, result = None, {'error': 'temporarily_unavailable'}
        # Recheck after the network: cancellation/supersession/session/config always wins.
        row = current(attempt_id, ('polling',))
        if not row or not live_admin() or fingerprint() != config_digest:
            return failure('attempt_changed', 409)
        if response is None or response.status_code != 200:
            error = result.get('error') if isinstance(result, dict) else 'temporarily_unavailable'
            terminal = error in ('access_denied', 'expired_token', 'invalid_grant')
            interval = min(300, row.interval + (5 if error == 'slow_down' else 0))
            cas(row, 'polling', state='failed' if terminal else 'pending',
                protected=None if terminal else row.protected, next_poll=time.time() + interval, interval=interval)
            db.session.commit()
            if error in ('authorization_pending', 'slow_down'):
                return reply({'status': 'pending', 'interval': interval})
            return failure(error if terminal else 'temporarily_unavailable', 400 if terminal else 503)
        if not exchange(result, row.installation_id):
            cas(row, 'polling', state='failed', protected=None)
            db.session.commit()
            return failure('invalid_exchange', 502)
        account, key = result['account'], result['credential']['api_key']
        validation, service_status = service_validation(key, account)
        row = current(attempt_id, ('polling',))
        if not row or not live_admin() or fingerprint() != config_digest:
            return failure('attempt_changed', 409)
        existing = runtime.CloudSync.get_config().license_key
        stage = {'account': account, 'api_key': key, 'validation': validation,
                 'service_status': service_status, 'can_commit': bool(validation or not existing or existing == key)}
        if cas(row, 'polling', state='staged', protected=encode(stage)) != 1:
            db.session.rollback()
            return failure('attempt_changed', 409)
        db.session.commit()
        return staged_reply(stage)

    @app.route('/api/account-link/commit', methods=['POST'])
    @guarded
    def account_link_commit():
        value = body(('attempt_id', 'confirm'))
        if value is None or value['confirm'] is not True:
            return failure('invalid_request')
        # sqlite3's legacy transaction mode does not lock on SELECT. Acquire
        # write authority BEFORE fresh reads, then consume + save in that same
        # transaction. No network call is made while holding this lock.
        db.session.rollback()
        db.session.execute(runtime.text('BEGIN IMMEDIATE'))
        if not live_admin():
            db.session.rollback()
            return failure('administrator_required', 403)
        row = current(value['attempt_id'], ('staged',))
        if not row or fingerprint() != row.config_digest:
            db.session.rollback()
            return failure('attempt_changed', 409)
        stage = decode(row.protected)
        if not stage['can_commit']:
            db.session.rollback()
            return failure('service_validation_failed', 409)
        if cas(row, 'staged', state='consumed', protected=None) != 1:
            db.session.rollback()
            return failure('attempt_changed', 409)
        config = runtime.CloudSync.query.first()
        existing = config.license_key
        config.license_key = stage['api_key']
        validation = stage['validation']
        if validation:
            runtime.apply_license_validation(config, validation)
            runtime.record_verified_linked_account(stage['api_key'], validation)
        else:
            # Identity-only first/same-key link: no fabricated customer/service grant.
            if not existing:
                config.subscription_valid = False
                config.features = '[]'
            identity = {'email': stage['account']['email'], 'user_id': stage['account']['id'],
                        'customer_id': '', 'linked_at': runtime.datetime.utcnow().isoformat(),
                        'key_digest': hashlib.sha256(stage['api_key'].encode()).hexdigest()}
            for field, field_value in identity.items():
                setting = runtime.SystemSettings.query.filter_by(key='ai_link_' + field).first()
                if setting:
                    setting.value = str(field_value)
                else:
                    db.session.add(runtime.SystemSettings(key='ai_link_' + field, value=str(field_value)))
            user = runtime.User.query.filter_by(username=session['username']).first()
            if user:
                user.wp_user_id = stage['account']['id']
                user.wp_email = stage['account']['email']
                user.wp_linked_at = runtime.datetime.utcnow()
        db.session.commit()
        return reply({'status': 'linked', 'account': stage['account'], 'service_status': stage['service_status']})

    @app.route('/api/account-link/cancel', methods=['POST'])
    @guarded
    def account_link_cancel():
        value = body(('attempt_id',))
        if value is None:
            return failure('invalid_request')
        row = current(value['attempt_id'], ('starting', 'pending', 'polling', 'staged'))
        if not row or cas(row, row.state, state='cancelled', protected=None) != 1:
            db.session.rollback()
            return failure('invalid_attempt', 409)
        db.session.commit()
        return reply({'status': 'cancelled'})

    def reset_account_link_session():
        """Logout/login identity reset also invalidates persistent pending authority."""
        digest = session.get('pair_binding')
        if digest:
            AccountLinkAttempt.query.filter_by(owner=session.get('username'),
                session_digest=hashlib.sha256(digest.encode()).hexdigest()).filter(
                    AccountLinkAttempt.state.in_(('starting', 'pending', 'polling', 'staged'))).update(
                        {'state': 'cancelled', 'protected': None}, synchronize_session=False)
            db.session.commit()
        for name in ('pair_binding', 'pair_subject', 'pair_csrf'):
            session.pop(name, None)

    runtime.reset_account_link_session = reset_account_link_session
