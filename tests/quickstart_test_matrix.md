# Quickstart Test Matrix

## Decision Points

| # | Decision | Options |
|---|----------|---------|
| 1 | Server Count | `single` / `bulk` |
| 2 | Bulk Method | `import` / `manual` (only if bulk) |
| 3 | SSH Access | `Yes` / `No` |
| 4 | SSH Auth Type | `Password` / `SSH Key` (only if SSH=Yes) |
| 5 | SSH Key Valid | `valid` / `not_found` / `invalid` (only if SSH Key) |
| 6 | Server IP Pattern | `offset` / `same` / `manual` (only if bulk manual + SSH) |
| 7 | Admin Password | `default` / `custom` |
| 8 | Password Match | `match` / `mismatch` (only if custom) |
| 9 | AI Features | `Yes` / `No` |
| 10 | HTTPS Proxy | `Yes` / `No` |
| 11 | Has Domain | `Yes` / `No` (only if HTTPS=Yes) |
| 12 | Let's Encrypt | `Yes` / `No` (only if domain=Yes) |

---

## Test Scenarios

### Scenario 1: Single Server, No SSH, Default Password, No HTTPS
**Path:** single → No SSH → default password → No AI → No HTTPS

**User Inputs:**
- Server count: "Just one server"
- Server name: "test-server"
- BMC IP: "192.168.1.83"
- BMC user: "ADMIN"
- BMC pass: "password123"
- Add SSH: No
- Custom password: No
- Enable AI: No
- HTTPS proxy: No

**Expected Data Flow:**
1. `add_server_interactive()` returns:
   ```python
   {
       "name": "test-server",
       "bmc_ip": "192.168.1.83",
       "bmc_user": "ADMIN",
       "bmc_password": "password123"
   }
   ```

2. `flask_servers` conversion (line 229-251):
   ```python
   {
       "name": "test-server",
       "bmc_ip": "192.168.1.83",
       "ipmi_user": "ADMIN",
       "ipmi_pass": "password123"
   }
   ```

3. `servers.yaml` output (line 260-279):
   ```yaml
   servers:
     - name: test-server
       bmc_ip: 192.168.1.83
       ipmi_user: ADMIN
       ipmi_pass: password123
   ```

4. `set_admin_password("admin", db_path)` called (line 285):
   - Creates user table with correct schema
   - Inserts admin user with hashed "admin" password
   - `password_changed = 0`

5. No SSH key processing (line 214-225 skipped)

**Status:** ✅ VERIFIED - Data flows correctly

---

### Scenario 2: Single Server, SSH with Password, Custom Password, HTTPS no domain
**Path:** single → SSH Yes → Password → custom password (match) → No AI → HTTPS Yes → No domain

**User Inputs:**
- Server count: "Just one server"
- Server name: "gpu-01"
- BMC IP: "192.168.1.83"
- BMC user: "admin"
- BMC pass: "bmcpass"
- Add SSH: Yes
- Server IP for SSH: "192.168.1.100"
- SSH username: "root"
- SSH auth: Password
- SSH password: "sshpass123"
- Custom password: Yes → "MyPassword" / "MyPassword"
- Enable AI: No
- HTTPS proxy: Yes
- Has domain: No

**Expected Data Flow:**
1. `add_server_interactive()` returns:
   ```python
   {
       "name": "gpu-01",
       "bmc_ip": "192.168.1.83",
       "bmc_user": "admin",
       "bmc_password": "bmcpass",
       "server_ip": "192.168.1.100",
       "ssh_user": "root",
       "ssh_password": "sshpass123",
       "ssh_port": 22
   }
   ```

2. `flask_servers` conversion:
   ```python
   {
       "name": "gpu-01",
       "bmc_ip": "192.168.1.83",
       "ipmi_user": "admin",
       "ipmi_pass": "bmcpass",
       "server_ip": "192.168.1.100",
       "ssh_user": "root",
       "ssh_pass": "sshpass123",  # NOTE: ssh_password → ssh_pass
       "ssh_port": 22
   }
   ```

3. `servers.yaml` output:
   ```yaml
   servers:
     - name: gpu-01
       bmc_ip: 192.168.1.83
       ipmi_user: admin
       ipmi_pass: bmcpass
       server_ip: 192.168.1.100
       ssh_user: root
       ssh_pass: sshpass123
       ssh_port: 22
   ```

4. `set_admin_password("MyPassword", db_path)`:
   - `password_changed = 1` (is_custom = True)
   - Password properly hashed with werkzeug

5. No SSH key in ssh_key table (password auth)

6. `setup_https_access()` called with no domain → self-signed cert

**Status:** ✅ VERIFIED - Data flows correctly

---

### Scenario 3: Single Server, SSH with Key (valid), Custom Password, HTTPS with domain + Let's Encrypt
**Path:** single → SSH Yes → SSH Key (valid) → custom password → No AI → HTTPS Yes → domain Yes → LE Yes

**User Inputs:**
- Server count: "Just one server"
- Server name: "dgx-01"
- BMC IP: "192.168.1.80"
- BMC user: "admin"
- BMC pass: "bmcpass"
- Add SSH: Yes
- Server IP: "192.168.1.81"
- SSH username: "root"
- SSH auth: SSH Key
- SSH key path: "/root/.ssh/id_rsa" (valid key exists)
- Custom password: Yes → "SecurePass123"
- Enable AI: No
- HTTPS proxy: Yes
- Domain: Yes → "ipmi.example.com"
- Let's Encrypt: Yes
- Email: "admin@example.com"

**Expected Data Flow:**
1. `add_server_interactive()` returns:
   ```python
   {
       "name": "dgx-01",
       "bmc_ip": "192.168.1.80",
       "bmc_user": "admin",
       "bmc_password": "bmcpass",
       "server_ip": "192.168.1.81",
       "ssh_user": "root",
       "ssh_key": "/root/.ssh/id_rsa",  # PATH, not content
       "ssh_port": 22
   }
   ```

2. SSH key processing (line 214-225):
   - `read_ssh_key_file("/root/.ssh/id_rsa")` returns key content
   - `create_ssh_key_in_database("default-key", content, db_path)` creates entry
   - `ssh_key_map = {"/root/.ssh/id_rsa": "default-key"}`

3. `flask_servers` conversion:
   ```python
   {
       "name": "dgx-01",
       "bmc_ip": "192.168.1.80",
       "ipmi_user": "admin",
       "ipmi_pass": "bmcpass",
       "server_ip": "192.168.1.81",
       "ssh_user": "root",
       "ssh_key_name": "default-key",  # NOT ssh_key path!
       "ssh_port": 22
   }
   ```

4. `servers.yaml` output:
   ```yaml
   servers:
     - name: dgx-01
       bmc_ip: 192.168.1.80
       ipmi_user: admin
       ipmi_pass: bmcpass
       server_ip: 192.168.1.81
       ssh_user: root
       ssh_key_name: default-key
       ssh_port: 22
   ```

5. `ssh_key` table entry:
   ```sql
   INSERT INTO ssh_key (name, key_content, fingerprint, created_at, updated_at)
   VALUES ('default-key', '-----BEGIN...', 'sha256hash', '2026-01-21...', '2026-01-21...')
   ```

6. `setup_https_access()` with domain + LE

**Status:** ✅ VERIFIED - Data flows correctly

---

### Scenario 4: Single Server, SSH Key (NOT FOUND)
**Path:** single → SSH Yes → SSH Key (file not found)

**User Inputs:**
- Server name: "server-01"
- BMC IP: "192.168.1.83"
- SSH: Yes
- SSH key path: "/root/.ssh/nonexistent_key"

**Expected Data Flow:**
1. `add_server_interactive()` returns server with `ssh_key: "/root/.ssh/nonexistent_key"`

2. SSH key processing (line 214-225):
   - `read_ssh_key_file()` returns `None` (file not found)
   - Console shows: `[yellow]⚠[/yellow] SSH key file not found: /root/.ssh/nonexistent_key`
   - Key NOT added to `ssh_key_map`

3. `flask_servers` conversion:
   - `srv.get("ssh_key")` is truthy BUT `srv["ssh_key"] not in ssh_key_map`
   - So `ssh_key_name` is NOT set

4. `servers.yaml` output:
   ```yaml
   servers:
     - name: server-01
       bmc_ip: 192.168.1.83
       ...
       ssh_user: root
       # NO ssh_key_name - key wasn't stored!
       ssh_port: 22
   ```

**Status:** ⚠️ WARNING - Server saved but SSH key auth won't work. User warned.

---

### Scenario 5: Bulk Manual, SSH with Password, IP Offset
**Path:** bulk → manual → SSH Yes → Password → offset pattern

**User Inputs:**
- Server count: "Multiple servers"
- Method: "Enter manually"
- BMC IPs: 192.168.1.83, 192.168.1.85, 192.168.1.88
- BMC user: "admin", BMC pass: "bmcpass"
- Add SSH: Yes
- IP pattern: "offset" with offset=1
- SSH username: "root"
- SSH auth: Password
- SSH password: "sshpass"

**Expected Data Flow:**
1. `add_servers_manual()` - server_ips mapping:
   ```python
   server_ips = {
       "192.168.1.83": "192.168.1.84",  # .83 + 1 = .84
       "192.168.1.85": "192.168.1.86",
       "192.168.1.88": "192.168.1.89"
   }
   ```

2. Server list built (line 654-677):
   ```python
   [
       {
           "name": "server-01",
           "bmc_ip": "192.168.1.83",
           "bmc_user": "admin",
           "bmc_password": "bmcpass",
           "server_ip": "192.168.1.84",  # From server_ips mapping
           "ssh_user": "root",
           "ssh_password": "sshpass",
           "ssh_port": 22
       },
       # ... similar for .85 and .88
   ]
   ```

3. `servers.yaml`:
   ```yaml
   servers:
     - name: server-01
       bmc_ip: 192.168.1.83
       ipmi_user: admin
       ipmi_pass: bmcpass
       server_ip: 192.168.1.84
       ssh_user: root
       ssh_pass: sshpass
       ssh_port: 22
     - name: server-02
       bmc_ip: 192.168.1.85
       ...
       server_ip: 192.168.1.86
     - name: server-03
       bmc_ip: 192.168.1.88
       ...
       server_ip: 192.168.1.89
   ```

**Status:** ✅ VERIFIED - IP offset calculated correctly

---

### Scenario 6: Bulk Manual, SSH with Key, IP Same
**Path:** bulk → manual → SSH Yes → SSH Key → same pattern

**User Inputs:**
- BMC IPs: 192.168.1.80, 192.168.1.81
- Add SSH: Yes
- IP pattern: "same"
- SSH auth: SSH Key
- SSH key path: "/root/.ssh/id_rsa" (valid)

**Expected Data Flow:**
1. `server_ips`:
   ```python
   server_ips = {
       "192.168.1.80": "192.168.1.80",
       "192.168.1.81": "192.168.1.81"
   }
   ```

2. SSH key stored once (deduplication):
   - Both servers reference same key path
   - `ssh_key_map = {"/root/.ssh/id_rsa": "default-key"}`
   - Only ONE entry in `ssh_key` table

3. `servers.yaml`:
   ```yaml
   servers:
     - name: server-01
       bmc_ip: 192.168.1.80
       server_ip: 192.168.1.80
       ssh_key_name: default-key
     - name: server-02
       bmc_ip: 192.168.1.81
       server_ip: 192.168.1.81
       ssh_key_name: default-key
   ```

**Status:** ✅ VERIFIED - Key deduplicated, IP same as BMC

---

### Scenario 7: Bulk Manual, No SSH
**Path:** bulk → manual → SSH No

**User Inputs:**
- BMC IPs: 192.168.1.83, 192.168.1.85
- BMC user/pass: admin/pass
- Add SSH: No

**Expected Data Flow:**
1. `add_servers_manual()` skips SSH section entirely
2. Server dict has NO `server_ip`, `ssh_user`, `ssh_password`, `ssh_key`, `ssh_port`

3. `servers.yaml`:
   ```yaml
   servers:
     - name: server-01
       bmc_ip: 192.168.1.83
       ipmi_user: admin
       ipmi_pass: pass
     - name: server-02
       bmc_ip: 192.168.1.85
       ipmi_user: admin
       ipmi_pass: pass
   ```

**Status:** ✅ VERIFIED - No SSH fields written

---

### Scenario 8: Bulk Import (Text), SSH only servers (no BMC)
**Path:** bulk → import → SSH only format

**User Inputs (pasted text):**
```
global:root,sshpassword
192.168.1.101
192.168.1.102
```

**Expected Data Flow:**
1. `parse_ipmi_server_list()`:
   - Sets `global_ssh_user = "root"`, `global_ssh_pass = "sshpassword"`
   - For each IP (1 part): sets `server_ip`, applies global SSH creds
   - NO `bmc_ip` set!

2. Servers returned:
   ```python
   [
       {
           "name": "server-01",
           "server_ip": "192.168.1.101",
           "ssh_user": "root",
           "ssh_password": "sshpassword",
           "ssh_port": 22
           # NO bmc_ip!
       },
       ...
   ]
   ```

3. `valid_servers` filtering (line 255):
   - `[srv for srv in flask_servers if srv.get('bmc_ip')]`
   - All servers SKIPPED because no `bmc_ip`!

4. Console output:
   ```
   ⚠ Skipped 2 server(s) without BMC IP (IPMI monitoring requires BMC)
   ```

5. `servers.yaml`:
   ```yaml
   servers:
   ```
   (empty!)

**Status:** ⚠️ WARNING - SSH-only servers skipped. IPMI Monitor requires BMC IP.

---

### Scenario 9: Bulk Import, Full format with BMC
**Path:** bulk → import → full SSH+IPMI format

**User Inputs (pasted text):**
```
globalSSH:root,sshpass
globalIPMI:ADMIN,ipmipass
192.168.1.101,192.168.1.80
192.168.1.102,192.168.1.82
```

**Expected Data Flow:**
1. `parse_ipmi_server_list()`:
   - `global_ssh_user = "root"`, `global_ssh_pass = "sshpass"`
   - `global_ipmi_user = "ADMIN"`, `global_ipmi_pass = "ipmipass"`
   - For 2-part lines: `server_ip` = part[0], `bmc_ip` = part[1]

2. Servers returned:
   ```python
   [
       {
           "name": "server-01",
           "server_ip": "192.168.1.101",
           "bmc_ip": "192.168.1.80",
           "ssh_user": "root",
           "ssh_password": "sshpass",
           "bmc_user": "ADMIN",
           "bmc_password": "ipmipass",
           "ssh_port": 22
       },
       ...
   ]
   ```

3. `servers.yaml`:
   ```yaml
   servers:
     - name: server-01
       bmc_ip: 192.168.1.80
       ipmi_user: ADMIN
       ipmi_pass: ipmipass
       server_ip: 192.168.1.101
       ssh_user: root
       ssh_pass: sshpass
       ssh_port: 22
   ```

**Status:** ✅ VERIFIED - Both SSH and IPMI credentials applied

---

### Scenario 10: Custom Password Mismatch
**Path:** any → custom password → mismatch

**User Inputs:**
- Custom password: Yes
- Password: "Password1"
- Confirm: "Password2" (different!)

**Expected Data Flow:**
1. Line 150: `admin_password != confirm_password`
2. Console: `[yellow]⚠[/yellow] Passwords don't match. Using default: admin`
3. `admin_password = "admin"`
4. `set_admin_password("admin", db_path)` called
5. `password_changed = 0` (default password)

**Status:** ✅ VERIFIED - Falls back to default

---

### Scenario 11: HTTPS No
**Path:** any → HTTPS No

**User Inputs:**
- HTTPS proxy: No

**Expected Data Flow:**
1. Line 294-302: `setup_ssl = False`
2. Line 305-306: `if setup_ssl:` is False, `setup_https_access()` NOT called
3. `domain = None`
4. Summary shows: `http://{local_ip}:{port}` not https

**Status:** ✅ VERIFIED - No reverse proxy setup

---

### Scenario 12: HTTPS Yes, No Domain (self-signed)
**Path:** any → HTTPS Yes → domain No

**User Inputs:**
- HTTPS proxy: Yes
- Has domain: No

**Expected Data Flow:**
1. `setup_https_access()` called
2. Line 967-971: `use_domain = False`
3. `domain = None`, `use_letsencrypt = False`
4. `setup_reverse_proxy(domain=None, email=None, use_letsencrypt=False)`
5. Generates self-signed certificate

**Status:** ✅ VERIFIED - Self-signed cert generated

---

### Scenario 13: HTTPS Yes, Domain Yes, Let's Encrypt No
**Path:** any → HTTPS Yes → domain Yes → LE No

**User Inputs:**
- HTTPS proxy: Yes
- Domain: Yes → "ipmi.local"
- Let's Encrypt: No

**Expected Data Flow:**
1. `domain = "ipmi.local"`
2. `use_letsencrypt = False`
3. `setup_reverse_proxy(domain="ipmi.local", email=None, use_letsencrypt=False)`
4. Self-signed cert for domain

**Status:** ✅ VERIFIED - Domain with self-signed

---

### Scenario 14: AI Features Enabled
**Path:** any → AI Yes

**User Inputs:**
- Enable AI: Yes
- License key: "ABC123-XYZ789"

**Expected Data Flow:**
1. `license_key = "ABC123-XYZ789"`
2. `config.yaml` includes:
   ```yaml
   ai:
     enabled: true
     license_key: ABC123-XYZ789
   ```

**Status:** ✅ VERIFIED - AI config saved

---

---

### Scenario 15: User Cancels During SSH Setup (Bulk Manual)
**Path:** bulk → manual → SSH Yes → cancels during auth method

**Expected Behavior:**
- Line 640: `auth_method` returns `None`
- Line 644: `if auth_method is None:` sets `add_ssh = False`
- Servers built without SSH credentials

**Status:** ✅ VERIFIED - Gracefully skips SSH

---

### Scenario 16: User Cancels During SSH Setup (Single Server)
**Path:** single → SSH Yes → cancels during password/key entry

**Expected Behavior:**
- Returns server WITHOUT SSH credentials
- Server still has BMC credentials
- Warning not shown (user intentionally cancelled)

**Status:** ✅ VERIFIED - Gracefully returns partial server

---

## Summary of Potential Issues Found

| Issue | Scenario | Severity | Status |
|-------|----------|----------|--------|
| SSH-only servers (no BMC) are skipped | 8 | Warning | By Design - IPMI requires BMC |
| SSH key not found | 4 | Warning | User warned, server saved without key |
| Password mismatch | 10 | Low | Falls back to default with warning |
| User cancels SSH setup | 15, 16 | None | Handled gracefully |

## Database Schema Verification

### `user` table (from `set_admin_password`)
```sql
CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'readonly',
    enabled BOOLEAN DEFAULT 1,
    password_changed BOOLEAN DEFAULT 0,
    created_at DATETIME,
    updated_at DATETIME,
    last_login DATETIME,
    wp_user_id INTEGER,
    wp_email VARCHAR(100),
    wp_linked_at DATETIME
)
```
**Matches Flask's User model:** ✅

### `ssh_key` table (from `create_ssh_key_in_database`)
```sql
CREATE TABLE ssh_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(50) NOT NULL UNIQUE,
    key_content TEXT NOT NULL,
    fingerprint VARCHAR(100),
    created_at DATETIME,
    updated_at DATETIME
)
```
**Matches Flask's SSHKey model:** ✅

## servers.yaml Field Mapping

| Quickstart Field | Flask Field | Written to YAML |
|------------------|-------------|-----------------|
| `name` | `server_name` | `name` |
| `bmc_ip` | `bmc_ip` | `bmc_ip` |
| `bmc_user` | `ipmi_user` | `ipmi_user` |
| `bmc_password` | `ipmi_pass` | `ipmi_pass` |
| `server_ip` | `server_ip` | `server_ip` |
| `ssh_user` | `ssh_user` | `ssh_user` |
| `ssh_password` | `ssh_pass` | `ssh_pass` |
| `ssh_key` (path) | `ssh_key_name` | `ssh_key_name` |
| `ssh_port` | `ssh_port` | `ssh_port` |

**All mappings verified:** ✅
