# IPMI Monitor - Subscription Service Architecture Plan

## Executive Summary

Transform the IPMI Monitor from a free self-hosted tool into a tiered SaaS product:

| Tier | Price | Servers | Tokens/mo | What's Included |
|------|-------|---------|-----------|-----------------|
| **Free** | $0 | Unlimited | - | Monitoring, dashboard, CSV export, Prometheus/Grafana |
| **Standard** | $100/mo | 50 | 1M | + AI summaries, predictions, RCA, chat, alerting |
| **Standard+** | +$15/10 servers | 51+ | +100K | Additional servers at $15/10 servers |
| **Professional** | $500/mo | 500 | 10M | All features + priority support |

**Key Principle**: All AI logic, prompts, and playbooks remain on CryptoLabs servers. Customers cannot bypass by adding their own LLM tokens.

**Release Strategy**: Ship FREE tier NOW, build AI features for Standard tier iteratively.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CUSTOMER INFRASTRUCTURE                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     IPMI Monitor (Free/Self-Hosted)                  │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐    │   │
│  │  │ Dashboard │  │ Sensors  │  │   SEL    │  │  Basic Alerts    │    │   │
│  │  │   View    │  │ Collect  │  │ Monitor  │  │  (Email/SMTP)    │    │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘    │   │
│  │                              │                                       │   │
│  │                    ┌─────────▼─────────┐                            │   │
│  │                    │  Data Sync Agent  │ ◄── License Key Required   │   │
│  │                    │  (Paid Tier Only) │     for AI features        │   │
│  │                    └─────────┬─────────┘                            │   │
│  └──────────────────────────────┼──────────────────────────────────────┘   │
└─────────────────────────────────┼───────────────────────────────────────────┘
                                  │ HTTPS (Encrypted)
                                  │ - SEL Events
                                  │ - Sensor Data
                                  │ - Server Configs
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CRYPTOLABS CLOUD INFRASTRUCTURE                         │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        API Gateway (Nginx)                            │  │
│  │   • License Key Validation    • Rate Limiting    • TLS Termination   │  │
│  └─────────────────────────────────┬────────────────────────────────────┘  │
│                                    │                                        │
│  ┌─────────────────────────────────▼────────────────────────────────────┐  │
│  │                    IPMI Intelligence Service                          │  │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐  │  │
│  │  │  License/Sub   │  │  Data Ingestion│  │   Customer Data Store  │  │  │
│  │  │  Validator     │  │   & Storage    │  │   (PostgreSQL/Redis)   │  │  │
│  │  └────────────────┘  └────────────────┘  └────────────────────────┘  │  │
│  │                                                                       │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │                    AI Processing Pipeline                        │ │  │
│  │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐  │ │  │
│  │  │  │  Summaries  │ │ Maintenance │ │ Predictions │ │    RCA    │  │ │  │
│  │  │  │  Generator  │ │ Task Engine │ │   Engine    │ │  Analyzer │  │ │  │
│  │  │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └─────┬─────┘  │ │  │
│  │  │         └───────────────┴───────────────┴──────────────┘        │ │  │
│  │  │                              │                                   │ │  │
│  │  │                    ┌─────────▼─────────┐                        │ │  │
│  │  │                    │     LiteLLM       │ ◄── HIDDEN from users  │ │  │
│  │  │                    │  (VLLM/Anthropic) │     No direct access   │ │  │
│  │  │                    └───────────────────┘                        │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │                      WordPress + WooCommerce                           ││
│  │   • User Registration    • Subscription Management    • License Keys  ││
│  │   • Payment Processing   • Customer Portal            • Usage Billing ││
│  └────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Tier Breakdown

### ✅ FREE TIER (Self-Hosted Monitoring) - RELEASE NOW

**What's Included:**
- Full IPMI Monitor installation (Docker)
- Up to 50 servers
- Real-time sensor monitoring (temp, fans, voltage, power)
- SEL event collection & display
- Severity classification (Critical/Warning/Info)
- Dashboard + server detail views
- 7-day data retention (local DB)
- CSV export
- Prometheus metrics endpoint
- Grafana dashboard integration

**What's NOT Included (Standard/Professional only):**
- ❌ Email/Telegram/Slack alerts (costs us money)
- ❌ AI summaries & reports
- ❌ Predictive analytics
- ❌ Root Cause Analysis
- ❌ Long-term data retention

**Technical Implementation:**
- Current codebase with alerting disabled
- No CryptoLabs server connectivity required
- Fully offline capable
- Self-hosted, user installs on their infrastructure

---

### 💎 STANDARD TIER ($100/month) - PHASE 2

**Pricing:**
- $29/month for up to 50 servers
- $1/server/month for additional servers (51+)
- Example: 75 servers = $29 + (25 × $1) = $54/month

**What's Included:**
- Everything in Free +
- ✅ **Alerting**: Email, Telegram, Slack, Discord, Webhooks
- ✅ **AI Daily Summaries**: Fleet health digest
- ✅ **AI Weekly Reports**: Trends, top issues, recommendations
- ✅ **Maintenance Tasks**: AI-generated task suggestions
- ✅ **Predictive Analytics**: Failure predictions, trend analysis
- ✅ **Root Cause Analysis**: AI explains incidents
- ✅ **Alert Deduplication**: No alert storms
- ✅ **90-day data retention** (on CryptoLabs cloud)
- ✅ **PDF Report Export**
- ✅ Email support

**Technical Implementation:**
- License key activates paid features
- Data syncs to CryptoLabs for AI processing
- AI results fetched and displayed in dashboard

---

## Security Architecture (Preventing LLM Bypass)

### Why Users Can't Just Add Their Own LLM Token

```
┌─────────────────────────────────────────────────────────────────┐
│                    CUSTOMER'S IPMI MONITOR                       │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  NO LLM CODE HERE                                        │   │
│  │  • Only data collection                                  │   │
│  │  • Only display of pre-computed results                  │   │
│  │  • No prompts, no AI logic, no model calls              │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                    ┌─────────▼─────────┐                       │
│                    │  Sync Agent sends │                       │
│                    │  RAW DATA ONLY:   │                       │
│                    │  • SEL events     │                       │
│                    │  • Sensor values  │                       │
│                    │  • Server info    │                       │
│                    └─────────┬─────────┘                       │
└──────────────────────────────┼──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CRYPTOLABS SERVERS                            │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  ALL AI LOGIC HERE                                       │   │
│  │  • Prompt templates (secret)                             │   │
│  │  • Analysis playbooks (secret)                           │   │
│  │  • ML models                                             │   │
│  │  • LiteLLM/VLLM integration                              │   │
│  │  • Business logic                                        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                    ┌─────────▼─────────┐                       │
│                    │  Returns RESULTS: │                       │
│                    │  • Pre-generated  │                       │
│                    │    summaries      │                       │
│                    │  • Task lists     │                       │
│                    │  • Predictions    │                       │
│                    └───────────────────┘                       │
└─────────────────────────────────────────────────────────────────┘
```

### Key Security Measures

1. **No LLM Code in Client Installation**
   - IPMI Monitor contains ZERO AI/LLM code
   - No prompt templates shipped
   - No API endpoints for direct LLM access
   - Client only displays pre-computed results from CryptoLabs

2. **Server-Side Processing Only**
   - All prompts stored on CryptoLabs servers
   - All analysis logic server-side
   - LiteLLM/VLLM never exposed to customers
   - Results are "baked" summaries, not raw LLM responses

3. **License Key Validation**
   ```python
   # On every API request:
   def validate_request(license_key, customer_id):
       # Check key exists and is active
       # Check subscription tier
       # Check server count within limits
       # Check rate limits
       # Log usage for billing
   ```

4. **Data Isolation**
   - Each customer's data stored separately
   - Customer can only access their own AI results
   - No cross-tenant data leakage

5. **Audit Trail**
   - All API requests logged
   - Usage metered for billing
   - Anomaly detection for abuse

---

## Technical Implementation Plan

### Phase 1: Infrastructure Setup (Week 1-2)

#### 1.1 Create IPMI Intelligence Service

```
/cryptolabs-ipmi-service/
├── api/
│   ├── __init__.py
│   ├── routes/
│   │   ├── auth.py          # License key validation
│   │   ├── ingest.py        # Data ingestion from customers
│   │   ├── results.py       # Fetch AI results
│   │   └── webhooks.py      # Alert webhooks
│   └── middleware/
│       ├── license.py       # License validation middleware
│       └── rate_limit.py    # Per-customer rate limiting
├── services/
│   ├── ai_pipeline/
│   │   ├── summary_generator.py
│   │   ├── task_engine.py
│   │   ├── prediction_engine.py
│   │   └── rca_analyzer.py
│   ├── llm/
│   │   ├── litellm_client.py   # Internal LiteLLM calls
│   │   └── prompts/            # SECRET prompt templates
│   │       ├── daily_summary.txt
│   │       ├── maintenance_task.txt
│   │       ├── prediction.txt
│   │       └── rca.txt
│   └── data/
│       ├── ingestion.py
│       └── storage.py
├── models/
│   ├── customer.py
│   ├── subscription.py
│   ├── server_data.py
│   └── ai_result.py
├── workers/
│   ├── daily_summary_worker.py
│   ├── prediction_worker.py
│   └── alert_worker.py
├── docker-compose.yml
└── Dockerfile
```

#### 1.2 Database Schema

```sql
-- Customers table (synced with WooCommerce)
CREATE TABLE customers (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    company_name VARCHAR(255),
    license_key VARCHAR(64) UNIQUE,
    subscription_tier VARCHAR(50),  -- 'standard', 'professional'
    max_servers INT,
    subscription_status VARCHAR(50),
    created_at TIMESTAMP,
    expires_at TIMESTAMP
);

-- Customer's synced servers
CREATE TABLE customer_servers (
    id UUID PRIMARY KEY,
    customer_id UUID REFERENCES customers(id),
    server_name VARCHAR(255),
    bmc_ip VARCHAR(45),
    last_sync TIMESTAMP,
    UNIQUE(customer_id, bmc_ip)
);

-- Synced SEL events
CREATE TABLE synced_events (
    id UUID PRIMARY KEY,
    customer_id UUID REFERENCES customers(id),
    server_id UUID REFERENCES customer_servers(id),
    event_id VARCHAR(50),
    timestamp TIMESTAMP,
    severity VARCHAR(20),
    event_type VARCHAR(100),
    description TEXT,
    raw_data JSONB,
    synced_at TIMESTAMP
);

-- Synced sensor readings
CREATE TABLE synced_sensors (
    id UUID PRIMARY KEY,
    customer_id UUID REFERENCES customers(id),
    server_id UUID REFERENCES customer_servers(id),
    sensor_name VARCHAR(100),
    sensor_type VARCHAR(50),
    value DECIMAL,
    unit VARCHAR(20),
    status VARCHAR(50),
    recorded_at TIMESTAMP,
    synced_at TIMESTAMP
);

-- AI-generated results (what customers fetch)
CREATE TABLE ai_results (
    id UUID PRIMARY KEY,
    customer_id UUID REFERENCES customers(id),
    result_type VARCHAR(50),  -- 'daily_summary', 'task', 'prediction', 'rca'
    server_id UUID REFERENCES customer_servers(id),  -- NULL for fleet-wide
    title VARCHAR(255),
    content TEXT,  -- Pre-generated HTML/Markdown
    metadata JSONB,
    generated_at TIMESTAMP,
    expires_at TIMESTAMP
);

-- Maintenance tasks
CREATE TABLE maintenance_tasks (
    id UUID PRIMARY KEY,
    customer_id UUID REFERENCES customers(id),
    server_id UUID REFERENCES customer_servers(id),
    title VARCHAR(255),
    description TEXT,
    priority VARCHAR(20),  -- 'critical', 'high', 'medium', 'low'
    ai_confidence DECIMAL,
    suggested_action TEXT,
    status VARCHAR(50),  -- 'pending', 'acknowledged', 'completed'
    created_at TIMESTAMP,
    due_date TIMESTAMP
);
```

#### 1.3 WooCommerce Integration

```php
// WordPress plugin to sync subscriptions
// /wp-content/plugins/cryptolabs-ipmi-subscriptions/

add_action('woocommerce_subscription_status_active', function($subscription) {
    $user = $subscription->get_user();
    $product = $subscription->get_items()[0]->get_product();
    
    // Generate unique license key
    $license_key = wp_generate_password(32, false);
    
    // Sync to IPMI Intelligence Service
    wp_remote_post('https://api.cryptolabs.co.za/ipmi/v1/subscriptions', [
        'body' => json_encode([
            'customer_email' => $user->user_email,
            'license_key' => $license_key,
            'tier' => get_post_meta($product->get_id(), '_ipmi_tier', true),
            'max_servers' => get_post_meta($product->get_id(), '_max_servers', true),
            'expires_at' => $subscription->get_date('next_payment')
        ]),
        'headers' => ['Content-Type' => 'application/json']
    ]);
    
    // Store license key in user meta
    update_user_meta($user->ID, 'ipmi_license_key', $license_key);
});
```

### Phase 2: Client-Side Integration (Week 2-3)

#### 2.1 Add Sync Agent to IPMI Monitor

```python
# app.py additions

class CloudSyncConfig(db.Model):
    """Configuration for CryptoLabs cloud sync"""
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(64))
    sync_enabled = db.Column(db.Boolean, default=False)
    sync_interval = db.Column(db.Integer, default=300)  # 5 minutes
    last_sync = db.Column(db.DateTime)
    api_endpoint = db.Column(db.String(255), default='https://api.cryptolabs.co.za/ipmi/v1')

def sync_to_cloud():
    """Send data to CryptoLabs cloud for AI processing"""
    config = CloudSyncConfig.query.first()
    if not config or not config.sync_enabled or not config.license_key:
        return
    
    # Collect data to sync
    servers = Server.query.all()
    events = Event.query.filter(Event.timestamp > config.last_sync).all()
    sensors = SensorReading.query.filter(SensorReading.timestamp > config.last_sync).all()
    
    payload = {
        'license_key': config.license_key,
        'servers': [s.to_dict() for s in servers],
        'events': [e.to_dict() for e in events],
        'sensors': [s.to_dict() for s in sensors]
    }
    
    try:
        response = requests.post(
            f"{config.api_endpoint}/sync",
            json=payload,
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=30
        )
        if response.ok:
            config.last_sync = datetime.utcnow()
            db.session.commit()
    except Exception as e:
        app.logger.error(f"Cloud sync failed: {e}")

def fetch_ai_results():
    """Fetch AI-generated results from CryptoLabs"""
    config = CloudSyncConfig.query.first()
    if not config or not config.sync_enabled:
        return None
    
    try:
        response = requests.get(
            f"{config.api_endpoint}/results",
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=30
        )
        return response.json() if response.ok else None
    except Exception:
        return None
```

#### 2.2 Settings UI for Cloud Features

```html
<!-- In settings.html - new "AI Features" tab -->
<div id="ai-features-tab" class="tab-content">
    <h3>🤖 CryptoLabs AI Features</h3>
    
    <div class="setting-group">
        <h4>Subscription Status</h4>
        <div id="subscription-status">
            <span class="status-badge free">FREE TIER</span>
            <p>Upgrade to unlock AI-powered features:</p>
            <ul>
                <li>✨ AI Daily/Weekly Summaries</li>
                <li>🔧 Automated Maintenance Tasks</li>
                <li>📈 Predictive Failure Analytics</li>
                <li>🔍 Root Cause Analysis</li>
                <li>📱 Slack/Teams/Discord Alerts</li>
            </ul>
            <a href="https://cryptolabs.co.za/ipmi-monitor/pricing" 
               target="_blank" class="btn btn-primary">
                Upgrade Now
            </a>
        </div>
    </div>
    
    <div class="setting-group" id="license-section" style="display:none;">
        <h4>License Key</h4>
        <input type="password" id="license-key" placeholder="Enter your license key">
        <button onclick="activateLicense()">Activate</button>
    </div>
    
    <div class="setting-group" id="ai-settings" style="display:none;">
        <h4>AI Feature Settings</h4>
        <label>
            <input type="checkbox" id="enable-sync" checked>
            Enable cloud sync for AI features
        </label>
        <label>
            <input type="checkbox" id="daily-summaries" checked>
            Receive daily AI summaries
        </label>
        <label>
            <input type="checkbox" id="auto-tasks" checked>
            Auto-generate maintenance tasks
        </label>
        <label>
            <input type="checkbox" id="predictions" checked>
            Enable predictive analytics
        </label>
    </div>
</div>
```

### Phase 3: AI Pipeline Implementation (Week 3-4)

#### 3.1 Summary Generator

```python
# services/ai_pipeline/summary_generator.py

class SummaryGenerator:
    def __init__(self, litellm_client):
        self.llm = litellm_client
        # Prompts stored SERVER-SIDE ONLY
        self.daily_prompt = self._load_prompt('daily_summary.txt')
        self.weekly_prompt = self._load_prompt('weekly_summary.txt')
    
    def generate_daily_summary(self, customer_id: str) -> dict:
        """Generate daily fleet health summary"""
        # Fetch last 24h of data
        events = self._get_events(customer_id, hours=24)
        sensors = self._get_sensor_trends(customer_id, hours=24)
        
        # Build context (no LLM prompts exposed to customer)
        context = self._build_context(events, sensors)
        
        # Call LiteLLM (internal, not exposed)
        response = self.llm.completion(
            model="qwen3-coder-30b",  # or fallback to Claude
            messages=[
                {"role": "system", "content": self.daily_prompt},
                {"role": "user", "content": context}
            ],
            max_tokens=2000
        )
        
        # Return pre-baked summary (customer never sees raw LLM)
        return {
            'type': 'daily_summary',
            'title': f"Fleet Health Summary - {date.today()}",
            'content': self._format_summary(response.choices[0].message.content),
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def _load_prompt(self, filename):
        """Load prompt from secure server-side storage"""
        prompt_path = os.path.join(PROMPT_DIR, filename)
        with open(prompt_path, 'r') as f:
            return f.read()
```

#### 3.2 Maintenance Task Engine

```python
# services/ai_pipeline/task_engine.py

class MaintenanceTaskEngine:
    # Rule-based + AI-enhanced task generation
    
    RULES = [
        {
            'name': 'ECC Memory Threshold',
            'condition': lambda e: e['type'] == 'Memory' and 'ECC' in e['description'],
            'count_threshold': 5,
            'period_hours': 168,  # 1 week
            'task': {
                'title': 'DIMM Replacement Required',
                'priority': 'high',
                'action': 'Replace {dimm_slot} on {server_name}'
            }
        },
        {
            'name': 'Fan Speed Degradation',
            'condition': lambda s: s['type'] == 'Fan' and s['trend'] == 'declining',
            'threshold_percent': 15,
            'task': {
                'title': 'Fan Motor Degradation Detected',
                'priority': 'medium',
                'action': 'Inspect/replace {sensor_name} on {server_name}'
            }
        },
        # More rules...
    ]
    
    def evaluate_and_create_tasks(self, customer_id: str):
        """Evaluate rules and create maintenance tasks"""
        events = self._get_recent_events(customer_id)
        sensors = self._get_sensor_data(customer_id)
        
        tasks = []
        
        # Rule-based evaluation
        for rule in self.RULES:
            if matches := self._evaluate_rule(rule, events, sensors):
                for match in matches:
                    task = self._create_task(rule, match, customer_id)
                    tasks.append(task)
        
        # AI-enhanced analysis for complex patterns
        ai_tasks = self._ai_pattern_analysis(customer_id, events, sensors)
        tasks.extend(ai_tasks)
        
        return tasks
```

### Phase 4: Dashboard Integration (Week 4-5)

#### 4.1 AI Results Display in Dashboard

```html
<!-- dashboard.html additions -->

<!-- AI Insights Panel (only visible for paid users) -->
<div id="ai-insights-panel" class="panel ai-panel" style="display:none;">
    <div class="panel-header">
        <h3>🤖 AI Insights</h3>
        <span class="badge pro">PRO</span>
    </div>
    
    <div class="ai-summary">
        <h4>Today's Summary</h4>
        <div id="daily-summary-content">
            <!-- Loaded from /api/ai/summary -->
        </div>
    </div>
    
    <div class="ai-tasks">
        <h4>Suggested Tasks</h4>
        <div id="maintenance-tasks">
            <!-- Loaded from /api/ai/tasks -->
        </div>
    </div>
    
    <div class="ai-predictions">
        <h4>Predictions</h4>
        <div id="predictions-content">
            <!-- Loaded from /api/ai/predictions -->
        </div>
    </div>
</div>
```

---

## API Endpoints

### CryptoLabs Cloud API

```
POST /ipmi/v1/sync
  - License key in header
  - Body: { servers, events, sensors }
  - Response: { success: true, next_sync_in: 300 }

GET /ipmi/v1/results
  - License key in header
  - Response: { summaries: [...], tasks: [...], predictions: [...] }

GET /ipmi/v1/summary/daily
  - License key in header
  - Response: { title, content, generated_at }

GET /ipmi/v1/tasks
  - License key in header
  - Response: [{ id, title, priority, server, action, status }]

POST /ipmi/v1/tasks/{id}/acknowledge
  - Mark task as acknowledged

GET /ipmi/v1/predictions
  - License key in header
  - Response: [{ server, component, prediction, confidence, timeframe }]

POST /ipmi/v1/rca
  - License key in header
  - Body: { event_id }
  - Response: { analysis, root_cause, confidence, suggested_fixes }

GET /ipmi/v1/subscription/status
  - License key in header
  - Response: { tier, servers_used, servers_max, features, expires_at }
```

---

## Pricing & Monetization

### WooCommerce Products

| Product | Price | Description |
|---------|-------|-------------|
| IPMI Monitor Standard | $100/mo | 50 servers, 1M tokens, AI features |
| IPMI Monitor Standard+ | +$15/10 servers | Additional servers + 100K tokens each |
| IPMI Monitor Professional | $500/mo | 500 servers, 10M tokens, priority support |
| Additional Servers | $1/server/mo | For 51+ servers |

### Revenue Projections

| Customers | Avg Servers | Monthly Revenue |
|-----------|-------------|-----------------|
| 10 | 30 | $290 |
| 50 | 40 | $1,450 |
| 100 | 60 | $3,900 (some with extra servers) |
| 500 | 50 | $14,500+ |

---

## Rollout Timeline

### 🚀 PHASE 1: FREE TIER RELEASE (This Week)

| Task | Status | Notes |
|------|--------|-------|
| Remove/disable alerting code | TODO | Move to paid tier |
| Add "Upgrade to Standard" UI prompts | TODO | Settings page, dashboard |
| 50 server limit enforcement | TODO | Soft limit with upgrade prompt |
| Update README for open source | TODO | Installation guide |
| GitHub release | TODO | Tag v1.0.0 |
| Landing page on cryptolabs.co.za | TODO | Product page |

### 📈 PHASE 2: STANDARD TIER (4-6 Weeks)

| Week | Deliverables |
|------|--------------|
| 1-2 | Cloud infrastructure, license system, data sync agent |
| 3-4 | Re-enable alerting for paid users, WooCommerce integration |
| 5-6 | AI summaries, basic predictions |
| 7-8 | RCA, reports, polish & launch |

### 🔮 PHASE 3: AI ENHANCEMENTS (Ongoing)

- Advanced predictive analytics
- Custom automation rules
- Multi-tenant/MSP features
- Compliance reports

---

## Security Checklist

- [ ] License keys are cryptographically secure (UUID v4 + signature)
- [ ] All API calls over HTTPS with TLS 1.3
- [ ] Rate limiting per license key
- [ ] Data isolation verified (no cross-tenant access)
- [ ] LLM prompts never exposed to customers
- [ ] No AI code in client installation
- [ ] Subscription status checked on every request
- [ ] Audit logging for all API calls
- [ ] License key revocation works immediately
- [ ] Customer data deletion on subscription cancel

---

## Next Steps

### IMMEDIATE (Release Free Tier This Week)

1. **Disable alerting in free version**
   - Comment out/gate Telegram, Email, Slack notification code
   - Show "Upgrade to Standard" when user tries to configure alerts

2. **Add server limit (50)**
   - Soft limit: allow adding more but show upgrade prompt
   - Display "X/50 servers" in dashboard header

3. **Add upgrade prompts in UI**
   - Settings page: "🚀 Upgrade to Standard for AI features & alerting"
   - Dashboard: subtle "Standard" badge/banner

4. **Clean up for open source release**
   - Remove BrickBox-specific configs from repo
   - Update README with generic installation guide
   - Add LICENSE file (MIT or Apache 2.0)

5. **Create landing page**
   - cryptolabs.co.za/ipmi-monitor
   - Features, pricing, download link

6. **GitHub release**
   - Tag v1.0.0
   - Release notes

### LATER (Build Standard Tier)

7. Set up CryptoLabs cloud infrastructure
8. Implement license key system
9. Build data sync agent
10. Re-enable alerting for paid users
11. Develop AI pipeline
12. WooCommerce subscription products
13. Launch Standard tier

