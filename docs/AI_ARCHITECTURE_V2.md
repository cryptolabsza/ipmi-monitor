# AI Architecture V2 - Smart Context Management

## Problem Statement

LLMs have limited context windows (~8K-128K tokens). Dumping all server sensors and events wastes context and produces poor results.

## Solution: Smart Pre-Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        IPMI Monitor (Client)                             │
├─────────────────────────────────────────────────────────────────────────┤
│  1. User selects:                                                        │
│     - Devices: All / Specific servers / Server group                    │
│     - Time Range: 24h / 72h / 7d / 30d                                  │
│     - Report Type: Summary / Tasks / RCA / Chat                         │
│                                                                          │
│  2. Client sends request with filters to AI Service                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        AI Service (Backend)                              │
├─────────────────────────────────────────────────────────────────────────┤
│  3. Data Retrieval Layer                                                 │
│     - Query SQLite for requested devices + time range                   │
│     - Filter events by severity/type                                    │
│     - Get latest sensor readings per device                             │
│                                                                          │
│  4. Pre-Processing Layer (Python Scripts)                               │
│     ┌──────────────────────────────────────────────────────────────┐   │
│     │  summarize_data.py                                            │   │
│     │  ─────────────────                                            │   │
│     │  - Count events by severity (critical/warning/info)          │   │
│     │  - Group events by type (memory, thermal, power, etc.)       │   │
│     │  - Identify patterns (repeated errors, trends)               │   │
│     │  - Extract anomalies (sensors out of range)                  │   │
│     │  - Calculate health scores per device                        │   │
│     │  - Highlight obvious issues:                                 │   │
│     │    • ECC errors → DIMM replacement needed                    │   │
│     │    • Fan RPM < threshold → Fan failing                       │   │
│     │    • Temperature spikes → Cooling issue                      │   │
│     │    • PSU voltage instability → PSU failing                   │   │
│     │    • Multiple reboots → Hardware instability                 │   │
│     └──────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  5. Context Builder                                                      │
│     - Create structured summary (<4K tokens)                            │
│     - Include site background (device names, IPs, roles)                │
│     - Add relevant raw events for context (top 20 most important)       │
│     - Build prompt with clear instructions                              │
│                                                                          │
│  6. LLM Request                                                          │
│     - Send optimized context to LLM                                     │
│     - Parse and format response                                         │
│     - Cache results                                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

## API Changes

### 1. Summary Generation

**Request:**
```json
{
  "type": "health",           // health, events, sensors
  "time_range": "24h",        // 24h, 72h, 7d, 30d
  "devices": ["all"],         // ["all"] or ["brickbox-01", "brickbox-02"]
  "severity_filter": ["critical", "warning"]  // optional filter
}
```

**Backend Processing:**
1. Query events for selected devices + time range
2. Run `summarize_events.py`:
   - Group by device
   - Count by severity
   - Identify patterns
   - Calculate health scores
3. Build context: `{site_info} + {summary} + {top_events}`
4. Send to LLM with health report prompt

### 2. Task Generation

**Request:**
```json
{
  "time_range": "24h",
  "devices": ["all"],
  "task_types": ["memory", "thermal", "power", "fans", "storage"]
}
```

**Backend Processing:**
1. Query events + sensors for devices
2. Run `detect_issues.py`:
   - ECC errors > threshold → "Replace DIMM"
   - Fan RPM declining → "Check/replace fan"
   - Temperature high → "Clean/check cooling"
   - PSU voltage unstable → "Monitor/replace PSU"
   - CMOS battery low → "Replace CMOS battery"
3. Build context with detected issues
4. Send to LLM for task prioritization and details

### 3. Root Cause Analysis

**Request:**
```json
{
  "device": "brickbox-43",     // specific device
  "time_range": "72h",         // look back period
  "event_id": 12345,           // optional: specific event to analyze
  "description": "GPU fell off bus"  // optional: manual description
}
```

**Backend Processing:**
1. Get all events for device in time window
2. Get sensor history for context
3. Run `correlate_events.py`:
   - Timeline of events
   - Related events (same time window)
   - Sensor anomalies at event time
   - Boot/reboot detection
4. Build RCA context with timeline
5. Send to LLM for root cause analysis

### 4. Chat Interface

**Request:**
```json
{
  "question": "Which servers need maintenance?",
  "conversation_id": "uuid-123",  // for history
  "context_devices": ["all"]      // optional device filter
}
```

**Backend Processing:**
1. Load conversation history (if exists)
2. Build site context (always included, user doesn't see):
   - All device names + IPs
   - Last 72h event summary
   - Current sensor status
   - Recent critical/warning events
3. Append user question
4. Send to LLM
5. Save to conversation history

**Chat History Storage:**
```sql
CREATE TABLE chat_history (
    id INTEGER PRIMARY KEY,
    customer_id TEXT,
    conversation_id TEXT,
    role TEXT,              -- 'user' or 'assistant'
    content TEXT,
    created_at TIMESTAMP
);
```

## Pre-Processing Scripts

### `preprocess/summarize_events.py`

```python
def summarize_events(events: List[dict], devices: List[str]) -> dict:
    """
    Create a compact summary of events for LLM context.
    
    Returns:
        {
            "total_events": 150,
            "by_severity": {"critical": 5, "warning": 25, "info": 120},
            "by_type": {"memory": 30, "thermal": 10, ...},
            "by_device": {"brickbox-01": {"critical": 1, ...}, ...},
            "patterns": [
                "ECC errors recurring on brickbox-06 (5 in 24h)",
                "Temperature warnings on rack 3 devices"
            ],
            "top_issues": [
                {"device": "brickbox-06", "issue": "Uncorrectable ECC", "count": 2},
                ...
            ],
            "health_scores": {"brickbox-01": 95, "brickbox-06": 45, ...}
        }
    """
```

### `preprocess/detect_issues.py`

```python
def detect_actionable_issues(events: List, sensors: List) -> List[dict]:
    """
    Identify issues that need maintenance action.
    
    Returns:
        [
            {
                "device": "brickbox-06",
                "type": "memory",
                "severity": "critical",
                "issue": "Uncorrectable ECC errors on DIMM A1",
                "action": "Replace DIMM A1",
                "urgency": "immediate",
                "evidence": ["Event #123: Uncorrectable ECC...", ...]
            },
            ...
        ]
    """
```

### `preprocess/correlate_events.py`

```python
def correlate_for_rca(device: str, events: List, sensors: List, 
                       target_time: datetime = None) -> dict:
    """
    Build timeline and correlations for RCA.
    
    Returns:
        {
            "device": "brickbox-43",
            "timeline": [
                {"time": "...", "event": "GPU 3 AER Error"},
                {"time": "...", "event": "System reboot detected"},
                ...
            ],
            "sensor_anomalies": [
                {"sensor": "GPU3_Temp", "anomaly": "Spike to 95°C before error"}
            ],
            "related_devices": ["brickbox-42"],  # same switch/PDU
            "possible_causes": [
                "GPU thermal throttle followed by bus error",
                "PCIe link instability"
            ]
        }
    """
```

## UI Changes (Client Side)

### Summary Panel
```
┌─────────────────────────────────────────────────────────┐
│  📊 Fleet Summary                                       │
├─────────────────────────────────────────────────────────┤
│  Report Type: [Health ▼]                                │
│  Time Range:  [24h ▼]                                   │
│  Devices:     [All Servers ▼] or [Select...]           │
│                                                         │
│  [Generate Summary]                                     │
│                                                         │
│  ─────────────────────────────────────────────────────  │
│  Last generated: 5 minutes ago                          │
│  [View Previous Reports ▼]                              │
└─────────────────────────────────────────────────────────┘
```

### Chat Panel with History
```
┌─────────────────────────────────────────────────────────┐
│  💬 AI Chat                     [New Chat] [History ▼]  │
├─────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────┐  │
│  │ Conversation: "Maintenance Planning" - 2h ago     │  │
│  │ ─────────────────────────────────────────────────│  │
│  │ You: Which servers need attention?               │  │
│  │ AI: Based on the last 72h of data...            │  │
│  │                                                   │  │
│  │ You: Tell me more about brickbox-06              │  │
│  │ AI: Brickbox-06 has critical memory issues...   │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  [Ask a question...                            ] [Send] │
└─────────────────────────────────────────────────────────┘
```

### RCA Panel
```
┌─────────────────────────────────────────────────────────┐
│  🔍 Root Cause Analysis                                 │
├─────────────────────────────────────────────────────────┤
│  Device:     [brickbox-43 ▼]                           │
│  Time Range: [72h ▼]                                    │
│                                                         │
│  Select Event: [Event dropdown or "Describe manually"] │
│  OR                                                     │
│  Describe Issue: [GPU fell off bus, required reboot]   │
│                                                         │
│  [Analyze]                                              │
└─────────────────────────────────────────────────────────┘
```

## Sync Improvements

### Progress Tracking
```python
# Sync status stored in database
sync_status = {
    "state": "syncing",       # idle, syncing, complete, error
    "progress": 45,           # percentage
    "current_step": "Uploading events...",
    "events_synced": 150,
    "events_total": 300,
    "started_at": "...",
    "estimated_remaining": "30s"
}
```

### UI Progress Bar
```
┌─────────────────────────────────────────────────────────┐
│  Syncing to CryptoLabs AI...                           │
│  [████████████░░░░░░░░░░░░░░] 45%                      │
│  Uploading events... (150/300)                         │
│  Estimated: 30 seconds remaining                        │
└─────────────────────────────────────────────────────────┘
```

## PCI/GPU Error Detection

To catch events like GPU falling off bus:

1. **Expanded SEL parsing** - Look for:
   - `Critical Interrupt` events
   - `System Boot` events (indicate reboot)
   - `OEM` specific events
   - Time gaps in SEL (suggest reboot)

2. **Correlation with BIOS/POST**:
   - Track boot count changes
   - Detect unplanned reboots

3. **Sensor correlation**:
   - GPU temperature spikes before error
   - Power supply fluctuations

4. **Manual event input**:
   - Allow users to describe observed issues
   - RCA can analyze even without SEL event

## Implementation Priority

1. **Phase 1** (This week):
   - [ ] Device selection UI
   - [ ] Pre-processing scripts
   - [ ] Sync progress bar

2. **Phase 2** (Next week):
   - [ ] Chat history persistence
   - [ ] Improved RCA with manual input
   - [ ] Event correlation

3. **Phase 3** (Following week):
   - [ ] Advanced pattern detection
   - [ ] Predictive failure models
   - [ ] Report history/export

