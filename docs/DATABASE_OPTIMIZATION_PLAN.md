# Database Optimization Plan for v0.8.2

## Current State Analysis

### Database Size
- **Total Size**: 636.5 MB (growing ~20MB/day)
- **Projected 30-day size**: ~600MB (if cleanup works properly)

### Table Row Counts
| Table | Rows | Notes |
|-------|------|-------|
| sensor_reading | 2,193,664 | **Biggest table** - 50 sensors × 39 servers × 12/hr × 24hr × 30 days |
| ssh_logs | 65,731 | Collected hourly, synced to AI service |
| power_reading | 43,111 | Redundant with sensor_reading (power sensors exist) |
| ipmi_event | 35,965 | SEL events - important for RCA |
| ai_result | 1,115 | Cached AI results |

### Current Schema Issues

#### 1. **Sensor Reading Explosion** 🔴 CRITICAL
- Each sensor gets its own row per collection
- 39 servers × 50 sensors × 12/hour × 24 hours = **561,600 rows/day**
- Timestamps are microsecond-precise (almost all unique)

#### 2. **Redundant Tables** 🟡 MEDIUM
- `power_reading` duplicates data from `sensor_reading` (power sensors)
- `server_status` and `server_uptime` could be merged
- `ServerConfig` duplicates `Server.server_ip`

#### 3. **Missing Cleanup** 🟡 MEDIUM  
- 581,250 sensor readings older than 30 days still exist
- Cleanup timer may not be running effectively

#### 4. **Inefficient Queries** 🟢 LOW
- Multiple COUNT queries on page load
- No query caching for dashboard stats

---

## Implementation Status

### Phase 1: Immediate Fixes (v0.8.2) ✅ COMPLETED

#### 1.1 Fix Data Cleanup ✅ DONE
- Cleanup now runs **immediately on startup** (no 5-minute delay)
- Uses **batched deletions** (10K rows at a time, 50K for aggressive mode)
- Added progress logging for large deletions
- **SSH logs cleanup** added (7-day retention)
- **VACUUM** runs after large deletions to reclaim disk space

#### 1.2 Aggregate Sensor Readings ✅ DONE
New tables created:

**Table: `sensor_hourly_aggregate`**
```sql
CREATE TABLE sensor_hourly_aggregate (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bmc_ip VARCHAR(20) NOT NULL,
    server_name VARCHAR(50) NOT NULL,
    sensor_name VARCHAR(50) NOT NULL,
    sensor_type VARCHAR(30) NOT NULL,
    hour DATETIME NOT NULL,
    min_value FLOAT,
    max_value FLOAT,
    avg_value FLOAT,
    reading_count INTEGER DEFAULT 0,
    had_warning BOOLEAN DEFAULT 0,
    had_critical BOOLEAN DEFAULT 0,
    unit VARCHAR(20),
    UNIQUE(bmc_ip, sensor_name, hour)
);
```

**Table: `power_hourly_aggregate`**
```sql
CREATE TABLE power_hourly_aggregate (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bmc_ip VARCHAR(20) NOT NULL,
    server_name VARCHAR(50) NOT NULL,
    hour DATETIME NOT NULL,
    min_watts FLOAT,
    max_watts FLOAT,
    avg_watts FLOAT,
    reading_count INTEGER DEFAULT 0,
    UNIQUE(bmc_ip, hour)
);
```

**Aggregation process:**
- Runs **before cleanup** (every 6 hours)
- Processes up to 24 hours at a time
- Aggregates min/max/avg per sensor per hour
- Tracks warning/critical status for anomaly detection

**Reduction**: 2.2M rows → ~50K rows (kept for 7 days) + hourly aggregates

### Phase 2: Schema Consolidation (v0.8.3) 📋 PLANNED

#### 2.1 Merge Server Tables
Consolidate into single `Server` model:
- `Server` (keep)
- `ServerConfig` → merge SSH/IPMI config into `Server`
- `ServerStatus` → add columns to `Server`
- `ServerUptime` → add column to `Server`

**Before**: 4 tables, 3 JOINs
**After**: 1 table, 0 JOINs

#### 2.2 Add Latest Sensor Cache
```sql
CREATE TABLE sensor_latest (
    bmc_ip VARCHAR(20) PRIMARY KEY,
    sensors_json TEXT,  -- JSON blob of all sensors
    updated_at DATETIME
);
```
- Single row per server
- Dashboard loads 1 row instead of 50

#### 2.3 Remove Redundant Tables
- Remove `power_reading` table (data in sensor_reading + aggregates)
- After grace period, consider dropping `sensor_reading` rows older than 7 days

### Phase 3: Query Optimization (v0.8.3+) 📋 PLANNED

#### 3.1 Dashboard Stats Caching
```python
from functools import lru_cache
import time

_stats_cache = {}
_stats_cache_time = 0
STATS_CACHE_TTL = 60  # seconds

def get_dashboard_stats():
    global _stats_cache, _stats_cache_time
    if time.time() - _stats_cache_time < STATS_CACHE_TTL:
        return _stats_cache
    
    _stats_cache = {
        'total_servers': Server.query.count(),
        'online_servers': ServerStatus.query.filter_by(is_reachable=True).count(),
        # ... etc
    }
    _stats_cache_time = time.time()
    return _stats_cache
```

#### 3.2 Batch Queries
Replace:
```python
for server in servers:
    events = IPMIEvent.query.filter_by(bmc_ip=server.bmc_ip).count()
```
With:
```python
counts = db.session.query(IPMIEvent.bmc_ip, func.count()).group_by(IPMIEvent.bmc_ip).all()
```

---

## Implementation Priority

| Priority | Task | Impact | Effort | Status |
|----------|------|--------|--------|--------|
| 🔴 P0 | Fix data cleanup | -500MB | Low | ✅ Done |
| 🔴 P0 | Aggregate sensor readings | -95% rows | Medium | ✅ Done |
| 🟡 P1 | Remove power_reading table | -43K rows | Low | 📋 v0.8.3 |
| 🟡 P1 | Merge server tables | Faster queries | Medium | 📋 v0.8.3 |
| 🟢 P2 | Add sensor_latest cache | Faster dashboard | Low | 📋 v0.8.3 |
| 🟢 P2 | Query result caching | Faster pages | Low | 📋 v0.8.3 |

---

## Expected Results

### Before (v0.8.1)
- Database: 636 MB
- Sensor rows: 2.2M (growing 560K/day)
- Cleanup: Ineffective
- Memory usage: High

### After (v0.8.2)
- Database: ~100 MB (after first cleanup)
- Sensor rows: ~100K (7 days raw) + hourly aggregates
- Cleanup: Runs on startup, batched, with VACUUM
- Memory usage: Reduced 70%

### Target (v0.8.3)
- Database: ~50 MB
- Dashboard load: ~100ms
- Memory usage: Minimal

---

## New Features in v0.8.2

### Aggregated Data API (TODO)
New API endpoints to query aggregated data:
- `GET /api/sensors/<bmc_ip>/history?hours=72` - Returns hourly aggregates
- `GET /api/power/<bmc_ip>/history?days=7` - Returns power trends

### Historical Charts
- Use aggregated data for trend charts
- Show min/max/avg bands
- Highlight periods with warnings/critical status

---

## Rollback Plan

Keep original tables for 7 days after migration. If issues:
1. Revert code to use old tables
2. Old data still available
3. No data loss
