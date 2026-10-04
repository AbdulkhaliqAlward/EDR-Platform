# ⚙️ Configuration Guide - Sigma Detection Engine

## 📋 Overview

The Sigma Detection Engine now uses a comprehensive YAML-based configuration system. All settings can be easily modified in `config/config.yaml` without code changes.

---

## 📁 Configuration File Location

**Default:** `config/config.yaml`

You can specify a custom path using the `-config` flag:
```bash
./sigma-engine-live -config /path/to/custom/config.yaml
```

---

## 🔧 Configuration Sections

### 1. File Monitoring

```yaml
file_monitoring:
  watch_directory: "data/agent_ecs-events"  # Directory to watch
  file_pattern: "*.jsonl"                   # File pattern (glob)
  poll_interval_ms: 100                     # Poll interval (milliseconds)
  max_file_size_gb: 1                       # Max file size to monitor
```

**Description:**
- `watch_directory`: Directory containing log files from agents
- `file_pattern`: Glob pattern to match files (e.g., `*.jsonl`, `sysmon-*.log`)
- `poll_interval_ms`: How often to check for new files/lines (lower = more responsive, higher = less CPU)
- `max_file_size_gb`: Skip files larger than this (prevents memory issues)

**Default Values:**
- Watch directory: `data/agent_ecs-events`
- File pattern: `*.jsonl`
- Poll interval: `100ms`
- Max file size: `1GB`

---

### 2. Event Counting

```yaml
event_counting:
  window_size_minutes: 5                    # Time window for counting
  alert_threshold: 10                        # Alert if count >= this
  rate_threshold_per_minute: 5.0            # Alert if rate >= this
```

**Description:**
- `window_size_minutes`: Time window for counting events (sliding window)
- `alert_threshold`: Generate alert if event count reaches this threshold
- `rate_threshold_per_minute`: Generate alert if rate exceeds this (events/minute)

**Default Values:**
- Window size: `5 minutes`
- Alert threshold: `10 events`
- Rate threshold: `5.0 events/minute`

---

### 3. Escalation

```yaml
escalation:
  count_threshold: 100                      # Escalate if count > this
  rate_threshold_per_minute: 10.0           # Escalate if rate > this
  enable_critical_escalation: true          # Auto-escalate critical alerts
```

**Description:**
- `count_threshold`: Escalate alerts if event count exceeds this
- `rate_threshold_per_minute`: Escalate if rate exceeds this
- `enable_critical_escalation`: Automatically escalate all critical severity alerts

**Escalation Conditions:**
- Event count > `count_threshold`
- Rate > `rate_threshold_per_minute`
- Trend == "↑" AND count > 50
- Severity == "critical" (if enabled)

**Default Values:**
- Count threshold: `100`
- Rate threshold: `10.0 events/minute`
- Critical escalation: `true`

---

### 4. Detection Engine

```yaml
detection:
  workers: 0                                 # Number of workers (0 = CPU count)
  batch_size: 100                            # Batch size for processing
  cache_size: 10000                          # Cache size for field resolution
```

**Description:**
- `workers`: Number of worker goroutines (0 = use CPU count, set to specific number for control)
- `batch_size`: Number of events to process in each batch
- `cache_size`: Size of field resolution and regex caches

**Default Values:**
- Workers: `0` (uses CPU count)
- Batch size: `100`
- Cache size: `10000`

**Performance Tuning:**
- Increase `workers` for higher throughput (but more CPU)
- Increase `batch_size` for better efficiency (but higher latency)
- Increase `cache_size` for better hit rates (but more memory)

---

### 5. Output

```yaml
output:
  output_file: "data/alerts.jsonl"          # Output file path
  log_level: "info"                          # Log level (debug/info/warn/error)
```

**Description:**
- `output_file`: Path to output file for alerts (JSONL format)
  - **Will be created automatically if it doesn't exist**
  - Directory will be created if needed
- `log_level`: Logging verbosity level

**Default Values:**
- Output file: `data/alerts.jsonl`
- Log level: `info`

**Log Levels:**
- `debug`: Detailed debugging information (verbose)
- `info`: General information (recommended for production)
- `warn`: Warnings only
- `error`: Errors only

---

### 6. Rules

```yaml
rules:
  rules_directory: "sigma_rules/rules"      # Directory containing Sigma rules
```

**Description:**
- `rules_directory`: Path to directory containing Sigma rule files (`.yml` or `.yaml`)

**Default Value:**
- Rules directory: `sigma_rules/rules`

---

## 🚀 Quick Start

### 1. Create Configuration File

Copy the example configuration:
```bash
cp config.example.yaml config/config.yaml
```

### 2. Edit Configuration

Edit `config/config.yaml` with your settings:
```yaml
file_monitoring:
  watch_directory: "data/agent_ecs-events"
  file_pattern: "*.jsonl"

output:
  output_file: "data/alerts.jsonl"
```

### 3. Run the Application

```bash
# Use default config (config/config.yaml)
./sigma-engine-live

# Use custom config
./sigma-engine-live -config /path/to/config.yaml
```

---

## 📝 Configuration Examples

### Example 1: High-Performance Setup

```yaml
detection:
  workers: 16
  batch_size: 500
  cache_size: 50000

file_monitoring:
  poll_interval_ms: 50

output:
  log_level: "warn"
```

### Example 2: Development Setup

```yaml
detection:
  workers: 2
  batch_size: 50
  cache_size: 1000

file_monitoring:
  poll_interval_ms: 200

output:
  log_level: "debug"
```

### Example 3: Custom Paths

```yaml
file_monitoring:
  watch_directory: "/var/log/edr/events"
  file_pattern: "events-*.jsonl"

output:
  output_file: "/var/log/edr/alerts.jsonl"

rules:
  rules_directory: "/opt/sigma/rules"
```

---

## ✅ Automatic File Creation

The system automatically creates:

1. **Output File**: `data/alerts.jsonl`
   - Directory is created if it doesn't exist
   - File is created if it doesn't exist
   - File is verified to be writable

2. **Watch Directory**: `data/agent_ecs-events`
   - Directory is created if it doesn't exist
   - Directory is verified to be readable

**No manual file creation needed!**

---

## 🔍 Configuration Validation

The system validates configuration on startup:

- ✅ Watch directory exists and is readable
- ✅ Output file directory is writable
- ✅ Rules directory exists
- ✅ Log level is valid
- ✅ All numeric values are positive

**If validation fails, the application will not start.**

---

## 🎯 Recommended Settings

### Production

```yaml
detection:
  workers: 0              # Use all CPUs
  batch_size: 200
  cache_size: 50000

file_monitoring:
  poll_interval_ms: 100

output:
  log_level: "info"
```

### Development

```yaml
detection:
  workers: 2
  batch_size: 50
  cache_size: 1000

file_monitoring:
  poll_interval_ms: 500

output:
  log_level: "debug"
```

### High-Throughput

```yaml
detection:
  workers: 16
  batch_size: 1000
  cache_size: 100000

file_monitoring:
  poll_interval_ms: 50
```

---

## 📊 Configuration File Structure

```yaml
# Complete configuration structure
file_monitoring:
  watch_directory: "data/agent_ecs-events"
  file_pattern: "*.jsonl"
  poll_interval_ms: 100
  max_file_size_gb: 1

event_counting:
  window_size_minutes: 5
  alert_threshold: 10
  rate_threshold_per_minute: 5.0

escalation:
  count_threshold: 100
  rate_threshold_per_minute: 10.0
  enable_critical_escalation: true

detection:
  workers: 0
  batch_size: 100
  cache_size: 10000

output:
  output_file: "data/alerts.jsonl"
  log_level: "info"

rules:
  rules_directory: "sigma_rules/rules"
```

---

## 🔄 Reloading Configuration

**Note:** Configuration is loaded once at startup. To apply changes:

1. Stop the application (`Ctrl+C`)
2. Edit `config/config.yaml`
3. Restart the application

**Future Enhancement:** Hot-reload support may be added in future versions.

---

## 🛠️ Troubleshooting

### Issue: Configuration file not found

**Error:**
```
Config file not found at config/config.yaml, using defaults
```

**Solution:**
- Create `config/config.yaml` from `config.example.yaml`
- Or specify custom path: `-config /path/to/config.yaml`

### Issue: Output file cannot be created

**Error:**
```
Failed to create output file: permission denied
```

**Solution:**
- Check directory permissions
- Ensure parent directory exists
- Check disk space

### Issue: Watch directory not found

**Error:**
```
Watch directory does not exist: data/agent_ecs-events
```

**Solution:**
- Create the directory manually, or
- The system will create it automatically (if parent directory is writable)

---

## 📚 See Also

- `LIVE_MONITORING_GUIDE.md` - Complete live monitoring guide
- `config.example.yaml` - Example configuration file
- `QUICK_START_AR.md` - Quick start guide

---

**Version:** 1.0  
**Last Updated:** 2026-01-06

