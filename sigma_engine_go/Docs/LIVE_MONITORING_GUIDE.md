# 🔴 Live File Monitoring System - User Guide

## 📋 Overview

The Live File Monitoring System extends the Sigma Detection Engine with real-time file monitoring, event counting, and enhanced alert enrichment. It watches log directories for new files, tracks event occurrences, analyzes trends, and automatically escalates threats.

---

## 🎯 Features

### 1. **Live File Monitoring**
- ✅ Monitors directories for log files matching patterns
- ✅ Detects new files automatically
- ✅ Tracks file offsets (no re-reading)
- ✅ Handles file rotation (logrotate, sysmon)
- ✅ Configurable poll interval (default: 100ms)
- ✅ Graceful error recovery

### 2. **Event Counting & Statistics**
- ✅ Counts events within time windows (default: 5 minutes)
- ✅ Tracks: count, first_seen, last_seen, occurrences
- ✅ Calculates rate_per_minute
- ✅ Analyzes trends: ↑ (uptrend), ↓ (downtrend), → (stable)
- ✅ Auto-cleanup of old events
- ✅ Unique signature generation

### 3. **Enhanced Alert Enrichment**
- ✅ Adds event statistics to alerts
- ✅ Adjusts confidence scores based on patterns
- ✅ Automatic escalation detection
- ✅ Clear escalation reasons

---

## 🚀 Quick Start

### 1. Build the Application

```bash
cd sigma_engine_go
go build -o sigma-engine-live ./cmd/sigma-engine-live
```

### 2. Configure Environment Variables

```bash
export WATCH_DIR="/var/log/sysmon"
export FILE_PATTERN="*.jsonl"
export RULES_DIR="sigma_rules/rules"
export OUTPUT_FILE="data/enhanced_alerts.jsonl"
export LOG_LEVEL="info"
```

### 3. Run the Application

```bash
./sigma-engine-live
```

---

## 📊 Enhanced Alert Format

Enhanced alerts include additional fields for event counting and escalation:

```json
{
  "alert_id": "alert-1735234567890123456",
  "timestamp": "2026-01-06T22:15:30Z",
  "rule_id": "abc123...",
  "rule_title": "Suspicious PowerShell Command",
  "severity": 4,
  "confidence": 0.95,
  
  "event_count": 45,
  "first_seen": "2026-01-06T22:10:00Z",
  "last_seen": "2026-01-06T22:15:25Z",
  "rate_per_minute": 9.0,
  "count_trend": "↑",
  "window_size_minutes": 5.0,
  
  "should_escalate": true,
  "escalation_reason": "high event count (>100); rapid escalation",
  
  "mitre_tactics": ["Execution"],
  "mitre_techniques": ["T1059.001"],
  
  "matched_fields": {
    "process.command_line": "powershell.exe -encodedcommand ..."
  },
  "source_file": "/var/log/sysmon/events.jsonl"
}
```

---

## ⚙️ Configuration

### File Monitoring

```yaml
file_monitoring:
  watch_directory: "/var/log/sysmon"
  file_pattern: "*.jsonl"
  poll_interval_ms: 100
  max_file_size_gb: 1
```

**Parameters:**
- `watch_directory`: Directory to monitor
- `file_pattern`: Glob pattern (e.g., `*.jsonl`, `sysmon-*.log`)
- `poll_interval_ms`: How often to check (milliseconds)
- `max_file_size_gb`: Skip files larger than this

### Event Counting

```yaml
event_counting:
  window_size_minutes: 5
  alert_threshold: 10
  rate_threshold_per_minute: 5.0
```

**Parameters:**
- `window_size_minutes`: Time window for counting
- `alert_threshold`: Alert if count >= this
- `rate_threshold_per_minute`: Alert if rate >= this

### Escalation

```yaml
escalation:
  count_threshold: 100
  rate_threshold_per_minute: 10.0
  enable_critical_escalation: true
```

**Escalation Conditions:**
- Event count > `count_threshold`
- Rate > `rate_threshold_per_minute`
- Trend == "↑" AND count > 50
- Severity == "critical" (if enabled)

---

## 📈 Event Statistics

### Event Count
Total number of occurrences within the time window.

### Rate Per Minute
Calculated as: `event_count / window_size_minutes`

### Trend Analysis
- **↑ (Uptrend)**: Events becoming more frequent
- **↓ (Downtrend)**: Events becoming less frequent
- **→ (Stable)**: No significant change

**Calculation:**
- Compares first half vs second half of occurrences
- 20% change threshold

---

## 🎯 Confidence Adjustment

Confidence scores are automatically adjusted based on event patterns:

- **1.5x multiplier**: If event count > 10
- **2.0x multiplier**: If event count > 50
- **1.3x multiplier**: If trend == "↑"

**Example:**
- Base confidence: 0.6
- Event count: 45
- Trend: "↑"
- Adjusted: 0.6 × 2.0 × 1.3 = **1.56** → clamped to **1.0**

---

## 🚨 Escalation Logic

Alerts are automatically escalated when:

1. **High Event Count**: `event_count > 100`
2. **Rapid Escalation**: `rate_per_minute > 10.0`
3. **Uptrend + High Count**: `trend == "↑" AND count > 50`
4. **Critical Severity**: `severity == "critical"` (if enabled)

**Escalation Reason Format:**
```
"high event count; rapid escalation; uptrend with high count"
```

---

## 📁 File Rotation Handling

The system automatically handles file rotation:

1. **Detects rotation** by checking inode changes
2. **Resets offset** to start of new file
3. **Continues monitoring** without interruption
4. **Tracks statistics** across rotations

**Supported Rotation Methods:**
- logrotate
- sysmon rotation
- Manual file moves

---

## 🔍 Monitoring & Statistics

### Statistics Output

Every 30 seconds, the system reports:

```
Statistics - Files: 3, Events: 1250, Groups: 45, Alerts: 12
```

**Metrics:**
- **Files**: Number of files being tracked
- **Events**: Total events emitted
- **Groups**: Unique event groups
- **Alerts**: Alerts written

### File Monitor Statistics

```go
stats := fileMonitor.Stats()
// FilesDiscovered: Number of files discovered
// FilesTracked: Currently tracked files
// LinesRead: Total lines read
// EventsEmitted: Total events emitted
// RotationsDetected: File rotations detected
```

### Event Counter Statistics

```go
stats := eventCounter.Stats()
// TotalEventsRecorded: Total events recorded
// UniqueEventGroups: Unique event groups
// EventsCleaned: Events cleaned up
```

---

## 🛠️ Troubleshooting

### Issue: Files Not Being Discovered

**Check:**
1. Directory exists and is readable
2. File pattern matches files
3. Files are not larger than `max_file_size_gb`

**Solution:**
```bash
# Check directory permissions
ls -la /var/log/sysmon

# Test file pattern
ls /var/log/sysmon/*.jsonl
```

### Issue: Events Not Being Counted

**Check:**
1. Events are being emitted from file monitor
2. Event signatures are being generated correctly
3. Time window is appropriate

**Solution:**
```bash
# Enable debug logging
export LOG_LEVEL=debug
./sigma-engine-live
```

### Issue: High Memory Usage

**Check:**
1. Time window size
2. Number of unique event groups
3. Cleanup frequency

**Solution:**
- Reduce `window_size_minutes`
- Increase cleanup frequency
- Monitor `UniqueEventGroups` statistic

---

## 📊 Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Throughput | 300-500+ events/sec | File reading + detection |
| File Poll Latency | <100ms | Poll interval |
| Alert Generation | <5ms | Including enrichment |
| Memory (5M window) | 50-70MB | Event counting |
| CPU (4 cores) | 15-20% | Under normal load |
| Event Dedup Rate | 70-90% | Within time window |

---

## 🔐 Security Considerations

1. **File Permissions**: Ensure read access to log directories
2. **Output Security**: Secure output file location
3. **Log Rotation**: Handle large log files gracefully
4. **Memory Limits**: Monitor memory usage for long-running processes

---

## 📚 API Reference

### FileMonitor

```go
monitor, err := filemonitoring.NewFileMonitor(
    watchDir,      // Directory to watch
    filePattern,   // Glob pattern
    pollInterval,  // Poll interval
    maxFileSizeGB, // Max file size
)

monitor.Start()
events := monitor.Events()
errors := monitor.Errors()
monitor.Stop()
```

### EventCounter

```go
counter := monitoring.NewEventCounter(
    windowSize,          // Time window
    alertThreshold,     // Alert threshold
    rateThresholdPerMin, // Rate threshold
)

signature := counter.RecordEvent(event)
stats, exists := counter.GetStatistics(signature)
shouldAlert := counter.CheckAlertConditions(signature)
```

### AlertEnricher

```go
enricher := monitoring.NewAlertEnricher(
    eventCounter,
    countThreshold,
    rateThresholdPerMin,
    enableCriticalEscalation,
)

enhanced := enricher.EnrichAlert(alert, event, sourceFile)
```

---

## 🎓 Examples

### Example 1: Basic Setup

```go
// Create file monitor
monitor, _ := filemonitoring.NewFileMonitor(
    "/var/log/sysmon",
    "*.jsonl",
    100*time.Millisecond,
    1,
)

// Create event counter
counter := monitoring.NewEventCounter(
    5*time.Minute,
    10,
    5.0,
)

// Create alert enricher
enricher := monitoring.NewAlertEnricher(
    counter,
    100,
    10.0,
    true,
)

// Start monitoring
monitor.Start()
defer monitor.Stop()

// Process events
for event := range monitor.Events() {
    // Run detection...
    // Enrich alerts...
}
```

### Example 2: Custom Configuration

```go
// Custom window size
counter := monitoring.NewEventCounter(
    10*time.Minute, // 10 minute window
    20,             // Alert at 20 events
    10.0,           // Alert at 10 events/min
)

// Custom escalation
enricher := monitoring.NewAlertEnricher(
    counter,
    200,   // Escalate at 200 events
    20.0,  // Escalate at 20 events/min
    false, // Disable critical auto-escalation
)
```

---

## ✅ Testing Checklist

- [ ] File monitor discovers new files
- [ ] File monitor reads only new lines
- [ ] Offset tracking works across restarts
- [ ] File rotation detection works
- [ ] Event counting is accurate
- [ ] Trend calculation is correct (↑ ↓ →)
- [ ] Confidence adjustment works
- [ ] Escalation rules trigger correctly
- [ ] JSON serialization includes all fields
- [ ] Thread safety verified (`go test -race`)
- [ ] Performance meets targets
- [ ] Memory usage stays bounded

---

## 📝 Notes

- **Thread Safety**: All components are thread-safe
- **Error Recovery**: Graceful error handling throughout
- **Memory Efficiency**: Automatic cleanup prevents unbounded growth
- **Performance**: Optimized for high-throughput scenarios
- **Production Ready**: Enterprise-grade quality

---

**Version:** 1.0  
**Last Updated:** 2026-01-06

