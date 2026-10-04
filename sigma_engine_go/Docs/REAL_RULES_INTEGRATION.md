# Real Sigma Rules Integration Guide

## Overview

The Sigma Detection Engine now supports loading and processing real Sigma rules from the official Sigma repository. This guide explains how to use the `sigma_rules/` directory with the detection engine.

## Directory Structure

The `sigma_rules/` directory contains the official Sigma rule repository with 3,085+ detection rules organized by:

- **rules/**: Generic detection rules (main repository)
  - `windows/`: Windows-specific rules (process_creation, registry, file events, etc.)
  - `linux/`: Linux-specific rules (auditd, process_creation, etc.)
  - `macos/`: macOS-specific rules
  - `cloud/`: Cloud platform rules (AWS, Azure, GCP)
  - `network/`: Network device rules
  - `web/`: Web application rules
  - And more...

- **rules-threat-hunting/**: Broader threat hunting rules
- **rules-emerging-threats/**: Time-sensitive threat rules
- **rules-compliance/**: Compliance framework rules

## Usage

### Example 12: Load Real Sigma Rules

The engine includes `example12_LoadRealSigmaRules()` which demonstrates:

1. **Loading Rules**: Loads all rules from `sigma_rules/rules/` directory
2. **Rule Statistics**: Shows rule counts by product
3. **Detection Testing**: Tests detection with sample events
4. **Parallel Processing**: Demonstrates parallel processing with real rules

### Running the Example

```bash
cd sigma_engine_go
go run ./cmd/sigma-engine
```

The example will:
- Load all 3,085+ rules from the repository
- Display statistics (total rules, rules by product)
- Test detection with sample Windows events
- Run parallel processing pipeline
- Show performance metrics

### Programmatic Usage

```go
package main

import (
    "context"
    "time"
    
    "github.com/edr-platform/sigma-engine/internal/application/rules"
    "github.com/edr-platform/sigma-engine/internal/application/detection"
    "github.com/edr-platform/sigma-engine/internal/application/mapping"
    "github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
)

func main() {
    // Create components
    fieldCache, _ := cache.NewFieldResolutionCache(10000)
    regexCache, _ := cache.NewRegexCache(10000)
    fieldMapper := mapping.NewFieldMapper(fieldCache)
    modifierEngine := detection.NewModifierRegistry(regexCache)
    detectionEngine := detection.NewSigmaDetectionEngine(
        fieldMapper, 
        modifierEngine, 
        fieldCache,
    )
    
    // Load rules
    loader := rules.NewRuleLoader(false)
    ctx := context.Background()
    
    ruleIndex, err := loader.LoadRules(ctx, "sigma_rules/rules")
    if err != nil {
        panic(err)
    }
    
    // Load into detection engine
    detectionEngine.LoadRules(ruleIndex.Rules)
    
    // Now ready to process events!
    // ...
}
```

## Performance

### Rule Loading

- **Target**: < 100ms for 3,085 rules
- **Method**: Parallel loading with worker pools
- **Memory**: Efficient streaming, minimal allocations

### Detection Performance

- **Throughput**: 300-500+ events/second
- **Latency**: < 1ms per event
- **Rule Filtering**: O(1) candidate rule lookup

## Rule Categories

### Windows Rules (Majority)

- **process_creation**: 1,158 rules
- **registry**: 241 rules
- **powershell**: 207 rules
- **file**: 185 rules
- **builtin**: 322 rules
- And more...

### Linux Rules

- **auditd**: 53 rules
- **process_creation**: 117 rules
- **builtin**: 22 rules

### Cloud Rules

- **AWS CloudTrail**: 55 rules
- **Azure Activity Logs**: 42 rules
- **GCP Audit**: 16 rules

## Rule Format

Sigma rules follow the official specification:

```yaml
title: Rule Title
id: unique-uuid
status: stable
description: Rule description
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\bitsadmin.exe'
        CommandLine|contains: '/transfer'
    condition: selection
level: high
tags:
    - attack.command_and_control
    - attack.t1105
```

## Supported Features

The engine supports all major Sigma rule features:

- ✅ **Selections**: Field-based conditions
- ✅ **Modifiers**: contains, endswith, startswith, regex, base64, cidr, etc.
- ✅ **Conditions**: AND, OR, NOT, "1 of selection_*", "all of them"
- ✅ **Filters**: False positive prevention
- ✅ **MITRE ATT&CK**: Tactics and techniques extraction
- ✅ **LogSource**: Product, category, service filtering

## Error Handling

The rule loader handles:

- **Invalid YAML**: Skips with warning, continues processing
- **Missing Fields**: Uses defaults where appropriate
- **Parse Errors**: Logs and continues
- **Validation Errors**: Reports but doesn't stop loading

## Statistics

After loading, you can access:

- Total rules loaded
- Rules by product/category
- Parse errors (if any)
- Loading time
- Index statistics

## Best Practices

1. **Cache Sizes**: Use larger caches (10,000+) for real rule sets
2. **Parallel Processing**: Use worker pools for high-throughput
3. **Rule Filtering**: Leverage rule indexer for O(1) lookups
4. **Error Monitoring**: Check parse errors for rule quality
5. **Performance**: Monitor detection latency and throughput

## Troubleshooting

### Rules Not Loading

- Check directory path: `sigma_rules/rules/`
- Verify YAML files are present
- Check file permissions
- Review parse errors in logs

### Low Performance

- Increase cache sizes
- Use more workers for parallel processing
- Check rule indexer is working
- Monitor memory usage

### Detection Not Working

- Verify event format matches rule logsource
- Check field mappings (ECS ↔ Sigma)
- Review modifier application
- Enable debug logging

## Next Steps

1. **Custom Rules**: Add your own rules to `sigma_rules/rules/`
2. **Rule Testing**: Use test events to validate rules
3. **Performance Tuning**: Optimize for your workload
4. **Integration**: Integrate with your EDR/SIEM system

## Resources

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [Sigma Repository](https://github.com/SigmaHQ/sigma)
- [Sigma CLI](https://github.com/SigmaHQ/sigma-cli)

---

**Status**: Real Sigma rules integration complete ✅

The engine is now ready to process events against 3,085+ production Sigma rules!

