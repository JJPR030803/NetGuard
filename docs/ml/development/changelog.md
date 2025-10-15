# Changelog

All notable changes to the ML Network Analysis Module.

## [Current] - 2025-10-15

### Added
- ✨ **Workflows Module**: High-level workflows for common tasks
  - `DailyAudit`: Automated security audit with 15+ checks
  - `IPInvestigation`: Deep dive into specific IP behavior
  - `ThreatHunting`: Proactive threat hunting (C2, data theft, lateral movement)
  - `WorkflowReport`: Unified reporting with severity ratings

- 📚 **Documentation**: Complete MkDocs Material documentation
  - Architecture guide
  - User guide with workflows
  - API reference
  - Examples and tutorials

- 🛠️ **CLI Enhancements**: New commands
  - `daily-audit`: Run automated security audit
  - `investigate-ip`: Investigate specific IP
  - `threat-hunt`: Hunt for specific threats

### Improved
- 📝 Better error messages and logging
- 🎨 Human-readable report formatting with emoji severity indicators
- 🐛 Fixed Unicode encoding issue in logger.py

## [Previous] - 2025-10-14

### Added
- ✅ **8 Specialized Analyzers**: All completed (~2,400 lines)
  - TCPAnalyzer (387 lines)
  - UDPAnalyzer (205 lines)
  - DNSAnalyzer (282 lines)
  - ARPAnalyzer (225 lines)
  - ICMPAnalyzer (243 lines)
  - FlowAnalyzer (357 lines)
  - IPAnalyzer (412 lines)
  - AnomalyAnalyzer (336 lines)

- 📊 **NetworkParquetAnalysis**: Base class with core functionality
  - Protocol filtering
  - IP information lookup
  - Timestamp queries
  - Behavioral summaries

### Changed
- 🏗️ Reorganized ML module structure
- 📦 Migrated to `uv` for dependency management
- 🔧 Enhanced sniffer configuration system

## Roadmap

### Planned Features

#### Short-term (Next 2 weeks)
- [ ] Unit tests for all analyzers
- [ ] Integration tests with real data
- [ ] Performance benchmarking
- [ ] Utility functions (utils.py)

#### Medium-term (Next month)
- [ ] ML model integration
- [ ] Real-time analysis capabilities
- [ ] Advanced visualization tools
- [ ] Configuration file support (config.yaml)

#### Long-term (Future)
- [ ] Streaming analysis
- [ ] Distributed processing (Spark/Dask)
- [ ] REST API
- [ ] Web dashboard
- [ ] Threat intelligence integration

## Breaking Changes

None yet - initial release

## Migration Guide

### From Old Analysis Code

If you were using individual analyzers:

**Old way:**
```python
analysis = NetworkParquetAnalysis("capture.parquet")
port_scans = analysis.anomaly.detect_port_scanning(...)
syn_floods = analysis.anomaly.detect_syn_flood(...)
# ... many more calls
```

**New way (recommended):**
```python
audit = DailyAudit("capture.parquet")
report = audit.run()  # Automatically runs all checks
```

Low-level analyzer access still works the same way.
