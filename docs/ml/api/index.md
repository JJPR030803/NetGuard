# API Reference

Complete API reference for the ML Network Analysis Module.

## Core Classes

### NetworkParquetAnalysis

Main entry point for all analysis operations.

[:octicons-arrow-right-24: Full Reference](parquet-analysis.md)

### Workflows

High-level workflow classes for common tasks.

[:octicons-arrow-right-24: Workflows API](workflows.md)

## Analyzers

Protocol-specific analyzers:

- [TCP Analyzer](analyzers/tcp.md) - TCP connection and flag analysis
- [UDP Analyzer](analyzers/udp.md) - UDP flow and flood detection  
- [DNS Analyzer](analyzers/dns.md) - DNS query and threat detection
- [IP Analyzer](analyzers/ip.md) - IP-level traffic analysis
- [Flow Analyzer](analyzers/flow.md) - Flow-based behavioral analysis
- [ARP Analyzer](analyzers/arp.md) - ARP spoofing detection
- [ICMP Analyzer](analyzers/icmp.md) - ICMP ping and tunneling
- [Anomaly Analyzer](analyzers/anomaly.md) - Cross-protocol attack detection

## Utilities

- [Utils](utils.md) - Helper functions
- [Errors](errors.md) - Custom exceptions

## Quick Links

- [Architecture](../architecture.md)
- [User Guide](../user-guide/getting-started.md)
- [Examples](../examples/index.md)
