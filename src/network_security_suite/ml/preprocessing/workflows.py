#!/usr/bin/env python3
"""
High-level workflows for common network analysis tasks.

This module provides simplified interfaces for common security analysis workflows,
making it easier to perform routine checks without dealing with individual analyzers.
"""

import json
from datetime import datetime, time
from pathlib import Path
from typing import Any, Optional

from .logger import get_logger
from .parquet_analysis import NetworkParquetAnalysis


class WorkflowReport:
    """Base class for workflow reports with consistent formatting."""

    def __init__(self, title: str):
        self.title = title
        self.timestamp = datetime.now()
        self.sections = {}
        self.findings = []
        self.severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

    def add_section(self, name: str, data: Any):
        """Add a section to the report."""
        self.sections[name] = data

    def add_finding(
        self, severity: str, category: str, description: str, details: Any = None
    ):
        """
        Add a security finding.

        Args:
            severity: critical, high, medium, low, info
            category: Type of finding (e.g., "Port Scan", "SYN Flood")
            description: Human-readable description
            details: Additional details (dict, dataframe, etc.)
        """
        self.findings.append(
            {
                "severity": severity,
                "category": category,
                "description": description,
                "details": details,
                "timestamp": datetime.now().isoformat(),
            }
        )
        if severity in self.severity_counts:
            self.severity_counts[severity] += 1

    def summary(self) -> str:
        """Generate a human-readable summary."""
        lines = []
        lines.append("=" * 80)
        lines.append(f"  {self.title}")
        lines.append(f"  Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)
        lines.append("")

        # Severity summary
        if any(self.severity_counts.values()):
            lines.append("FINDINGS SUMMARY:")
            if self.severity_counts["critical"] > 0:
                lines.append(f"  🔴 Critical: {self.severity_counts['critical']}")
            if self.severity_counts["high"] > 0:
                lines.append(f"  🟠 High:     {self.severity_counts['high']}")
            if self.severity_counts["medium"] > 0:
                lines.append(f"  🟡 Medium:   {self.severity_counts['medium']}")
            if self.severity_counts["low"] > 0:
                lines.append(f"  🔵 Low:      {self.severity_counts['low']}")
            if self.severity_counts["info"] > 0:
                lines.append(f"  ⚪ Info:     {self.severity_counts['info']}")
            lines.append("")
        else:
            lines.append("✅ No security findings detected")
            lines.append("")

        # Detailed findings
        if self.findings:
            lines.append("DETAILED FINDINGS:")
            lines.append("-" * 80)
            for finding in self.findings:
                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🔵",
                    "info": "⚪",
                }.get(finding["severity"], "•")

                lines.append(
                    f"{severity_icon} [{finding['severity'].upper()}] {finding['category']}"
                )
                lines.append(f"   {finding['description']}")
                if finding["details"]:
                    lines.append(f"   Details: {finding['details']}")
                lines.append("")

        # Sections
        if self.sections:
            lines.append("ADDITIONAL INFORMATION:")
            lines.append("-" * 80)
            for name, data in self.sections.items():
                lines.append(f"\n{name}:")
                lines.append(str(data))
                lines.append("")

        lines.append("=" * 80)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Export report as dictionary."""
        return {
            "title": self.title,
            "timestamp": self.timestamp.isoformat(),
            "severity_counts": self.severity_counts,
            "findings": self.findings,
            "sections": {k: str(v) for k, v in self.sections.items()},
        }

    def to_json(self, file_path: Optional[str] = None) -> str:
        """Export report as JSON."""
        json_str = json.dumps(self.to_dict(), indent=2, default=str)
        if file_path:
            Path(file_path).write_text(json_str)
        return json_str


class DailyAudit:
    """
    Automated daily security audit workflow.

    Performs comprehensive security checks including:
    - Port scanning detection
    - SYN flood attacks
    - DNS tunneling
    - Top bandwidth consumers
    - Failed connections
    - Data exfiltration patterns
    - Off-hours activity

    Example:
        audit = DailyAudit("capture.parquet")
        report = audit.run()
        print(report.summary())
        report.to_json("daily_audit.json")
    """

    def __init__(
        self,
        parquet_file: str,
        business_hours: tuple = (time(9, 0), time(17, 0)),
        lazy_load: bool = False,
    ):
        """
        Initialize daily audit.

        Args:
            parquet_file: Path to parquet file to analyze
            business_hours: Tuple of (start_time, end_time) for off-hours detection
            lazy_load: Use lazy loading for analyzers
        """
        self.parquet_file = parquet_file
        self.business_hours = business_hours
        self.logger = get_logger()

        self.logger.info(f"Initializing DailyAudit for {parquet_file}")
        self.analysis = NetworkParquetAnalysis(parquet_file, lazy_load=lazy_load)

    def run(self) -> WorkflowReport:
        """
        Run complete daily audit and generate report.

        Returns:
            WorkflowReport with all findings
        """
        self.logger.info("Starting daily security audit")
        report = WorkflowReport("Daily Security Audit Report")

        # Basic statistics
        self._check_basic_stats(report)

        # Threat detection
        self._check_port_scans(report)
        self._check_syn_floods(report)
        self._check_udp_floods(report)
        self._check_dns_threats(report)
        self._check_arp_threats(report)
        self._check_icmp_threats(report)

        # Behavioral analysis
        self._check_top_talkers(report)
        self._check_failed_connections(report)
        self._check_suspicious_ips(report)
        self._check_data_exfiltration(report)
        self._check_off_hours_activity(report)

        # Advanced threats
        self._check_beaconing(report)
        self._check_scanning_patterns(report)

        self.logger.info(f"Daily audit complete: {len(report.findings)} findings")
        return report

    def _check_basic_stats(self, report: WorkflowReport):
        """Add basic network statistics."""
        try:
            total_packets = self.analysis.get_packet_count()
            date_range = self.analysis.get_date_range()

            stats = {
                "total_packets": f"{total_packets:,}",
                "start_time": date_range.get("start"),
                "end_time": date_range.get("end"),
                "duration": date_range.get("duration"),
            }

            report.add_section("Network Statistics", stats)
            report.add_finding(
                "info", "Statistics", f"Analyzed {total_packets:,} packets"
            )
        except Exception as e:
            self.logger.error(f"Failed to get basic stats: {e}")

    def _check_port_scans(self, report: WorkflowReport):
        """Detect port scanning activity."""
        try:
            port_scans = self.analysis.anomaly.detect_port_scanning(
                threshold=100, time_window="1m"
            )

            if len(port_scans) > 0:
                report.add_finding(
                    "high",
                    "Port Scan",
                    f"Detected {len(port_scans)} potential port scanning sources",
                    f"Top scanner: {port_scans[0] if len(port_scans) > 0 else 'N/A'}",
                )
        except Exception as e:
            self.logger.warning(f"Port scan detection failed: {e}")

    def _check_syn_floods(self, report: WorkflowReport):
        """Detect SYN flood attacks."""
        try:
            syn_floods = self.analysis.anomaly.detect_syn_flood(
                threshold=1000, time_window="1m"
            )

            if len(syn_floods) > 0:
                report.add_finding(
                    "critical",
                    "SYN Flood",
                    f"Detected {len(syn_floods)} potential SYN flood attacks",
                    f"Affected targets: {len(syn_floods)}",
                )
        except Exception as e:
            self.logger.warning(f"SYN flood detection failed: {e}")

    def _check_udp_floods(self, report: WorkflowReport):
        """Detect UDP flood attacks."""
        try:
            udp_floods = self.analysis.anomaly.detect_udp_flood(
                threshold=500, time_window="1m"
            )

            if len(udp_floods) > 0:
                report.add_finding(
                    "high",
                    "UDP Flood",
                    f"Detected {len(udp_floods)} potential UDP flood attacks",
                )
        except Exception as e:
            self.logger.warning(f"UDP flood detection failed: {e}")

    def _check_dns_threats(self, report: WorkflowReport):
        """Check for DNS-related threats."""
        try:
            # DNS tunneling
            tunneling = self.analysis.dns.detect_dns_tunneling(length_threshold=100)
            if len(tunneling) > 0:
                report.add_finding(
                    "high",
                    "DNS Tunneling",
                    f"Detected {len(tunneling)} potential DNS tunneling queries",
                    f"Longest query length: {tunneling['query_length'].max() if len(tunneling) > 0 else 'N/A'}",
                )

            # DGA domains
            dga = self.analysis.dns.identify_dga_domains()
            if len(dga) > 0:
                report.add_finding(
                    "high",
                    "DGA Domains",
                    f"Detected {len(dga)} potential DGA-generated domains",
                )

            # DNS amplification
            amplification = self.analysis.dns.detect_dns_amplification()
            if len(amplification) > 0:
                report.add_finding(
                    "medium",
                    "DNS Amplification",
                    f"Detected {len(amplification)} potential DNS amplification attempts",
                )
        except Exception as e:
            self.logger.warning(f"DNS threat detection failed: {e}")

    def _check_arp_threats(self, report: WorkflowReport):
        """Check for ARP-related threats."""
        try:
            # ARP spoofing
            spoofing = self.analysis.arp.detect_arp_spoofing()
            if len(spoofing) > 0:
                report.add_finding(
                    "critical",
                    "ARP Spoofing",
                    f"Detected {len(spoofing)} potential ARP spoofing attempts",
                    f"Conflicting IP-MAC pairs: {len(spoofing)}",
                )

            # ARP scanning
            scanning = self.analysis.arp.detect_arp_scanning()
            if len(scanning) > 0:
                report.add_finding(
                    "medium",
                    "ARP Scanning",
                    f"Detected {len(scanning)} hosts performing ARP scanning",
                )
        except Exception as e:
            self.logger.warning(f"ARP threat detection failed: {e}")

    def _check_icmp_threats(self, report: WorkflowReport):
        """Check for ICMP-related threats."""
        try:
            # ICMP flood
            flood = self.analysis.icmp.detect_icmp_flood(threshold=100)
            if len(flood) > 0:
                report.add_finding(
                    "medium",
                    "ICMP Flood",
                    f"Detected {len(flood)} potential ICMP flood sources",
                )

            # ICMP tunneling
            tunneling = self.analysis.icmp.detect_icmp_tunneling()
            if len(tunneling) > 0:
                report.add_finding(
                    "high",
                    "ICMP Tunneling",
                    f"Detected {len(tunneling)} potential ICMP tunneling packets",
                )
        except Exception as e:
            self.logger.warning(f"ICMP threat detection failed: {e}")

    def _check_top_talkers(self, report: WorkflowReport):
        """Identify top bandwidth consumers."""
        try:
            top_ips = self.analysis.ip.get_most_active_ips(n=5, by="bytes")
            if len(top_ips) > 0:
                report.add_section(
                    "Top 5 Bandwidth Consumers",
                    top_ips.to_pandas() if hasattr(top_ips, "to_pandas") else top_ips,
                )
        except Exception as e:
            self.logger.warning(f"Top talkers analysis failed: {e}")

    def _check_failed_connections(self, report: WorkflowReport):
        """Check for excessive failed connections."""
        try:
            incomplete = self.analysis.tcp.detect_incomplete_connections()
            if len(incomplete) > 100:  # Threshold for concern
                report.add_finding(
                    "medium",
                    "Failed Connections",
                    f"High number of incomplete TCP connections: {len(incomplete)}",
                    "May indicate connection timeouts or scanning",
                )
        except Exception as e:
            self.logger.warning(f"Failed connection check failed: {e}")

    def _check_suspicious_ips(self, report: WorkflowReport):
        """Identify suspicious IP behavior."""
        try:
            # Hub IPs (communicating with many others)
            hubs = self.analysis.ip.detect_hub_ips(threshold=50)
            if len(hubs) > 0:
                report.add_finding(
                    "medium",
                    "Hub IPs",
                    f"Detected {len(hubs)} IPs communicating with >50 unique hosts",
                    "May indicate scanning or botnet activity",
                )

            # Asymmetric traffic
            asymmetric = self.analysis.ip.get_asymmetric_ips(threshold=0.9)
            if len(asymmetric) > 0:
                report.add_finding(
                    "low",
                    "Asymmetric Traffic",
                    f"Detected {len(asymmetric)} IPs with >90% traffic imbalance",
                    "One-way communication patterns",
                )
        except Exception as e:
            self.logger.warning(f"Suspicious IP check failed: {e}")

    def _check_data_exfiltration(self, report: WorkflowReport):
        """Detect potential data exfiltration."""
        try:
            exfiltration = self.analysis.anomaly.detect_data_exfiltration(
                threshold=100_000_000  # 100MB
            )
            if len(exfiltration) > 0:
                report.add_finding(
                    "critical",
                    "Data Exfiltration",
                    f"Detected {len(exfiltration)} IPs with >100MB outbound transfer",
                    "Potential data exfiltration or backup activity",
                )
        except Exception as e:
            self.logger.warning(f"Data exfiltration check failed: {e}")

    def _check_off_hours_activity(self, report: WorkflowReport):
        """Detect activity outside business hours."""
        try:
            off_hours = self.analysis.anomaly.detect_off_hours_activity(
                business_hours=self.business_hours
            )
            if len(off_hours) > 0:
                report.add_finding(
                    "low",
                    "Off-Hours Activity",
                    f"Detected {len(off_hours)} packets outside business hours",
                    f"Business hours: {self.business_hours[0]}-{self.business_hours[1]}",
                )
        except Exception as e:
            self.logger.warning(f"Off-hours activity check failed: {e}")

    def _check_beaconing(self, report: WorkflowReport):
        """Detect beaconing behavior (C2 communication)."""
        try:
            self.analysis.flow.create_flows()
            beacons = self.analysis.flow.detect_beacon_behavior(tolerance=0.1)
            if len(beacons) > 0:
                report.add_finding(
                    "high",
                    "Beaconing Detected",
                    f"Detected {len(beacons)} flows with periodic communication patterns",
                    "May indicate C2 (Command & Control) communication",
                )
        except Exception as e:
            self.logger.warning(f"Beaconing detection failed: {e}")

    def _check_scanning_patterns(self, report: WorkflowReport):
        """Detect various scanning patterns."""
        try:
            # Vertical scanning (same port, multiple hosts)
            vertical = self.analysis.anomaly.detect_vertical_scanning()
            if len(vertical) > 0:
                report.add_finding(
                    "medium",
                    "Vertical Scan",
                    f"Detected {len(vertical)} vertical scanning patterns",
                )

            # Horizontal scanning (multiple ports, same host)
            horizontal = self.analysis.anomaly.detect_horizontal_scanning()
            if len(horizontal) > 0:
                report.add_finding(
                    "medium",
                    "Horizontal Scan",
                    f"Detected {len(horizontal)} horizontal scanning patterns",
                )
        except Exception as e:
            self.logger.warning(f"Scanning pattern detection failed: {e}")


class IPInvestigation:
    """
    Deep dive investigation into a specific IP address.

    Provides comprehensive analysis of all activity related to an IP including:
    - Timeline of activity
    - All connections
    - Protocol breakdown
    - Threat indicators
    - Behavioral patterns

    Example:
        inv = IPInvestigation("capture.parquet", ip="192.168.1.100")
        report = inv.run()
        print(report.summary())
    """

    def __init__(self, parquet_file: str, ip: str, lazy_load: bool = False):
        """
        Initialize IP investigation.

        Args:
            parquet_file: Path to parquet file to analyze
            ip: IP address to investigate
            lazy_load: Use lazy loading for analyzers
        """
        self.parquet_file = parquet_file
        self.ip = ip
        self.logger = get_logger()

        self.logger.info(f"Initializing IPInvestigation for {ip}")
        self.analysis = NetworkParquetAnalysis(parquet_file, lazy_load=lazy_load)

    def run(self) -> WorkflowReport:
        """
        Run complete IP investigation.

        Returns:
            WorkflowReport with all findings
        """
        self.logger.info(f"Starting investigation of IP: {self.ip}")
        report = WorkflowReport(f"IP Investigation Report: {self.ip}")

        # Basic info
        self._get_basic_info(report)

        # Traffic analysis
        self._analyze_traffic_stats(report)
        self._analyze_protocol_breakdown(report)
        self._analyze_connections(report)

        # Threat indicators
        self._check_scanning_behavior(report)
        self._check_attack_patterns(report)
        self._check_dns_activity(report)

        self.logger.info(f"IP investigation complete: {len(report.findings)} findings")
        return report

    def _get_basic_info(self, report: WorkflowReport):
        """Get basic information about the IP."""
        try:
            ip_traffic = self.analysis.find_ip_information(self.ip)
            total_packets = len(ip_traffic)

            report.add_section(
                "Basic Information",
                {
                    "IP Address": self.ip,
                    "Total Packets": f"{total_packets:,}",
                    "First Seen": (
                        ip_traffic["timestamp"].min() if total_packets > 0 else "N/A"
                    ),
                    "Last Seen": (
                        ip_traffic["timestamp"].max() if total_packets > 0 else "N/A"
                    ),
                },
            )
        except Exception as e:
            self.logger.error(f"Failed to get basic info: {e}")

    def _analyze_traffic_stats(self, report: WorkflowReport):
        """Analyze traffic statistics for the IP."""
        try:
            stats = self.analysis.ip.get_ip_traffic_stats(self.ip)
            report.add_section("Traffic Statistics", stats)
        except Exception as e:
            self.logger.warning(f"Traffic stats analysis failed: {e}")

    def _analyze_protocol_breakdown(self, report: WorkflowReport):
        """Analyze protocol usage for the IP."""
        try:
            # This would need to be implemented in parquet_analysis
            ip_traffic = self.analysis.find_ip_information(self.ip)
            if "protocol" in ip_traffic.columns:
                protocol_counts = ip_traffic.group_by("protocol").count()
                report.add_section("Protocol Breakdown", protocol_counts)
        except Exception as e:
            self.logger.warning(f"Protocol breakdown failed: {e}")

    def _analyze_connections(self, report: WorkflowReport):
        """Analyze all connections involving this IP."""
        try:
            ip_traffic = self.analysis.find_ip_information(self.ip)

            # Count unique remote IPs
            if (
                "source_ip" in ip_traffic.columns
                and "destination_ip" in ip_traffic.columns
            ):
                remote_ips = set()
                for row in ip_traffic.iter_rows():
                    if row[0] == self.ip:  # source_ip
                        remote_ips.add(row[1])  # destination_ip
                    else:
                        remote_ips.add(row[0])

                report.add_finding(
                    "info",
                    "Connections",
                    f"IP communicated with {len(remote_ips)} unique hosts",
                )
        except Exception as e:
            self.logger.warning(f"Connection analysis failed: {e}")

    def _check_scanning_behavior(self, report: WorkflowReport):
        """Check if this IP is performing scanning."""
        try:
            # Check if IP appears in port scan detection
            port_scans = self.analysis.anomaly.detect_port_scanning(
                threshold=50, time_window="1m"
            )

            if self.ip in str(port_scans):  # Simple check
                report.add_finding(
                    "high", "Port Scanning", f"IP {self.ip} is performing port scanning"
                )
        except Exception as e:
            self.logger.warning(f"Scanning behavior check failed: {e}")

    def _check_attack_patterns(self, report: WorkflowReport):
        """Check for attack patterns from this IP."""
        try:
            # Check SYN flood
            syn_floods = self.analysis.anomaly.detect_syn_flood(
                threshold=500, time_window="1m"
            )
            if self.ip in str(syn_floods):
                report.add_finding(
                    "critical",
                    "SYN Flood",
                    f"IP {self.ip} is source of SYN flood attack",
                )

            # Check UDP flood
            udp_floods = self.analysis.anomaly.detect_udp_flood(
                threshold=300, time_window="1m"
            )
            if self.ip in str(udp_floods):
                report.add_finding(
                    "high", "UDP Flood", f"IP {self.ip} is source of UDP flood attack"
                )
        except Exception as e:
            self.logger.warning(f"Attack pattern check failed: {e}")

    def _check_dns_activity(self, report: WorkflowReport):
        """Analyze DNS activity for this IP."""
        try:
            # Check if IP is a top querier
            top_queriers = self.analysis.dns.get_top_querying_ips(n=20)
            if self.ip in str(top_queriers):
                report.add_finding(
                    "info", "DNS Activity", f"IP {self.ip} is among top 20 DNS queriers"
                )
        except Exception as e:
            self.logger.warning(f"DNS activity check failed: {e}")


class ThreatHunting:
    """
    Proactive threat hunting workflow.

    Searches for specific attack patterns and indicators of compromise (IOCs).

    Example:
        hunter = ThreatHunting("capture.parquet")
        report = hunter.hunt_for_c2()
        print(report.summary())
    """

    def __init__(self, parquet_file: str, lazy_load: bool = False):
        """Initialize threat hunting."""
        self.parquet_file = parquet_file
        self.logger = get_logger()
        self.analysis = NetworkParquetAnalysis(parquet_file, lazy_load=lazy_load)

    def hunt_for_c2(self) -> WorkflowReport:
        """Hunt for Command & Control (C2) communication patterns."""
        report = WorkflowReport("C2 Threat Hunting Report")

        # Beaconing detection
        try:
            self.analysis.flow.create_flows()
            beacons = self.analysis.flow.detect_beacon_behavior(tolerance=0.1)
            if len(beacons) > 0:
                report.add_finding(
                    "high",
                    "Beaconing",
                    f"Detected {len(beacons)} potential C2 beaconing patterns",
                    beacons,
                )
        except Exception as e:
            self.logger.error(f"Beaconing detection failed: {e}")

        # Long-lived connections
        try:
            long_lived = self.analysis.tcp.identify_long_lived_connections(
                threshold="30m"
            )
            if len(long_lived) > 0:
                report.add_finding(
                    "medium",
                    "Long-lived Connections",
                    f"Detected {len(long_lived)} connections lasting >30 minutes",
                )
        except Exception as e:
            self.logger.error(f"Long-lived connection detection failed: {e}")

        # DNS tunneling
        try:
            tunneling = self.analysis.dns.detect_dns_tunneling(length_threshold=80)
            if len(tunneling) > 0:
                report.add_finding(
                    "high",
                    "DNS Tunneling",
                    f"Detected {len(tunneling)} potential DNS tunneling queries",
                )
        except Exception as e:
            self.logger.error(f"DNS tunneling detection failed: {e}")

        return report

    def hunt_for_data_theft(self) -> WorkflowReport:
        """Hunt for data exfiltration patterns."""
        report = WorkflowReport("Data Theft Threat Hunting Report")

        # Large outbound transfers
        try:
            exfil = self.analysis.anomaly.detect_data_exfiltration(threshold=50_000_000)
            if len(exfil) > 0:
                report.add_finding(
                    "critical",
                    "Large Outbound Transfer",
                    f"Detected {len(exfil)} IPs with >50MB outbound",
                )
        except Exception as e:
            self.logger.error(f"Data exfiltration detection failed: {e}")

        # DNS tunneling (can be used for data exfil)
        try:
            tunneling = self.analysis.dns.detect_dns_tunneling(length_threshold=100)
            if len(tunneling) > 0:
                report.add_finding(
                    "high",
                    "DNS Tunneling",
                    f"Detected {len(tunneling)} potential DNS tunneling queries",
                )
        except Exception as e:
            self.logger.error(f"DNS tunneling detection failed: {e}")

        # ICMP tunneling
        try:
            icmp_tunnel = self.analysis.icmp.detect_icmp_tunneling()
            if len(icmp_tunnel) > 0:
                report.add_finding(
                    "high",
                    "ICMP Tunneling",
                    f"Detected {len(icmp_tunnel)} potential ICMP tunneling packets",
                )
        except Exception as e:
            self.logger.error(f"ICMP tunneling detection failed: {e}")

        return report

    def hunt_for_lateral_movement(self) -> WorkflowReport:
        """Hunt for lateral movement within the network."""
        report = WorkflowReport("Lateral Movement Threat Hunting Report")

        # Hub IPs (talking to many internal hosts)
        try:
            hubs = self.analysis.ip.detect_hub_ips(threshold=30)
            if len(hubs) > 0:
                report.add_finding(
                    "medium",
                    "Hub IPs",
                    f"Detected {len(hubs)} IPs communicating with >30 hosts",
                )
        except Exception as e:
            self.logger.error(f"Hub detection failed: {e}")

        # Port scanning within network
        try:
            port_scans = self.analysis.anomaly.detect_port_scanning(
                threshold=20, time_window="5m"
            )
            if len(port_scans) > 0:
                report.add_finding(
                    "high",
                    "Internal Port Scanning",
                    f"Detected {len(port_scans)} sources performing port scans",
                )
        except Exception as e:
            self.logger.error(f"Port scan detection failed: {e}")

        return report
