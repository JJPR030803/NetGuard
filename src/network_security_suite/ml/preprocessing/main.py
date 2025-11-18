#!/usr/bin/env python3
"""
Main CLI entry point for network parquet analysis.

This module provides a command-line interface for analyzing network traffic
parquet files using the NetworkParquetAnalysis framework.
"""

import argparse
import json
import logging
import sys
from datetime import time
from pathlib import Path

from .errors import ParquetAnalysisError
from .logger import get_logger, set_log_level
from .parquet_analysis import NetworkParquetAnalysis
from .workflows import DailyAudit, IPInvestigation, ThreatHunting


def setup_argparser() -> argparse.ArgumentParser:
    """
    Set up command-line argument parser.

    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="Network Traffic Parquet Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run daily security audit
  %(prog)s daily-audit capture.parquet

  # Investigate specific IP
  %(prog)s investigate-ip capture.parquet 192.168.1.100

  # Hunt for C2 communication
  %(prog)s threat-hunt capture.parquet --type c2

  # Generate summary report
  %(prog)s analyze capture.parquet --summary

  # Analyze TCP traffic
  %(prog)s analyze capture.parquet --tcp --top-ports 10

  # Detect anomalies
  %(prog)s analyze capture.parquet --anomalies --port-scan
        """,
    )

    # Global options
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose debug logging"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress all output except errors"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a parquet file")
    analyze_parser.add_argument("file", type=str, help="Path to parquet file")
    analyze_parser.add_argument(
        "--summary", action="store_true", help="Generate and display network summary"
    )
    analyze_parser.add_argument(
        "--export",
        type=str,
        metavar="FILE",
        help="Export summary to file (format auto-detected from extension)",
    )
    analyze_parser.add_argument(
        "--format",
        type=str,
        choices=["json", "csv", "parquet"],
        default="json",
        help="Export format (default: json)",
    )
    analyze_parser.add_argument(
        "--lazy", action="store_true", help="Use lazy loading for analyzers"
    )

    # Protocol-specific analysis
    analyze_parser.add_argument(
        "--tcp", action="store_true", help="Analyze TCP traffic"
    )
    analyze_parser.add_argument(
        "--udp", action="store_true", help="Analyze UDP traffic"
    )
    analyze_parser.add_argument(
        "--dns", action="store_true", help="Analyze DNS traffic"
    )
    analyze_parser.add_argument(
        "--top-ports",
        type=int,
        metavar="N",
        help="Show top N ports (requires --tcp or --udp)",
    )

    # Anomaly detection
    analyze_parser.add_argument(
        "--anomalies", action="store_true", help="Run anomaly detection"
    )
    analyze_parser.add_argument(
        "--port-scan",
        action="store_true",
        help="Detect port scanning (requires --anomalies)",
    )
    analyze_parser.add_argument(
        "--syn-flood",
        action="store_true",
        help="Detect SYN flood attacks (requires --anomalies)",
    )

    # IP analysis
    analyze_parser.add_argument(
        "--ip", type=str, metavar="IP_ADDRESS", help="Analyze specific IP address"
    )
    analyze_parser.add_argument(
        "--top-ips", type=int, metavar="N", help="Show top N most active IPs"
    )

    # Info command
    info_parser = subparsers.add_parser("info", help="Display basic file information")
    info_parser.add_argument("file", type=str, help="Path to parquet file")

    # Schema command
    schema_parser = subparsers.add_parser("schema", help="Display parquet file schema")
    schema_parser.add_argument("file", type=str, help="Path to parquet file")

    # Daily Audit workflow
    audit_parser = subparsers.add_parser(
        "daily-audit", help="Run automated daily security audit"
    )
    audit_parser.add_argument("file", type=str, help="Path to parquet file")
    audit_parser.add_argument(
        "--business-hours",
        type=str,
        default="9-17",
        help="Business hours for off-hours detection (format: START-END, e.g., 9-17)",
    )
    audit_parser.add_argument(
        "--export", type=str, metavar="FILE", help="Export report to JSON file"
    )
    audit_parser.add_argument(
        "--lazy", action="store_true", help="Use lazy loading for analyzers"
    )

    # IP Investigation workflow
    investigate_parser = subparsers.add_parser(
        "investigate-ip", help="Investigate specific IP address"
    )
    investigate_parser.add_argument("file", type=str, help="Path to parquet file")
    investigate_parser.add_argument("ip", type=str, help="IP address to investigate")
    investigate_parser.add_argument(
        "--export", type=str, metavar="FILE", help="Export report to JSON file"
    )
    investigate_parser.add_argument(
        "--lazy", action="store_true", help="Use lazy loading for analyzers"
    )

    # Threat Hunting workflow
    threat_parser = subparsers.add_parser(
        "threat-hunt", help="Proactive threat hunting"
    )
    threat_parser.add_argument("file", type=str, help="Path to parquet file")
    threat_parser.add_argument(
        "--type",
        type=str,
        choices=["c2", "data-theft", "lateral", "all"],
        default="all",
        help="Type of threat to hunt for (default: all)",
    )
    threat_parser.add_argument(
        "--export", type=str, metavar="FILE", help="Export report to JSON file"
    )
    threat_parser.add_argument(
        "--lazy", action="store_true", help="Use lazy loading for analyzers"
    )

    return parser


def command_info(args, analysis: NetworkParquetAnalysis):
    """Execute info command."""
    print(f"\n{'=' * 60}")
    print(f"File: {args.file}")
    print(f"{'=' * 60}")
    print(f"Total packets: {analysis.get_packet_count():,}")

    date_range = analysis.get_date_range()
    if date_range["start"]:
        print(f"Start time:    {date_range['start']}")
        print(f"End time:      {date_range['end']}")
        if date_range["duration"]:
            from .utils import format_duration

            print(f"Duration:      {format_duration(date_range['duration'])}")

    print(f"DataFrame size: {analysis.df.estimated_size('mb'):.2f} MB")
    print(f"{'=' * 60}\n")


def command_schema(args, analysis: NetworkParquetAnalysis):
    """Execute schema command."""
    schema = analysis.get_schema()
    print(f"\n{'=' * 60}")
    print(f"Schema for: {args.file}")
    print(f"{'=' * 60}")
    print(f"{'Column':<40} {'Type':<20}")
    print("-" * 60)
    for col, dtype in schema.items():
        print(f"{col:<40} {dtype:<20}")
    print(f"{'=' * 60}")
    print(f"Total columns: {len(schema)}")
    print()


def command_analyze(args, analysis: NetworkParquetAnalysis):
    """Execute analyze command."""
    logger = get_logger()

    # Summary
    if args.summary:
        summary = analysis.generate_network_summary()
        print("\n" + "=" * 60)
        print("NETWORK TRAFFIC SUMMARY")
        print("=" * 60)
        print(json.dumps(summary, indent=2, default=str))
        print()

    # Export
    if args.export:
        # Auto-detect format from extension if not specified
        fmt = args.format
        ext = Path(args.export).suffix.lstrip(".")
        if ext in ["json", "csv", "parquet"]:
            fmt = ext

        analysis.export_summary_report(format=fmt, output=args.export)
        print(f"Summary exported to: {args.export}")

    # TCP analysis
    if args.tcp:
        try:
            tcp = analysis.tcp
            print("\n" + "=" * 60)
            print("TCP ANALYSIS")
            print("=" * 60)
            print(f"Total TCP packets: {len(tcp.df):,}")

            if args.top_ports:
                top_ports = tcp.get_most_used_ports(n=args.top_ports)
                print(f"\nTop {args.top_ports} TCP ports:")
                print(top_ports)

        except Exception as e:
            logger.error(f"TCP analysis failed: {e}")

    # UDP analysis
    if args.udp:
        try:
            udp = analysis.udp
            print("\n" + "=" * 60)
            print("UDP ANALYSIS")
            print("=" * 60)
            print(f"Total UDP packets: {len(udp.df):,}")

            if args.top_ports:
                top_ports = udp.get_most_used_ports(n=args.top_ports)
                print(f"\nTop {args.top_ports} UDP ports:")
                print(top_ports)

        except Exception as e:
            logger.error(f"UDP analysis failed: {e}")

    # DNS analysis
    if args.dns:
        try:
            dns = analysis.dns
            print("\n" + "=" * 60)
            print("DNS ANALYSIS")
            print("=" * 60)
            print(f"Total DNS packets: {len(dns.df):,}")

            top_queries = dns.get_top_queries(n=10)
            print("\nTop 10 DNS queries:")
            print(top_queries)

        except Exception as e:
            logger.error(f"DNS analysis failed: {e}")

    # IP analysis
    if args.ip:
        ip_info = analysis.find_ip_information(args.ip)
        print("\n" + "=" * 60)
        print(f"IP ANALYSIS: {args.ip}")
        print("=" * 60)
        print(f"Total packets: {len(ip_info):,}")
        print("\nPacket details:")
        print(ip_info)

    if args.top_ips:
        try:
            ip_analyzer = analysis.ip
            top_ips = ip_analyzer.get_most_active_ips(n=args.top_ips, by="packets")
            print("\n" + "=" * 60)
            print(f"TOP {args.top_ips} MOST ACTIVE IPs")
            print("=" * 60)
            print(top_ips)

        except Exception as e:
            logger.error(f"IP analysis failed: {e}")

    # Anomaly detection
    if args.anomalies:
        try:
            anomaly = analysis.anomaly
            print("\n" + "=" * 60)
            print("ANOMALY DETECTION")
            print("=" * 60)

            if args.port_scan:
                port_scans = anomaly.detect_port_scanning(
                    threshold=100, time_window="1m"
                )
                print("\nPort scan detection:")
                print(port_scans)

            if args.syn_flood:
                syn_floods = anomaly.detect_syn_flood(threshold=1000, time_window="1m")
                print("\nSYN flood detection:")
                print(syn_floods)

        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")


def command_daily_audit(args):
    """Execute daily audit workflow."""
    logger = get_logger()

    # Parse business hours
    try:
        hours = args.business_hours.split("-")
        start_hour = int(hours[0])
        end_hour = int(hours[1])
        business_hours = (time(start_hour, 0), time(end_hour, 0))
    except (ValueError, IndexError):
        logger.error(f"Invalid business hours format: {args.business_hours}")
        logger.error("Use format: START-END (e.g., 9-17 for 9 AM to 5 PM)")
        return 1

    # Run audit
    logger.info("Starting daily security audit...")
    audit = DailyAudit(args.file, business_hours=business_hours, lazy_load=args.lazy)
    report = audit.run()

    # Display report
    print(report.summary())

    # Export if requested
    if args.export:
        report.to_json(args.export)
        logger.info(f"Report exported to: {args.export}")

    # Return exit code based on severity
    if report.severity_counts["critical"] > 0:
        return 2
    elif report.severity_counts["high"] > 0:
        return 1
    return 0


def command_investigate_ip(args):
    """Execute IP investigation workflow."""
    logger = get_logger()

    logger.info(f"Investigating IP: {args.ip}")
    investigation = IPInvestigation(args.file, ip=args.ip, lazy_load=args.lazy)
    report = investigation.run()

    # Display report
    print(report.summary())

    # Export if requested
    if args.export:
        report.to_json(args.export)
        logger.info(f"Report exported to: {args.export}")
    else:
        # Auto-export with IP-based filename
        filename = f"ip_investigation_{args.ip.replace('.', '_')}.json"
        report.to_json(filename)
        logger.info(f"Report exported to: {filename}")

    return 0


def command_threat_hunt(args):
    """Execute threat hunting workflow."""
    logger = get_logger()

    hunter = ThreatHunting(args.file, lazy_load=args.lazy)

    # Determine which hunts to run
    hunt_types = ["c2", "data-theft", "lateral"] if args.type == "all" else [args.type]

    reports = {}

    # Run selected hunts
    for hunt_type in hunt_types:
        logger.info(f"Running {hunt_type} threat hunt...")

        if hunt_type == "c2":
            reports["c2"] = hunter.hunt_for_c2()
        elif hunt_type == "data-theft":
            reports["data-theft"] = hunter.hunt_for_data_theft()
        elif hunt_type == "lateral":
            reports["lateral"] = hunter.hunt_for_lateral_movement()

    # Display reports
    for hunt_type, report in reports.items():
        print("\n" + "=" * 80)
        print(f"THREAT HUNT: {hunt_type.upper()}")
        print("=" * 80)
        print(report.summary())

        # Export individual reports
        if args.export:
            # If single hunt, use the specified filename
            if len(reports) == 1:
                filename = args.export
            else:
                # For multiple hunts, append hunt type to filename
                base = Path(args.export).stem
                ext = Path(args.export).suffix or ".json"
                filename = f"{base}_{hunt_type}{ext}"

            report.to_json(filename)
            logger.info(f"{hunt_type} report exported to: {filename}")

    # Summary
    total_findings = sum(len(r.findings) for r in reports.values())
    print("\n" + "=" * 80)
    print("THREAT HUNTING SUMMARY")
    print("=" * 80)
    for hunt_type, report in reports.items():
        print(f"{hunt_type.upper():20} {len(report.findings)} findings")
    print(f"{'TOTAL':20} {total_findings} findings")

    return 0


def main():
    """Main entry point for CLI."""
    parser = setup_argparser()
    args = parser.parse_args()

    # Handle no command
    if not args.command:
        parser.print_help()
        return 0

    # Configure logging
    logger = get_logger()
    if args.verbose:
        set_log_level(logging.DEBUG)
    elif args.quiet:
        set_log_level(logging.ERROR)

    try:
        # Handle workflow commands separately (they manage their own analysis instances)
        if args.command == "daily-audit":
            return command_daily_audit(args)
        elif args.command == "investigate-ip":
            return command_investigate_ip(args)
        elif args.command == "threat-hunt":
            return command_threat_hunt(args)

        # For other commands, load parquet file and create analysis instance
        file_path = args.file
        if not Path(file_path).exists():
            logger.error(f"File not found: {file_path}")
            return 1

        # Create analysis instance
        lazy = args.lazy if hasattr(args, "lazy") else False
        analysis = NetworkParquetAnalysis(file_path, lazy_load=lazy)

        # Execute command
        if args.command == "info":
            command_info(args, analysis)
        elif args.command == "schema":
            command_schema(args, analysis)
        elif args.command == "analyze":
            command_analyze(args, analysis)

        return 0

    except ParquetAnalysisError as e:
        logger.error(f"Analysis error: {e}")
        return 1
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        return 130
    except Exception as e:
        logger.error(
            f"Unexpected error: {e}",
            exc_info=args.verbose if hasattr(args, "verbose") else False,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
