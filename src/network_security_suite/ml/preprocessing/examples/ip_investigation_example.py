#!/usr/bin/env python3
"""
Example: IP Address Investigation

This script demonstrates how to perform a deep-dive investigation
into a specific IP address.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from network_security_suite.ml.preprocessing.workflows import IPInvestigation


def main():
    # Configuration
    parquet_file = "capture.parquet"
    target_ip = "192.168.1.100"  # Change to your target IP

    # Check if file exists
    if not Path(parquet_file).exists():
        print(f"Error: File not found: {parquet_file}")
        return 1

    # Allow IP to be passed as command line argument
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]

    if len(sys.argv) > 2:
        parquet_file = sys.argv[2]

    # Create investigation instance
    print(f"Investigating IP: {target_ip}")
    print(f"Data source: {parquet_file}")
    print()

    investigation = IPInvestigation(parquet_file, ip=target_ip, lazy_load=True)

    # Run investigation
    print("Analyzing all activity related to this IP...")
    report = investigation.run()

    # Display results
    print(report.summary())

    # Export report
    output_file = f"ip_investigation_{target_ip.replace('.', '_')}.json"
    report.to_json(output_file)
    print(f"\nDetailed report saved to: {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
