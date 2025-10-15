#!/usr/bin/env python3
"""
Example: Threat Hunting

This script demonstrates how to proactively hunt for specific threats
in network traffic.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from network_security_suite.ml.preprocessing.workflows import ThreatHunting


def main():
    # Configuration
    parquet_file = "capture.parquet"

    # Check if file exists
    if not Path(parquet_file).exists():
        print(f"Error: File not found: {parquet_file}")
        return 1

    # Allow file to be passed as command line argument
    if len(sys.argv) > 1:
        parquet_file = sys.argv[1]

    # Create threat hunter
    print(f"Initializing threat hunting on: {parquet_file}")
    hunter = ThreatHunting(parquet_file, lazy_load=True)

    # Hunt for C2 communication
    print("\n" + "=" * 80)
    print("HUNTING FOR C2 COMMUNICATION")
    print("=" * 80)
    c2_report = hunter.hunt_for_c2()
    print(c2_report.summary())
    c2_report.to_json("threat_hunt_c2.json")

    # Hunt for data theft
    print("\n" + "=" * 80)
    print("HUNTING FOR DATA EXFILTRATION")
    print("=" * 80)
    data_theft_report = hunter.hunt_for_data_theft()
    print(data_theft_report.summary())
    data_theft_report.to_json("threat_hunt_data_theft.json")

    # Hunt for lateral movement
    print("\n" + "=" * 80)
    print("HUNTING FOR LATERAL MOVEMENT")
    print("=" * 80)
    lateral_report = hunter.hunt_for_lateral_movement()
    print(lateral_report.summary())
    lateral_report.to_json("threat_hunt_lateral.json")

    # Summary
    total_findings = (
        len(c2_report.findings) +
        len(data_theft_report.findings) +
        len(lateral_report.findings)
    )

    print("\n" + "=" * 80)
    print("THREAT HUNTING SUMMARY")
    print("=" * 80)
    print(f"C2 Findings:              {len(c2_report.findings)}")
    print(f"Data Theft Findings:      {len(data_theft_report.findings)}")
    print(f"Lateral Movement Findings: {len(lateral_report.findings)}")
    print(f"Total Findings:           {total_findings}")
    print("\nReports saved to:")
    print("  - threat_hunt_c2.json")
    print("  - threat_hunt_data_theft.json")
    print("  - threat_hunt_lateral.json")

    return 0


if __name__ == "__main__":
    sys.exit(main())
