#!/usr/bin/env python3
"""
Example: Daily Security Audit

This script demonstrates how to run a comprehensive daily security audit
on captured network traffic.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from network_security_suite.ml.preprocessing.workflows import DailyAudit
from datetime import time


def main():
    # Path to your parquet file
    parquet_file = "capture.parquet"

    # Check if file exists
    if not Path(parquet_file).exists():
        print(f"Error: File not found: {parquet_file}")
        print("Please provide a valid parquet file path")
        return 1

    # Define business hours (9 AM to 5 PM)
    business_hours = (time(9, 0), time(17, 0))

    # Create audit instance
    print(f"Initializing daily audit for: {parquet_file}")
    audit = DailyAudit(
        parquet_file,
        business_hours=business_hours,
        lazy_load=True  # Use lazy loading for better memory efficiency
    )

    # Run the audit
    print("Running comprehensive security audit...")
    print("This may take a few minutes for large files...")
    report = audit.run()

    # Display summary
    print("\n" + "=" * 80)
    print("AUDIT COMPLETE")
    print("=" * 80)
    print(report.summary())

    # Export to JSON
    output_file = "daily_audit_report.json"
    report.to_json(output_file)
    print(f"\nFull report saved to: {output_file}")

    # Return exit code based on severity
    if report.severity_counts["critical"] > 0:
        return 2  # Critical findings
    elif report.severity_counts["high"] > 0:
        return 1  # High severity findings
    else:
        return 0  # No major issues


if __name__ == "__main__":
    sys.exit(main())
