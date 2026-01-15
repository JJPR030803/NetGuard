"""Tests for preprocessing workflows."""

import json
import unittest
from datetime import datetime, time
from unittest.mock import Mock, patch

import polars as pl

from netguard.workflows import (
    DailyAudit,
    IPInvestigation,
    ThreatHunting,
    WorkflowReport,
)


class TestWorkflowReport:
    """Test WorkflowReport class."""

    def test_report_creation(self):
        """Test creating a workflow report."""
        report = WorkflowReport("Test Report")
        assert report.title == "Test Report"
        assert isinstance(report.timestamp, datetime)
        assert report.sections == {}
        assert report.findings == []
        assert report.severity_counts == {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

    def test_add_section(self):
        """Test adding a section to report."""
        report = WorkflowReport("Test Report")
        report.add_section("Statistics", {"packets": 1000})
        assert "Statistics" in report.sections
        assert report.sections["Statistics"] == {"packets": 1000}

    def test_add_finding(self):
        """Test adding a finding to report."""
        report = WorkflowReport("Test Report")
        report.add_finding("high", "Port Scan", "Detected port scanning", {"count": 10})

        assert len(report.findings) == 1
        finding = report.findings[0]
        assert finding["severity"] == "high"
        assert finding["category"] == "Port Scan"
        assert finding["description"] == "Detected port scanning"
        assert finding["details"] == {"count": 10}
        assert "timestamp" in finding

    def test_severity_counts_increment(self):
        """Test severity counts increment correctly."""
        report = WorkflowReport("Test Report")
        report.add_finding("critical", "Test", "Description 1")
        report.add_finding("critical", "Test", "Description 2")
        report.add_finding("high", "Test", "Description 3")

        assert report.severity_counts["critical"] == 2
        assert report.severity_counts["high"] == 1
        assert report.severity_counts["medium"] == 0

    def test_summary_generation(self):
        """Test summary generation."""
        report = WorkflowReport("Test Report")
        report.add_finding("high", "Test", "Test finding")
        summary = report.summary()

        assert isinstance(summary, str)
        assert "Test Report" in summary
        assert "Test finding" in summary

    def test_summary_with_no_findings(self):
        """Test summary with no findings."""
        report = WorkflowReport("Test Report")
        summary = report.summary()

        assert "No security findings detected" in summary

    def test_summary_with_sections(self):
        """Test summary includes sections."""
        report = WorkflowReport("Test Report")
        report.add_section("Network Stats", {"total": 1000})
        summary = report.summary()

        assert "Network Stats" in summary
        assert "ADDITIONAL INFORMATION" in summary

    def test_to_dict(self):
        """Test converting report to dictionary."""
        report = WorkflowReport("Test Report")
        report.add_finding("info", "Test", "Test finding")
        report.add_section("Stats", {"count": 100})

        result = report.to_dict()

        assert result["title"] == "Test Report"
        assert "timestamp" in result
        assert "severity_counts" in result
        assert "findings" in result
        assert "sections" in result
        assert len(result["findings"]) == 1

    def test_to_json_string(self):
        """Test converting report to JSON string."""
        report = WorkflowReport("Test Report")
        report.add_finding("info", "Test", "Test finding")

        json_str = report.to_json()

        assert isinstance(json_str, str)
        data = json.loads(json_str)
        assert data["title"] == "Test Report"

    def test_to_json_file(self, tmp_path):
        """Test exporting report to JSON file."""
        report = WorkflowReport("Test Report")
        report.add_finding("info", "Test", "Test finding")

        output_file = tmp_path / "report.json"
        result = report.to_json(str(output_file))

        assert result is None  # Returns None when writing to file
        assert output_file.exists()

        with output_file.open() as f:
            data = json.load(f)
        assert data["title"] == "Test Report"


class TestDailyAudit:
    """Test DailyAudit workflow."""

    @patch("netguard.workflows.workflows.ParquetAnalysisFacade")
    def test_daily_audit_initialization(self, mock_analysis):
        """Test DailyAudit initialization."""
        custom_hours: tuple[time, time] = (time(9, 0), time(17, 0))
        audit = DailyAudit("test.parquet", business_hours=custom_hours)

        assert audit.parquet_file == "test.parquet"
        assert audit.business_hours == (time(9, 0), time(17, 0))
        mock_analysis.assert_called_once_with("test.parquet")

    @patch("netguard.workflows.workflows.ParquetAnalysisFacade")
    def test_daily_audit_custom_business_hours(self, _mock_analysis):
        """Test DailyAudit with custom business hours."""
        custom_hours = (time(8, 0), time(18, 0))
        audit = DailyAudit("test.parquet", business_hours=custom_hours)

        assert audit.business_hours == custom_hours

    @patch("netguard.workflows.workflows.ParquetAnalysisFacade")
    def test_daily_audit_run_returns_report(self, mock_analysis):
        """Test that run() returns a WorkflowReport."""
        # Setup mock
        mock_instance = Mock()
        mock_instance.get_packet_count.return_value = 1000
        mock_instance.get_date_range.return_value = {
            "start": "2021-01-01",
            "end": "2021-01-02",
            "duration": 86400,
        }
        mock_analysis.return_value = mock_instance

        audit = DailyAudit("test.parquet")
        report = audit.run()

        assert isinstance(report, WorkflowReport)
        assert "Daily Security Audit Report" in report.title


class TestIPInvestigation:
    """Test IPInvestigation workflow."""

    @patch("netguard.workflows.workflows.ParquetAnalysisFacade")
    def test_ip_investigation_initialization(self, mock_analysis):
        """Test IPInvestigation initialization."""
        inv = IPInvestigation("test.parquet", ip="192.168.1.100")

        assert inv.parquet_file == "test.parquet"
        assert inv.ip == "192.168.1.100"
        mock_analysis.assert_called_once_with("test.parquet")

    @patch("netguard.workflows.workflows.ParquetAnalysisFacade")
    def test_ip_investigation_run_returns_report(self, mock_analysis):
        """Test that run() returns a WorkflowReport."""
        # Setup mock
        mock_instance = Mock()
        mock_df = pl.DataFrame({"timestamp": [], "source_ip": [], "destination_ip": []})
        mock_instance.find_ip_information.return_value = mock_df
        mock_analysis.return_value = mock_instance

        inv = IPInvestigation("test.parquet", ip="192.168.1.100")
        report = inv.run()

        assert isinstance(report, WorkflowReport)
        assert "IP Investigation Report: 192.168.1.100" in report.title


class TestThreatHunting:
    """Test ThreatHunting workflow."""

    @patch("netguard.workflows.workflows.ParquetAnalysisFacade")
    def test_threat_hunting_initialization(self, mock_analysis):
        """Test ThreatHunting initialization."""
        hunter = ThreatHunting("test.parquet")

        assert hunter.parquet_file == "test.parquet"
        mock_analysis.assert_called_once_with("test.parquet")

    @patch("netguard.workflows.workflows.ParquetAnalysisFacade")
    def test_hunt_for_c2_returns_report(self, _mock_analysis):
        """Test hunt_for_c2() returns a WorkflowReport."""
        hunter = ThreatHunting("test.parquet")
        report = hunter.hunt_for_c2()

        assert isinstance(report, WorkflowReport)
        assert "C2 Threat Hunting Report" in report.title

    @patch("netguard.workflows.workflows.ParquetAnalysisFacade")
    def test_hunt_for_data_theft_returns_report(self, _mock_analysis):
        """Test hunt_for_data_theft() returns a WorkflowReport."""
        hunter = ThreatHunting("test.parquet")
        report = hunter.hunt_for_data_theft()

        assert isinstance(report, WorkflowReport)
        assert "Data Theft Threat Hunting Report" in report.title

    @patch("netguard.workflows.workflows.ParquetAnalysisFacade")
    def test_hunt_for_lateral_movement_returns_report(self, _mock_analysis):
        """Test hunt_for_lateral_movement() returns a WorkflowReport."""
        hunter = ThreatHunting("test.parquet")
        report = hunter.hunt_for_lateral_movement()

        assert isinstance(report, WorkflowReport)
        assert "Lateral Movement Threat Hunting Report" in report.title


if __name__ == "__main__":
    unittest.main()
