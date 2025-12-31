"""Network traffic analysis workflows."""

from netguard.analysis.facade import ParquetAnalysisFacade
from netguard.workflows.workflows import (
    DailyAudit,
    IPInvestigation,
    ThreatHunting,
    WorkflowReport,
)

# Backwards compatibility alias
NetworkParquetAnalysis = ParquetAnalysisFacade

__all__ = [
    "DailyAudit",
    "IPInvestigation",
    "NetworkParquetAnalysis",  # Alias for backwards compatibility
    "ParquetAnalysisFacade",
    "ThreatHunting",
    "WorkflowReport",
]
