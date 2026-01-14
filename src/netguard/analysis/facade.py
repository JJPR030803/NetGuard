"""
Facade for comprehensive network traffic analysis.

Provides a single interface to analyze parquet files across all protocols.
This is the main entry point for analyzing network captures.
"""

import contextlib
import json
from pathlib import Path
from typing import Any, ClassVar, Optional

import polars as pl
import polars.selectors as cs

# Import all analyzers
from netguard.analysis.analyzers.anomaly_analyzer import AnomalyAnalyzer
from netguard.analysis.analyzers.arp_analyzer import ArpAnalyzer
from netguard.analysis.analyzers.dns_analyzer import DnsAnalyzer
from netguard.analysis.analyzers.flow_analyzer import FlowAnalyzer
from netguard.analysis.analyzers.icmp_analyzer import IcmpAnalyzer
from netguard.analysis.analyzers.ip_analyzer import IpAnalyzer
from netguard.analysis.analyzers.tcp_analyzer import TcpAnalyzer
from netguard.analysis.analyzers.udp_analyzer import UdpAnalyzer
from netguard.analysis.utils import format_bytes, format_duration
from netguard.core.data_store import DataStore
from netguard.core.errors import FileNotFoundError as ParquetFileNotFoundError
from netguard.core.errors import InvalidFileFormatError
from netguard.core.loggers import get_logger

__all__ = ["ParquetAnalysisFacade"]


class ParquetAnalysisFacade:
    """
    Comprehensive network traffic analysis facade.

    Loads a parquet file and provides access to all protocol-specific
    analyzers through a single interface.

    Example:
        >>> analysis = ParquetAnalysisFacade("capture.parquet")
        >>> tcp_scans = analysis.tcp.detect_port_scanning()
        >>> dns_tunnels = analysis.dns.detect_tunneling()
        >>> report = analysis.generate_summary()

    Attributes:
        path: Path to the parquet file
        df: Loaded DataFrame
        tcp: TCP protocol analyzer (or None if no TCP traffic)
        udp: UDP protocol analyzer (or None if no UDP traffic)
        dns: DNS protocol analyzer (or None if no DNS traffic)
        arp: ARP protocol analyzer (or None if no ARP traffic)
        icmp: ICMP protocol analyzer (or None if no ICMP traffic)
        flow: Network flow analyzer
        ip: IP protocol analyzer
        anomaly: Anomaly detection analyzer
    """

    _tcp: Optional[TcpAnalyzer]
    _udp: Optional[UdpAnalyzer]
    _dns: Optional[DnsAnalyzer]
    _arp: Optional[ArpAnalyzer]
    _icmp: Optional[IcmpAnalyzer]
    _flow: Optional[FlowAnalyzer]
    _ip: Optional[IpAnalyzer]
    _anomaly: Optional[AnomalyAnalyzer]

    PROTOCOLS: ClassVar[set[str]] = {"TCP", "UDP", "IP", "IPv6", "DHCP", "DNS", "ARP", "ICMP"}

    def __init__(self, path: str):
        """
        Initialize facade and load parquet file.

        Args:
            path: Path to parquet file containing packet data

        Raises:
            FileNotFoundError: If file doesn't exist
            InvalidFileFormatError: If file is not valid parquet
        """
        self.path = path
        self.logger = get_logger()

        # Validate file exists
        if not Path(path).exists():
            raise ParquetFileNotFoundError(path)

        # Load DataFrame via DataStore
        try:
            self.logger.info(f"Loading parquet file: {path}")
            self.df = DataStore.load_packets(path)
            self.logger.log_dataframe_info(
                "loaded_parquet",
                shape=self.df.shape,
                memory_mb=self.df.estimated_size("mb"),
            )
        except FileNotFoundError:
            raise
        except Exception as e:
            raise InvalidFileFormatError(path, e) from e

        # Initialize all analyzers eagerly (no lazy loading)
        self.logger.info("Initializing protocol analyzers...")
        self._initialize_analyzers()
        self.logger.info("All analyzers initialized")

    def _initialize_analyzers(self) -> None:
        """Initialize all protocol analyzers."""
        # Initialize each analyzer with the DataFrame
        # Catch exceptions for protocol-specific analyzers that may fail
        # if the required protocol data is not present

        # TCP Analyzer
        try:
            self._tcp = TcpAnalyzer(self.df)
            self.logger.debug(f"TCP analyzer initialized: {len(self._tcp)} packets")
        except Exception as e:
            self._tcp = None
            self.logger.debug(f"TCP analyzer not initialized: {e}")

        # UDP Analyzer
        try:
            self._udp = UdpAnalyzer(self.df)
            self.logger.debug(f"UDP analyzer initialized: {len(self._udp)} packets")
        except Exception as e:
            self._udp = None
            self.logger.debug(f"UDP analyzer not initialized: {e}")

        # DNS Analyzer
        try:
            self._dns = DnsAnalyzer(self.df)
            self.logger.debug(f"DNS analyzer initialized: {len(self._dns)} packets")
        except Exception as e:
            self._dns = None
            self.logger.debug(f"DNS analyzer not initialized: {e}")

        # ARP Analyzer
        try:
            self._arp = ArpAnalyzer(self.df)
            self.logger.debug(f"ARP analyzer initialized: {len(self._arp)} packets")
        except Exception as e:
            self._arp = None
            self.logger.debug(f"ARP analyzer not initialized: {e}")

        # ICMP Analyzer
        try:
            self._icmp = IcmpAnalyzer(self.df)
            self.logger.debug(f"ICMP analyzer initialized: {len(self._icmp)} packets")
        except Exception as e:
            self._icmp = None
            self.logger.debug(f"ICMP analyzer not initialized: {e}")

        # Flow Analyzer (should always work)
        try:
            self._flow = FlowAnalyzer(self.df)
            self.logger.debug(f"Flow analyzer initialized: {len(self._flow)} packets")
        except Exception as e:
            self._flow = None
            self.logger.debug(f"Flow analyzer not initialized: {e}")

        # IP Analyzer (should always work)
        try:
            self._ip = IpAnalyzer(self.df)
            self.logger.debug(f"IP analyzer initialized: {len(self._ip)} packets")
        except Exception as e:
            self._ip = None
            self.logger.debug(f"IP analyzer not initialized: {e}")

        # Anomaly Analyzer (should always work)
        try:
            self._anomaly = AnomalyAnalyzer(self.df)
            self.logger.debug(f"Anomaly analyzer initialized: {len(self._anomaly)} packets")
        except Exception as e:
            self._anomaly = None
            self.logger.debug(f"Anomaly analyzer not initialized: {e}")

    # ============================================================================
    # ANALYZER PROPERTIES
    # ============================================================================

    @property
    def tcp(self) -> Optional[TcpAnalyzer]:
        """Get TCP analyzer instance (None if no TCP traffic)."""
        return self._tcp

    @property
    def udp(self) -> Optional[UdpAnalyzer]:
        """Get UDP analyzer instance (None if no UDP traffic)."""
        return self._udp

    @property
    def dns(self) -> Optional[DnsAnalyzer]:
        """Get DNS analyzer instance (None if no DNS traffic)."""
        return self._dns

    @property
    def arp(self) -> Optional[ArpAnalyzer]:
        """Get ARP analyzer instance (None if no ARP traffic)."""
        return self._arp

    @property
    def icmp(self) -> Optional[IcmpAnalyzer]:
        """Get ICMP analyzer instance (None if no ICMP traffic)."""
        return self._icmp

    @property
    def flow(self) -> Optional[FlowAnalyzer]:
        """Get Flow analyzer instance."""
        return self._flow

    @property
    def ip(self) -> Optional[IpAnalyzer]:
        """Get IP analyzer instance."""
        return self._ip

    @property
    def anomaly(self) -> Optional[AnomalyAnalyzer]:
        """Get Anomaly analyzer instance."""
        return self._anomaly

    # ============================================================================
    # QUERY METHODS
    # ============================================================================

    def get_by_protocol(self, protocol: str) -> pl.DataFrame:
        """
        Get packets filtered by protocol.

        Args:
            protocol: Protocol name (TCP, UDP, IP, IPv6, DHCP, DNS, ARP, ICMP)

        Returns:
            pl.DataFrame: Filtered packets

        Raises:
            ValueError: If protocol is not valid
        """
        if protocol not in self.PROTOCOLS:
            raise ValueError(
                f"Invalid protocol: {protocol}. Valid protocols: {', '.join(self.PROTOCOLS)}"
            )
        return self.df.select(cs.contains(protocol))

    def find_ip_information(self, ip_address: str) -> pl.DataFrame:
        """
        Get all packets involving a specific IP address.

        Args:
            ip_address: IP address to search for

        Returns:
            pl.DataFrame: Packets with this IP as source or destination
        """
        # Only compare against actual IP address columns (src/dst), not all IP-related columns
        ip_address_patterns = ["IP_src", "IP_dst", "IPv6_src", "IPv6_dst"]
        ip_columns = [c for c in self.df.columns if any(p in c for p in ip_address_patterns)]
        if not ip_columns:
            return self.df.head(0)  # Return empty DataFrame with same schema
        return self.df.filter(pl.any_horizontal(pl.col(c) == ip_address for c in ip_columns))

    def get_timestamps(self) -> pl.DataFrame:
        """Get all timestamps from the capture."""
        return self.df.select(cs.contains("timestamp"))

    def get_timestamps_by_ip(self, ip_address: str) -> pl.DataFrame:
        """Get timestamps for packets involving a specific IP."""
        # Only compare against actual IP address columns (src/dst), not all IP-related columns
        ip_address_patterns = ["IP_src", "IP_dst", "IPv6_src", "IPv6_dst"]
        ip_columns = [c for c in self.df.columns if any(p in c for p in ip_address_patterns)]
        if not ip_columns:
            return self.df.select(cs.contains("timestamp")).head(0)
        return self.df.filter(
            pl.any_horizontal(pl.col(c) == ip_address for c in ip_columns)
        ).select(cs.contains("timestamp"))

    # ============================================================================
    # METADATA METHODS
    # ============================================================================

    def get_dataframe(self) -> pl.DataFrame:
        """Return the underlying DataFrame."""
        return self.df

    def get_schema(self) -> dict[str, str]:
        """Return the DataFrame schema."""
        return {col: str(dtype) for col, dtype in zip(self.df.columns, self.df.dtypes)}

    def get_packet_count(self) -> int:
        """Get total packet count."""
        return len(self.df)

    def get_date_range(self) -> dict[str, Any]:
        """
        Get the date range of the capture.

        Returns:
            dict: Dictionary with 'start', 'end', and 'duration' keys
        """
        if "timestamp" not in self.df.columns:
            return {"start": None, "end": None, "duration": None}

        timestamps = self.df.select("timestamp")
        min_ts = timestamps.min().item()
        max_ts = timestamps.max().item()

        duration = None
        if min_ts and max_ts:
            with contextlib.suppress(AttributeError, TypeError):
                duration = (max_ts - min_ts).total_seconds()

        return {"start": min_ts, "end": max_ts, "duration": duration}

    def get_analyzers_available(self) -> dict[str, bool]:
        """Get which analyzers are available."""
        return {
            "tcp": self._tcp is not None,
            "udp": self._udp is not None,
            "dns": self._dns is not None,
            "arp": self._arp is not None,
            "icmp": self._icmp is not None,
            "flow": self._flow is not None,
            "ip": self._ip is not None,
            "anomaly": self._anomaly is not None,
        }

    # ============================================================================
    # SUMMARY METHODS
    # ============================================================================

    def generate_summary(self) -> dict[str, Any]:
        """
        Generate comprehensive analysis summary.

        Returns:
            dict: Summary containing:
                - file_info: File metadata
                - packet_counts: Per-protocol packet counts
                - date_range: Temporal information
                - analyzers: Which analyzers have data
        """
        self.logger.log_analysis_start("network_summary")

        summary = {
            "file_info": {
                "path": str(self.path),
                "size_mb": self.df.estimated_size("mb"),
            },
            "packet_counts": {
                "total": len(self.df),
                "tcp": len(self._tcp) if self._tcp else 0,
                "udp": len(self._udp) if self._udp else 0,
                "dns": len(self._dns) if self._dns else 0,
                "arp": len(self._arp) if self._arp else 0,
                "icmp": len(self._icmp) if self._icmp else 0,
                "ip": len(self._ip) if self._ip else 0,
            },
            "date_range": self.get_date_range(),
            "analyzers_available": self.get_analyzers_available(),
        }

        # Protocol distribution
        if "IP_proto" in self.df.columns:
            protocol_counts = (
                self.df.group_by("IP_proto")
                .agg(pl.count().alias("count"))
                .sort("count", descending=True)
            )
            summary["protocols"] = {str(row[0]): int(row[1]) for row in protocol_counts.iter_rows()}

        # Get unique host counts
        src_cols = [c for c in ["IP_src", "IPv6_src"] if c in self.df.columns]
        dst_cols = [c for c in ["IP_dst", "IPv6_dst"] if c in self.df.columns]

        if src_cols or dst_cols:
            all_ips: list[Any] = []
            if src_cols:
                all_ips.extend(
                    self.df.select(pl.coalesce(src_cols)).to_series().drop_nulls().to_list()
                )
            if dst_cols:
                all_ips.extend(
                    self.df.select(pl.coalesce(dst_cols)).to_series().drop_nulls().to_list()
                )
            summary["unique_hosts"] = len(set(all_ips))

        # Format for readability
        file_info = summary["file_info"]
        if isinstance(file_info, dict) and file_info.get("size_mb"):
            file_info["size_formatted"] = format_bytes(int(file_info["size_mb"] * 1024 * 1024))

        date_range = summary["date_range"]
        if isinstance(date_range, dict) and date_range.get("duration"):
            date_range["duration_formatted"] = format_duration(date_range["duration"])

        self.logger.log_analysis_complete("network_summary")
        return summary

    def export_summary_report(
        self, format: str = "json", output: Optional[str] = None
    ) -> Optional[str]:
        """
        Export analysis summary to file.

        Args:
            format: Output format ('json', 'csv', or 'parquet')
            output: Output file path (if None, returns string for JSON)

        Returns:
            str: JSON string if output is None and format is 'json', otherwise None

        Raises:
            ValueError: If format is not supported
        """
        summary = self.generate_summary()

        if format == "json":
            json_str = json.dumps(summary, indent=2, default=str)
            if output:
                Path(output).write_text(json_str)
                self.logger.info(f"Summary exported to {output}")
                return None
            return json_str

        elif format == "csv":
            # Flatten summary for CSV
            flat_data = []
            for key, value in summary.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        flat_data.append(
                            {
                                "category": key,
                                "metric": sub_key,
                                "value": str(sub_value),
                            }
                        )
                else:
                    flat_data.append(
                        {
                            "category": "general",
                            "metric": key,
                            "value": str(value),
                        }
                    )

            df = pl.DataFrame(flat_data)
            if output:
                df.write_csv(output)
                self.logger.info(f"Summary exported to {output}")
            return None

        elif format == "parquet":
            flat_data = []
            for key, value in summary.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        flat_data.append(
                            {
                                "category": key,
                                "metric": sub_key,
                                "value": str(sub_value),
                            }
                        )
                else:
                    flat_data.append(
                        {
                            "category": "general",
                            "metric": key,
                            "value": str(value),
                        }
                    )

            df = pl.DataFrame(flat_data)
            if output:
                df.write_parquet(output)
                self.logger.info(f"Summary exported to {output}")
            return None

        else:
            raise ValueError(
                f"Unsupported format: {format}. Supported formats: 'json', 'csv', 'parquet'"
            )

    # ============================================================================
    # BEHAVIORAL ANALYSIS
    # ============================================================================

    def behavioral_summary(
        self, time_window: str = "1m", group_by_col: str = "source_ip"
    ) -> pl.DataFrame:
        """
        Generate behavioral summary of network traffic.

        Args:
            time_window: Time window to group packets by (e.g., '1m', '1h')
            group_by_col: Column to group by ('source_ip' or 'destination_ip')

        Returns:
            pl.DataFrame: Behavioral features aggregated over time window
        """
        if group_by_col not in ["source_ip", "destination_ip"]:
            raise ValueError("group_by_col must be 'source_ip' or 'destination_ip'")

        existing_cols = self.df.columns
        src_ip_cols = [c for c in ["IP_src", "IPv6_src"] if c in existing_cols]
        dst_ip_cols = [c for c in ["IP_dst", "IPv6_dst"] if c in existing_cols]

        if not src_ip_cols:
            raise ValueError("No source IP columns found")
        if not dst_ip_cols:
            raise ValueError("No destination IP columns found")

        # Unified source and destination IP
        df_with_unified_ips = self.df.with_columns(
            pl.coalesce(src_ip_cols).alias("source_ip"),
            pl.coalesce(dst_ip_cols).alias("destination_ip"),
        ).drop_nulls(group_by_col)

        if group_by_col == "source_ip":
            unique_ip_agg = pl.col("destination_ip").n_unique().alias("unique_dst_ip_count")
            bytes_agg = (
                pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("total_bytes_sent")
            )
        else:
            unique_ip_agg = pl.col("source_ip").n_unique().alias("unique_src_ip_count")
            bytes_agg = (
                pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("total_bytes_received")
            )

        # Build aggregation list - only include columns that exist
        aggs = [
            # Volume
            pl.len().alias("packet_count"),
            bytes_agg,
            # Diversity
            unique_ip_agg,
        ]

        # Optional port aggregations
        if "TCP_dport" in existing_cols:
            aggs.append(pl.col("TCP_dport").n_unique().alias("unique_tcp_dst_port_count"))
        if "UDP_dport" in existing_cols:
            aggs.append(pl.col("UDP_dport").n_unique().alias("unique_udp_dst_port_count"))

        # Per protocol (requires IP_proto)
        if "IP_proto" in existing_cols:
            aggs.extend(
                [
                    (pl.col("IP_proto").cast(pl.Int64, strict=False) == 6)
                    .sum()
                    .alias("tcp_packet_count"),
                    (pl.col("IP_proto").cast(pl.Int64, strict=False) == 17)
                    .sum()
                    .alias("udp_packet_count"),
                    (pl.col("IP_proto").cast(pl.Int64, strict=False) == 1)
                    .sum()
                    .alias("icmp_packet_count"),
                ]
            )

        # TCP flags (requires TCP_flags)
        if "TCP_flags" in existing_cols:
            aggs.extend(
                [
                    pl.col("TCP_flags").str.contains("S").sum().alias("syn_count"),
                    pl.col("TCP_flags").str.contains("R").sum().alias("rst_count"),
                    pl.col("TCP_flags").str.contains("F").sum().alias("fin_count"),
                    pl.col("TCP_flags").str.contains("P").sum().alias("psh_count"),
                ]
            )

        # IP flags (requires IP_flags)
        if "IP_flags" in existing_cols:
            aggs.extend(
                [
                    (pl.col("IP_flags") == "MF").sum().alias("ip_fragment_count"),
                    (pl.col("IP_flags") == "DF").sum().alias("ip_dont_fragment_count"),
                ]
            )

        behavioral_df = df_with_unified_ips.group_by_dynamic(
            index_column="timestamp", every=time_window, group_by=group_by_col
        ).agg(*aggs)
        return behavioral_df

    # ============================================================================
    # DUNDER METHODS
    # ============================================================================

    def __repr__(self) -> str:
        """Technical representation."""
        return f"ParquetAnalysisFacade(path={self.path!r}, packets={len(self.df)})"

    def __str__(self) -> str:
        """Human-readable representation."""
        return f"Network Analysis: {len(self.df)} packets from {self.path}"

    def __len__(self) -> int:
        """Return total packet count."""
        return len(self.df)
