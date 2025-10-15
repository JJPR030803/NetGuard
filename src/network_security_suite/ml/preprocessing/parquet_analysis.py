"""Base parquet analysis logic"""

import polars as pl
import polars.selectors as cs
from typing import Optional, Dict, Any
import json
from pathlib import Path
from .logger import get_logger
from .errors import (
    ParquetAnalysisError,
    AnalyzerNotInitializedError,
    FileNotFoundError as ParquetFileNotFoundError,
    InvalidFileFormatError
) 


class NetworkParquetAnalysis:
    """
    NetworkParquetAnalysis.

    Class to initialize and have parquet files filtered, processed, etc.
    
    Args:
        path:str: Path where the parquet file is.

    Returns:
        NetworkParquetAnalysis object
    """
    def __init__(self, path: str, lazy_load: bool = False):
        """
        Initialize NetworkParquetAnalysis.

        Args:
            path: Path to the parquet file
            lazy_load: If True, analyzers are initialized on first access (default: False)

        Raises:
            ParquetFileNotFoundError: If file doesn't exist
            InvalidFileFormatError: If file is not a valid parquet file
        """
        self.path = path
        self.logger = get_logger()
        self._lazy_load = lazy_load

        # Validate file exists
        if not Path(path).exists():
            raise ParquetFileNotFoundError(path)

        # Load DataFrame
        try:
            self.logger.info(f"Loading parquet file: {path}")
            self.df = pl.read_parquet(self.path)
            self.logger.log_dataframe_info(
                "loaded_parquet",
                shape=self.df.shape,
                memory_mb=self.df.estimated_size("mb")
            )
        except Exception as e:
            raise InvalidFileFormatError(path, e)

        self.PROTOCOLS = set(["TCP", "UDP", "IP", "IPv6", "DHCP", "DNS", "ARP", "ICMP"])

        # Initialize analyzer instances (with lazy loading support)
        self._tcp = None
        self._udp = None
        self._dns = None
        self._arp = None
        self._icmp = None
        self._flow = None
        self._ip = None
        self._anomaly = None

        # Initialize analyzers immediately if not lazy loading
        if not lazy_load:
            self._initialize_analyzers()

    def _initialize_analyzers(self):
        """Initialize all analyzer instances."""
        from .analyzers.tcp_analyzer import TcpAnalyzer
        from .analyzers.udp_analyzer import UdpAnalyzer
        from .analyzers.dns_analyzer import DnsAnalyzer
        from .analyzers.arp_analyzer import ArpAnalyzer
        from .analyzers.icmp_analyzer import IcmpAnalyzer
        from .analyzers.flow_analyzer import FlowAnalyzer
        from .analyzers.ip_analyzer import IpAnalyzer
        from .analyzers.anomaly_analyzer import AnomalyAnalyzer

        # Try to initialize each analyzer (some may fail if protocol not present)
        try:
            self._tcp = TcpAnalyzer(self.df)
            self.logger.debug("TCP analyzer initialized")
        except Exception as e:
            self.logger.debug(f"TCP analyzer not initialized: {e}")

        try:
            self._udp = UdpAnalyzer(self.df)
            self.logger.debug("UDP analyzer initialized")
        except Exception as e:
            self.logger.debug(f"UDP analyzer not initialized: {e}")

        try:
            self._dns = DnsAnalyzer(self.df)
            self.logger.debug("DNS analyzer initialized")
        except Exception as e:
            self.logger.debug(f"DNS analyzer not initialized: {e}")

        try:
            self._arp = ArpAnalyzer(self.df)
            self.logger.debug("ARP analyzer initialized")
        except Exception as e:
            self.logger.debug(f"ARP analyzer not initialized: {e}")

        try:
            self._icmp = IcmpAnalyzer(self.df)
            self.logger.debug("ICMP analyzer initialized")
        except Exception as e:
            self.logger.debug(f"ICMP analyzer not initialized: {e}")

        try:
            self._flow = FlowAnalyzer(self.df)
            self.logger.debug("Flow analyzer initialized")
        except Exception as e:
            self.logger.debug(f"Flow analyzer not initialized: {e}")

        try:
            self._ip = IpAnalyzer(self.df)
            self.logger.debug("IP analyzer initialized")
        except Exception as e:
            self.logger.debug(f"IP analyzer not initialized: {e}")

        try:
            self._anomaly = AnomalyAnalyzer(self.df)
            self.logger.debug("Anomaly analyzer initialized")
        except Exception as e:
            self.logger.debug(f"Anomaly analyzer not initialized: {e}")

    # Properties for lazy loading analyzers
    @property
    def tcp(self):
        """Get TCP analyzer instance."""
        if self._tcp is None:
            if self._lazy_load:
                from .analyzers.tcp_analyzer import TcpAnalyzer
                try:
                    self._tcp = TcpAnalyzer(self.df)
                except Exception as e:
                    raise AnalyzerNotInitializedError("tcp") from e
            else:
                raise AnalyzerNotInitializedError("tcp")
        return self._tcp

    @property
    def udp(self):
        """Get UDP analyzer instance."""
        if self._udp is None:
            if self._lazy_load:
                from .analyzers.udp_analyzer import UdpAnalyzer
                try:
                    self._udp = UdpAnalyzer(self.df)
                except Exception as e:
                    raise AnalyzerNotInitializedError("udp") from e
            else:
                raise AnalyzerNotInitializedError("udp")
        return self._udp

    @property
    def dns(self):
        """Get DNS analyzer instance."""
        if self._dns is None:
            if self._lazy_load:
                from .analyzers.dns_analyzer import DnsAnalyzer
                try:
                    self._dns = DnsAnalyzer(self.df)
                except Exception as e:
                    raise AnalyzerNotInitializedError("dns") from e
            else:
                raise AnalyzerNotInitializedError("dns")
        return self._dns

    @property
    def arp(self):
        """Get ARP analyzer instance."""
        if self._arp is None:
            if self._lazy_load:
                from .analyzers.arp_analyzer import ArpAnalyzer
                try:
                    self._arp = ArpAnalyzer(self.df)
                except Exception as e:
                    raise AnalyzerNotInitializedError("arp") from e
            else:
                raise AnalyzerNotInitializedError("arp")
        return self._arp

    @property
    def icmp(self):
        """Get ICMP analyzer instance."""
        if self._icmp is None:
            if self._lazy_load:
                from .analyzers.icmp_analyzer import IcmpAnalyzer
                try:
                    self._icmp = IcmpAnalyzer(self.df)
                except Exception as e:
                    raise AnalyzerNotInitializedError("icmp") from e
            else:
                raise AnalyzerNotInitializedError("icmp")
        return self._icmp

    @property
    def flow(self):
        """Get Flow analyzer instance."""
        if self._flow is None:
            if self._lazy_load:
                from .analyzers.flow_analyzer import FlowAnalyzer
                try:
                    self._flow = FlowAnalyzer(self.df)
                except Exception as e:
                    raise AnalyzerNotInitializedError("flow") from e
            else:
                raise AnalyzerNotInitializedError("flow")
        return self._flow

    @property
    def ip(self):
        """Get IP analyzer instance."""
        if self._ip is None:
            if self._lazy_load:
                from .analyzers.ip_analyzer import IpAnalyzer
                try:
                    self._ip = IpAnalyzer(self.df)
                except Exception as e:
                    raise AnalyzerNotInitializedError("ip") from e
            else:
                raise AnalyzerNotInitializedError("ip")
        return self._ip

    @property
    def anomaly(self):
        """Get Anomaly analyzer instance."""
        if self._anomaly is None:
            if self._lazy_load:
                from .analyzers.anomaly_analyzer import AnomalyAnalyzer
                try:
                    self._anomaly = AnomalyAnalyzer(self.df)
                except Exception as e:
                    raise AnalyzerNotInitializedError("anomaly") from e
            else:
                raise AnalyzerNotInitializedError("anomaly")
        return self._anomaly

    def get_by_protocol(self,protocol:str):
        """
        get_by_protocol:
            gets a specific packet information based on it protocol.

        Args:
            protocol:str: Protocol for which to look for the packets,
        Returns:
            polars.DataFrame
        """
        if protocol not in self.PROTOCOLS:
            raise ValueError(f"Invalid protocol: {protocol}\nValid protocols are: {', '.join(self.PROTOCOLS)}")
        return self.df.select(cs.contains(protocol))

    def find_ip_information(self, ip_address: str)->pl.DataFrame:
        """
        find_ip_information:
            gets specific data packets based on its ip
        Args:
            ip_address:str: IP for which to look up information
        Returns:
            polars.DataFrame
        """
        ip_columns = self.df.select(cs.contains("IP") | cs.contains("IPv6")).columns
        return self.df.filter(
            pl.any_horizontal(pl.col(c) == ip_address for c in ip_columns)
        )

    def get_timestamps(self)->pl.DataFrame:
        """
        Returns timestamps in the parquet
        """
        return self.df.select(cs.contains("timestamp"))

    def get_timestamps_by_ip(self, ip_address: str)->pl.DataFrame:
        """
        Returns timestamps using ip as filter
        """
        ip_columns = self.df.select(cs.contains("IP") | cs.contains("IPv6")).columns
        return self.df.filter(
            pl.any_horizontal(pl.col(c) == ip_address for c in ip_columns)
        ).select(cs.contains("timestamp"))


    def behavioral_summary(self, time_window: str = "1m", group_by_col: str = "source_ip"):
        """
        Generates a behavioral summary of network traffic, grouped by source or destination IP.

        Args:
            time_window (str): The time window to group packets by (e.g., '1m', '1h').
            group_by_col (str): The column to group by, either 'source_ip' or 'destination_ip'.

        Returns:
            pl.DataFrame: A DataFrame with behavioral features aggregated over the time window.
        """
        if group_by_col not in ["source_ip", "destination_ip"]:
            raise ValueError("group_by_col must be one of 'source_ip' or 'destination_ip'")

        existing_cols = self.df.columns
        src_ip_cols = [c for c in ["IP_src", "IPv6_src"] if c in existing_cols]
        dst_ip_cols = [c for c in ["IP_dst", "IPv6_dst"] if c in existing_cols]

        if not src_ip_cols:
            raise ValueError("No source IP columns found")
        if not dst_ip_cols:
            raise ValueError("No destination IP columns found")

        # Single unified source and destination IP
        df_with_unified_ips = self.df.with_columns(
            pl.coalesce(src_ip_cols).alias("source_ip"),
            pl.coalesce(dst_ip_cols).alias("destination_ip")
        ).drop_nulls(group_by_col)

        if group_by_col == "source_ip":
            unique_ip_agg = pl.col("destination_ip").n_unique().alias("unique_dst_ip_count")
            bytes_agg = pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("total_bytes_sent")
        else:  # destination_ip
            unique_ip_agg = pl.col("source_ip").n_unique().alias("unique_src_ip_count")
            bytes_agg = pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("total_bytes_received")

        behavioral_df = df_with_unified_ips.group_by_dynamic(
            index_column="timestamp",
            every=time_window,
            by=group_by_col
        ).agg(
            # Volume
            pl.count().alias("packet_count"),
            bytes_agg,

            # Diversity unique
            unique_ip_agg,
            pl.col("TCP_dport").n_unique().alias("unique_tcp_dst_port_count"),
            pl.col("UDP_dport").n_unique().alias("unique_udp_dst_port_count"),

            # Per protocol
            (pl.col("IP_proto").cast(pl.Int64, strict=False) == 6).sum().alias("tcp_packet_count"),
            (pl.col("IP_proto").cast(pl.Int64, strict=False) == 17).sum().alias("udp_packet_count"),
            (pl.col("IP_proto").cast(pl.Int64, strict=False) == 1).sum().alias("icmp_packet_count"),

            # TCP flag features check for SYN and RST count
            pl.col("TCP_flags").str.contains("S").sum().alias("syn_count"),
            pl.col("TCP_flags").str.contains("R").sum().alias("rst_count"),
            pl.col("TCP_flags").str.contains("F").sum().alias("fin_count"),
            pl.col("TCP_flags").str.contains("P").sum().alias("psh_count"),

            # IP flags
            (pl.col("IP_flags") == "MF").sum().alias("ip_fragment_count"),
            (pl.col("IP_flags") == "DF").sum().alias("ip_dont_fragment_count")
        )
        return behavioral_df

    def service_behavioral_summary(self, time_window: str = "1m"):
        """
        Generates a behavioral summary of network traffic, grouped by destination service port.
        This helps in understanding the behavior of traffic to specific services.

        Args:
            time_window (str): The time window to group packets by (e.g., '1m', '1h').

        Returns:
            pl.DataFrame: A DataFrame with behavioral features aggregated by port over the time window.
        """
        # Coalesce IP columns for source IP
        existing_cols = self.df.columns
        src_ip_cols = [c for c in ["IP_src", "IPv6_src"] if c in existing_cols]
        if not src_ip_cols:
            raise ValueError("No source IP columns found")

        df_with_src_ip = self.df.with_columns(
            pl.coalesce(src_ip_cols).alias("source_ip")
        ).drop_nulls("source_ip")

        summaries = []

        # TCP summary
        if "TCP_dport" in df_with_src_ip.columns:
            tcp_summary = df_with_src_ip.filter(pl.col("TCP_dport").is_not_null()).group_by_dynamic(
                index_column="timestamp",
                every=time_window,
                by="TCP_dport"
            ).agg(
                pl.count().alias("packet_count"),
                pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("total_bytes"),
                pl.col("source_ip").n_unique().alias("unique_src_ip_count"),
                pl.col("TCP_flags").str.contains("S").sum().alias("syn_count"),
                pl.col("TCP_flags").str.contains("R").sum().alias("rst_count"),
                pl.col("TCP_flags").str.contains("F").sum().alias("fin_count")
            ).rename({"TCP_dport": "destination_port"}).with_columns(pl.lit("TCP").alias("protocol"))
            summaries.append(tcp_summary)

        # UDP summary
        if "UDP_dport" in df_with_src_ip.columns:
            udp_summary = df_with_src_ip.filter(pl.col("UDP_dport").is_not_null()).group_by_dynamic(
                index_column="timestamp",
                every=time_window,
                by="UDP_dport"
            ).agg(
                pl.count().alias("packet_count"),
                pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("total_bytes"),
                pl.col("source_ip").n_unique().alias("unique_src_ip_count")
            ).rename({"UDP_dport": "destination_port"}).with_columns(pl.lit("UDP").alias("protocol"))
            summaries.append(udp_summary)

        if not summaries:
            return pl.DataFrame()

        return pl.concat(summaries, how="diagonal")

    def get_dataframe(self) -> pl.DataFrame:
        """
        Return the underlying DataFrame.

        Returns:
            pl.DataFrame: The complete parquet DataFrame
        """
        return self.df

    def get_schema(self) -> Dict[str, Any]:
        """
        Return the DataFrame schema.

        Returns:
            dict: Dictionary mapping column names to data types
        """
        return {col: str(dtype) for col, dtype in zip(self.df.columns, self.df.dtypes)}

    def get_packet_count(self) -> int:
        """
        Get total packet count.

        Returns:
            int: Total number of packets in the capture
        """
        return len(self.df)

    def get_date_range(self) -> Dict[str, Any]:
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
            try:
                duration = (max_ts - min_ts).total_seconds()
            except:
                duration = None

        return {
            "start": min_ts,
            "end": max_ts,
            "duration": duration
        }

    def generate_network_summary(self) -> Dict[str, Any]:
        """
        Generate a complete network traffic summary.

        Returns:
            dict: Comprehensive summary of network traffic
        """
        from .utils import format_bytes, format_duration

        self.logger.log_analysis_start("network_summary")

        summary = {
            "file_info": {
                "path": str(self.path),
                "size": self.df.estimated_size("mb"),
            },
            "temporal": self.get_date_range(),
            "packet_counts": {
                "total": self.get_packet_count(),
            },
            "protocols": {},
            "top_ips": {},
            "analyzers_available": {}
        }

        # Protocol distribution
        if "IP_proto" in self.df.columns:
            protocol_counts = (
                self.df
                .group_by("IP_proto")
                .agg(pl.count().alias("count"))
                .sort("count", descending=True)
            )
            summary["protocols"] = {
                str(row[0]): int(row[1])
                for row in protocol_counts.iter_rows()
            }

        # Get unique host counts
        src_cols = [c for c in ["IP_src", "IPv6_src"] if c in self.df.columns]
        dst_cols = [c for c in ["IP_dst", "IPv6_dst"] if c in self.df.columns]

        if src_cols or dst_cols:
            all_ips = []
            if src_cols:
                all_ips.extend(self.df.select(pl.coalesce(src_cols)).to_series().drop_nulls().to_list())
            if dst_cols:
                all_ips.extend(self.df.select(pl.coalesce(dst_cols)).to_series().drop_nulls().to_list())

            summary["unique_hosts"] = len(set(all_ips))

        # Check which analyzers are available
        summary["analyzers_available"] = {
            "tcp": self._tcp is not None,
            "udp": self._udp is not None,
            "dns": self._dns is not None,
            "arp": self._arp is not None,
            "icmp": self._icmp is not None,
            "flow": self._flow is not None,
            "ip": self._ip is not None,
            "anomaly": self._anomaly is not None,
        }

        # Add protocol-specific summaries if analyzers available
        if self._tcp:
            try:
                summary["tcp"] = {
                    "packet_count": len(self._tcp.df),
                    "syn_count": self._tcp.get_syn_count() if hasattr(self._tcp, 'get_syn_count') else None,
                }
            except Exception as e:
                self.logger.debug(f"Error generating TCP summary: {e}")

        if self._udp:
            try:
                summary["udp"] = {
                    "packet_count": len(self._udp.df),
                }
            except Exception as e:
                self.logger.debug(f"Error generating UDP summary: {e}")

        # Format bytes and duration for readability
        if summary["file_info"]["size"]:
            summary["file_info"]["size_formatted"] = format_bytes(
                int(summary["file_info"]["size"] * 1024 * 1024)
            )

        if summary["temporal"]["duration"]:
            summary["temporal"]["duration_formatted"] = format_duration(
                summary["temporal"]["duration"]
            )

        self.logger.log_analysis_complete("network_summary")
        return summary

    def export_summary_report(
        self,
        format: str = "json",
        output: Optional[str] = None
    ) -> Optional[str]:
        """
        Export analysis summary to file.

        Args:
            format: Output format ('json', 'csv', or 'parquet')
            output: Output file path (if None, returns string)

        Returns:
            str: JSON string if output is None, otherwise None

        Raises:
            ValueError: If format is not supported
        """
        summary = self.generate_network_summary()

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
                        flat_data.append({
                            "category": key,
                            "metric": sub_key,
                            "value": str(sub_value)
                        })
                else:
                    flat_data.append({
                        "category": "general",
                        "metric": key,
                        "value": str(value)
                    })

            df = pl.DataFrame(flat_data)
            if output:
                df.write_csv(output)
                self.logger.info(f"Summary exported to {output}")
            return None

        elif format == "parquet":
            # Similar to CSV but save as parquet
            flat_data = []
            for key, value in summary.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        flat_data.append({
                            "category": key,
                            "metric": sub_key,
                            "value": str(sub_value)
                        })
                else:
                    flat_data.append({
                        "category": "general",
                        "metric": key,
                        "value": str(value)
                    })

            df = pl.DataFrame(flat_data)
            if output:
                df.write_parquet(output)
                self.logger.info(f"Summary exported to {output}")
            return None

        else:
            raise ValueError(
                f"Unsupported format: {format}. "
                "Supported formats: 'json', 'csv', 'parquet'"
            )

if __name__ == "__main__":
    path = "/mnt/shared/tesis/netguard/src/network_security_suite/data/ml_testing.parquet"
    analysis = NetworkParquetAnalysis(path)

    print("---\"Behavioral Summary by Source IP\"---")
    src_df = analysis.behavioral_summary(time_window="10m", group_by_col="source_ip")
    print(src_df.describe())

    print("\n---\"Behavioral Summary by Destination IP\"---")
    dst_df = analysis.behavioral_summary(time_window="10m", group_by_col="destination_ip")
    print(dst_df.describe())

    print("\n---\"Behavioral Summary by Service Port\"---")
    service_df = analysis.service_behavioral_summary(time_window="10m")
    print(service_df)
