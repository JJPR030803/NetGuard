"""UDP protocol analyzer for network traffic analysis."""

import polars as pl
from typing import Optional
from ..errors import (
    EmptyDataFrameError,
    MissingColumnError,
    InvalidThresholdError,
)
from ..utils import (
    validate_dataframe_columns,
    has_column,
    time_window_to_polars,
    safe_cast_to_int,
    classify_port,
    create_flow_id,
)


class UdpAnalyzer:
    """
    Analyzer for UDP protocol traffic.

    Filters the provided DataFrame to only UDP-related packets and provides
    UDP-specific analysis methods.

    Args:
        df: Polars DataFrame containing network traffic data
    """

    # UDP Protocol Constants
    UDP_PROTOCOL_NUMBER = 17

    # Common UDP ports
    COMMON_PORTS = {
        53: "DNS",
        67: "DHCP-SERVER",
        68: "DHCP-CLIENT",
        69: "TFTP",
        123: "NTP",
        137: "NETBIOS-NS",
        138: "NETBIOS-DGM",
        161: "SNMP",
        162: "SNMP-TRAP",
        500: "ISAKMP",
        514: "SYSLOG",
        520: "RIP",
        1900: "SSDP",
        4500: "IPSec-NAT-T",
        5353: "MDNS",
    }

    # Port ranges
    WELL_KNOWN_PORTS = range(0, 1024)
    REGISTERED_PORTS = range(1024, 49152)
    EPHEMERAL_PORTS = range(49152, 65536)

    def __init__(self, df: pl.DataFrame):
        """
        Initialize UDP analyzer and filter to UDP traffic only.

        Args:
            df: Polars DataFrame containing network traffic data

        Raises:
            EmptyDataFrameError: If input DataFrame is empty
            MissingColumnError: If required columns are missing
        """
        if df.is_empty():
            raise EmptyDataFrameError("Cannot initialize UdpAnalyzer with empty DataFrame")

        # Validate required columns
        validate_dataframe_columns(df, ["IP_proto"])

        # Filter to UDP traffic only (IP protocol 17)
        self.df = df.filter(
            pl.col("IP_proto").cast(pl.Int64, strict=False) == self.UDP_PROTOCOL_NUMBER
        )

        if self.df.is_empty():
            raise EmptyDataFrameError("No UDP traffic found in DataFrame")

        # Store metadata for debugging
        self._packet_count = len(self.df)
        self._has_udp_columns = any("UDP" in col for col in self.df.columns)

    def __repr__(self) -> str:
        """Technical representation for debugging."""
        return (
            f"UdpAnalyzer(packets={self._packet_count}, "
            f"shape={self.df.shape}, has_udp_cols={self._has_udp_columns})"
        )

    def __str__(self) -> str:
        """Human-readable string representation."""
        date_range = ""
        if "timestamp" in self.df.columns and len(self.df) > 0:
            min_ts = self.df["timestamp"].min()
            max_ts = self.df["timestamp"].max()
            date_range = f", {min_ts} to {max_ts}"
        return f"UDP Analyzer: {self._packet_count} packets{date_range}"

    def __eq__(self, other) -> bool:
        """Compare two UdpAnalyzer instances."""
        if not isinstance(other, UdpAnalyzer):
            return False
        return self.df.frame_equal(other.df)

    # ============================================================================
    # TRAFFIC ANALYSIS METHODS
    # ============================================================================

    def detect_unidirectional_traffic(self) -> pl.DataFrame:
        """
        Detect UDP traffic with no response (potential scanning or tunneling).

        Returns:
            pl.DataFrame: Unidirectional UDP flows with columns:
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - src_port: Source port
                - dst_port: Destination port
                - packet_count: Number of packets in one direction
                - total_bytes: Total bytes sent
                - first_seen: First packet timestamp
                - last_seen: Last packet timestamp

        Raises:
            MissingColumnError: If required columns are missing
        """
        required_cols = ["UDP_sport", "UDP_dport"]
        validate_dataframe_columns(self.df, required_cols)

        # Get source and destination IP columns
        src_ip_col = "IP_src" if has_column(self.df, "IP_src") else "IPv6_src"
        dst_ip_col = "IP_dst" if has_column(self.df, "IP_dst") else "IPv6_dst"

        if not has_column(self.df, src_ip_col) or not has_column(self.df, dst_ip_col):
            raise MissingColumnError(
                "IP_src/IP_dst or IPv6_src/IPv6_dst",
                self.df.columns
            )

        # Create flow identifiers for both directions
        df_with_flow = self.df.with_columns([
            pl.col(src_ip_col).alias("src_ip"),
            pl.col(dst_ip_col).alias("dst_ip"),
            safe_cast_to_int(pl.col("UDP_sport")).alias("src_port"),
            safe_cast_to_int(pl.col("UDP_dport")).alias("dst_port"),
            # Forward flow: src->dst
            (
                pl.col(src_ip_col).cast(pl.Utf8) + ":" +
                pl.col("UDP_sport").cast(pl.Utf8) + "->" +
                pl.col(dst_ip_col).cast(pl.Utf8) + ":" +
                pl.col("UDP_dport").cast(pl.Utf8)
            ).alias("forward_flow"),
            # Reverse flow: dst->src
            (
                pl.col(dst_ip_col).cast(pl.Utf8) + ":" +
                pl.col("UDP_dport").cast(pl.Utf8) + "->" +
                pl.col(src_ip_col).cast(pl.Utf8) + ":" +
                pl.col("UDP_sport").cast(pl.Utf8)
            ).alias("reverse_flow"),
        ])

        # Get all unique flows
        forward_flows = df_with_flow.select("forward_flow").unique()
        reverse_flows = df_with_flow.select("reverse_flow").unique()

        # Find flows that exist in forward but not in reverse (no response)
        unidirectional_flows = forward_flows.join(
            reverse_flows,
            left_on="forward_flow",
            right_on="reverse_flow",
            how="anti"
        )

        # Get statistics for unidirectional flows
        result = df_with_flow.filter(
            pl.col("forward_flow").is_in(unidirectional_flows["forward_flow"])
        ).group_by(["src_ip", "dst_ip", "src_port", "dst_port"]).agg([
            pl.count().alias("packet_count"),
            safe_cast_to_int(pl.col("IP_len")).sum().alias("total_bytes"),
            pl.col("timestamp").min().alias("first_seen"),
            pl.col("timestamp").max().alias("last_seen"),
        ]).sort("packet_count", descending=True)

        return result

    def get_most_used_ports(self, n: int = 10) -> pl.DataFrame:
        """
        Get top N most used UDP ports.

        Args:
            n: Number of top ports to return

        Returns:
            pl.DataFrame: Top ports with columns:
                - port: Port number
                - port_name: Service name if known
                - port_class: Port classification (well-known, registered, ephemeral)
                - count: Number of packets
                - unique_sources: Number of unique source IPs

        Raises:
            MissingColumnError: If UDP_dport column is missing
            InvalidThresholdError: If n is not positive
        """
        if n <= 0:
            raise InvalidThresholdError(n, "n must be positive")

        validate_dataframe_columns(self.df, ["UDP_dport"])

        # Get source IP column
        src_ip_col = "IP_src" if has_column(self.df, "IP_src") else "IPv6_src"
        if not has_column(self.df, src_ip_col):
            raise MissingColumnError("IP_src or IPv6_src", self.df.columns)

        # Count packets per destination port
        port_stats = self.df.group_by("UDP_dport").agg([
            pl.count().alias("count"),
            pl.col(src_ip_col).n_unique().alias("unique_sources"),
        ]).sort("count", descending=True).head(n)

        # Add port names and classifications
        result = port_stats.with_columns([
            safe_cast_to_int(pl.col("UDP_dport")).alias("port"),
        ]).drop("UDP_dport").with_columns([
            pl.col("port").map_elements(
                lambda x: self.COMMON_PORTS.get(x, "Unknown"),
                return_dtype=pl.Utf8
            ).alias("port_name"),
            pl.col("port").map_elements(
                classify_port,
                return_dtype=pl.Utf8
            ).alias("port_class"),
        ])

        return result

    def get_udp_flow_stats(self) -> pl.DataFrame:
        """
        Get statistics per UDP flow (5-tuple grouping).

        Returns:
            pl.DataFrame: Flow statistics with columns:
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - src_port: Source port
                - dst_port: Destination port
                - flow_id: Unique flow identifier
                - packet_count: Number of packets in flow
                - total_bytes: Total bytes in flow
                - avg_packet_size: Average packet size
                - duration_seconds: Flow duration in seconds
                - first_seen: First packet timestamp
                - last_seen: Last packet timestamp

        Raises:
            MissingColumnError: If required columns are missing
        """
        required_cols = ["UDP_sport", "UDP_dport", "timestamp"]
        validate_dataframe_columns(self.df, required_cols)

        # Get source and destination IP columns
        src_ip_col = "IP_src" if has_column(self.df, "IP_src") else "IPv6_src"
        dst_ip_col = "IP_dst" if has_column(self.df, "IP_dst") else "IPv6_dst"

        if not has_column(self.df, src_ip_col) or not has_column(self.df, dst_ip_col):
            raise MissingColumnError(
                "IP_src/IP_dst or IPv6_src/IPv6_dst",
                self.df.columns
            )

        # Prepare DataFrame with flow identifiers
        df_with_flow = self.df.with_columns([
            pl.col(src_ip_col).alias("src_ip"),
            pl.col(dst_ip_col).alias("dst_ip"),
            safe_cast_to_int(pl.col("UDP_sport")).alias("src_port"),
            safe_cast_to_int(pl.col("UDP_dport")).alias("dst_port"),
        ])

        # Group by 5-tuple and calculate statistics
        flow_stats = df_with_flow.group_by(
            ["src_ip", "dst_ip", "src_port", "dst_port"]
        ).agg([
            pl.count().alias("packet_count"),
            safe_cast_to_int(pl.col("IP_len")).sum().alias("total_bytes"),
            safe_cast_to_int(pl.col("IP_len")).mean().alias("avg_packet_size"),
            pl.col("timestamp").min().alias("first_seen"),
            pl.col("timestamp").max().alias("last_seen"),
        ]).with_columns([
            (
                (pl.col("last_seen") - pl.col("first_seen")).dt.total_seconds()
            ).alias("duration_seconds")
        ])

        # Add flow ID
        result = flow_stats.with_columns([
            (
                pl.col("src_ip").cast(pl.Utf8) + ":" +
                pl.col("src_port").cast(pl.Utf8) + "->" +
                pl.col("dst_ip").cast(pl.Utf8) + ":" +
                pl.col("dst_port").cast(pl.Utf8) + ":UDP"
            ).alias("flow_id")
        ]).sort("packet_count", descending=True)

        return result

    def calculate_packet_rate(self, time_window: str = "1m") -> pl.DataFrame:
        """
        Calculate UDP packets per time window.

        Args:
            time_window: Time window for aggregation (e.g., "1m", "5m", "1h")

        Returns:
            pl.DataFrame: Packet rate over time with columns:
                - timestamp: Time window start
                - packet_count: Number of packets in window
                - byte_count: Total bytes in window
                - packets_per_second: Calculated packet rate
                - bytes_per_second: Calculated byte rate

        Raises:
            MissingColumnError: If timestamp column is missing
            InvalidTimeWindowError: If time window format is invalid
        """
        validate_dataframe_columns(self.df, ["timestamp"])

        # Convert time window to Polars format (validates format)
        polars_window = time_window_to_polars(time_window)

        # Group by time window
        result = self.df.group_by_dynamic(
            index_column="timestamp",
            every=polars_window
        ).agg([
            pl.count().alias("packet_count"),
            safe_cast_to_int(pl.col("IP_len")).sum().alias("byte_count"),
        ])

        # Calculate window duration in seconds for rate calculation
        from ..utils import parse_time_window
        window_seconds = parse_time_window(time_window).total_seconds()

        # Add rate calculations
        result = result.with_columns([
            (pl.col("packet_count") / window_seconds).alias("packets_per_second"),
            (pl.col("byte_count") / window_seconds).alias("bytes_per_second"),
        ]).sort("timestamp")

        return result

    # ============================================================================
    # ANOMALY DETECTION METHODS
    # ============================================================================

    def detect_udp_flood(self, threshold: int = 1000, time_window: str = "1m") -> pl.DataFrame:
        """
        Detect abnormal UDP packet volume (potential DDoS).

        Args:
            threshold: Packet count threshold per source IP per time window
            time_window: Time window for analysis (e.g., "1m", "5m")

        Returns:
            pl.DataFrame: Suspected UDP flood sources with columns:
                - src_ip: Source IP address
                - timestamp: Time window
                - packet_count: Number of packets sent
                - byte_count: Total bytes sent
                - unique_destinations: Number of unique destination IPs
                - unique_ports: Number of unique destination ports

        Raises:
            MissingColumnError: If required columns are missing
            InvalidThresholdError: If threshold is not positive
        """
        if threshold <= 0:
            raise InvalidThresholdError(threshold, "threshold must be positive")

        validate_dataframe_columns(self.df, ["timestamp"])

        # Get IP columns
        src_ip_col = "IP_src" if has_column(self.df, "IP_src") else "IPv6_src"
        dst_ip_col = "IP_dst" if has_column(self.df, "IP_dst") else "IPv6_dst"

        if not has_column(self.df, src_ip_col):
            raise MissingColumnError("IP_src or IPv6_src", self.df.columns)

        # Convert time window to Polars format
        polars_window = time_window_to_polars(time_window)

        # Prepare DataFrame
        df_prepared = self.df.with_columns([
            pl.col(src_ip_col).alias("src_ip"),
        ])

        # Group by source IP and time window
        flood_candidates = df_prepared.group_by_dynamic(
            index_column="timestamp",
            every=polars_window,
            by="src_ip"
        ).agg([
            pl.count().alias("packet_count"),
            safe_cast_to_int(pl.col("IP_len")).sum().alias("byte_count"),
        ])

        # Add additional metrics if destination data is available
        if has_column(self.df, dst_ip_col):
            df_prepared = df_prepared.with_columns([
                pl.col(dst_ip_col).alias("dst_ip"),
            ])
            flood_candidates = df_prepared.group_by_dynamic(
                index_column="timestamp",
                every=polars_window,
                by="src_ip"
            ).agg([
                pl.count().alias("packet_count"),
                safe_cast_to_int(pl.col("IP_len")).sum().alias("byte_count"),
                pl.col("dst_ip").n_unique().alias("unique_destinations"),
                safe_cast_to_int(pl.col("UDP_dport")).n_unique().alias("unique_ports")
                if has_column(self.df, "UDP_dport") else pl.lit(0).alias("unique_ports"),
            ])

        # Filter sources exceeding threshold
        result = flood_candidates.filter(
            pl.col("packet_count") >= threshold
        ).sort("packet_count", descending=True)

        return result

    def detect_udp_amplification(self, min_amplification_ratio: float = 10.0) -> pl.DataFrame:
        """
        Detect UDP amplification attacks (small request, large response).

        Args:
            min_amplification_ratio: Minimum response/request size ratio to flag

        Returns:
            pl.DataFrame: Suspected amplification attacks with columns:
                - victim_ip: Likely victim IP (receives large responses)
                - reflector_ip: Reflector server IP
                - service_port: Service port being abused
                - request_count: Number of requests
                - avg_request_size: Average request size
                - avg_response_size: Average response size
                - amplification_ratio: Response/request size ratio

        Raises:
            MissingColumnError: If required columns are missing
            InvalidThresholdError: If min_amplification_ratio is not valid
        """
        if min_amplification_ratio <= 1.0:
            raise InvalidThresholdError(
                min_amplification_ratio,
                "min_amplification_ratio must be greater than 1.0"
            )

        required_cols = ["UDP_sport", "UDP_dport"]
        validate_dataframe_columns(self.df, required_cols)

        # Get IP columns
        src_ip_col = "IP_src" if has_column(self.df, "IP_src") else "IPv6_src"
        dst_ip_col = "IP_dst" if has_column(self.df, "IP_dst") else "IPv6_dst"

        if not has_column(self.df, src_ip_col) or not has_column(self.df, dst_ip_col):
            raise MissingColumnError(
                "IP_src/IP_dst or IPv6_src/IPv6_dst",
                self.df.columns
            )

        # Common amplification service ports
        amplification_ports = [53, 123, 161, 1900, 5353]  # DNS, NTP, SNMP, SSDP, mDNS

        # Filter to traffic involving amplification-prone services
        df_amp = self.df.filter(
            pl.col("UDP_dport").is_in(amplification_ports) |
            pl.col("UDP_sport").is_in(amplification_ports)
        )

        if df_amp.is_empty():
            return pl.DataFrame()

        # Prepare data
        df_prepared = df_amp.with_columns([
            pl.col(src_ip_col).alias("src_ip"),
            pl.col(dst_ip_col).alias("dst_ip"),
            safe_cast_to_int(pl.col("UDP_sport")).alias("src_port"),
            safe_cast_to_int(pl.col("UDP_dport")).alias("dst_port"),
            safe_cast_to_int(pl.col("IP_len")).alias("packet_size"),
        ])

        # Identify requests (to service port) and responses (from service port)
        requests = df_prepared.filter(
            pl.col("dst_port").is_in(amplification_ports)
        ).group_by(["dst_ip", "dst_port", "src_ip"]).agg([
            pl.count().alias("request_count"),
            pl.col("packet_size").mean().alias("avg_request_size"),
        ]).rename({
            "dst_ip": "reflector_ip",
            "dst_port": "service_port",
            "src_ip": "client_ip",
        })

        responses = df_prepared.filter(
            pl.col("src_port").is_in(amplification_ports)
        ).group_by(["src_ip", "src_port", "dst_ip"]).agg([
            pl.count().alias("response_count"),
            pl.col("packet_size").mean().alias("avg_response_size"),
        ]).rename({
            "src_ip": "reflector_ip",
            "src_port": "service_port",
            "dst_ip": "client_ip",
        })

        # Match requests with responses
        matched = requests.join(
            responses,
            on=["reflector_ip", "service_port", "client_ip"],
            how="inner"
        )

        if matched.is_empty():
            return pl.DataFrame()

        # Calculate amplification ratio and filter
        result = matched.with_columns([
            (pl.col("avg_response_size") / pl.col("avg_request_size")).alias("amplification_ratio")
        ]).filter(
            pl.col("amplification_ratio") >= min_amplification_ratio
        ).select([
            pl.col("client_ip").alias("victim_ip"),
            pl.col("reflector_ip"),
            pl.col("service_port"),
            pl.col("request_count"),
            pl.col("avg_request_size"),
            pl.col("avg_response_size"),
            pl.col("amplification_ratio"),
        ]).sort("amplification_ratio", descending=True)

        return result

    def identify_udp_scan(self, threshold: int = 100) -> pl.DataFrame:
        """
        Identify UDP port scanning activity.

        Args:
            threshold: Number of unique ports contacted by single source

        Returns:
            pl.DataFrame: Suspected UDP scanners with columns:
                - src_ip: Source IP address
                - unique_ports_scanned: Number of unique ports contacted
                - unique_destinations: Number of unique destination IPs
                - total_packets: Total packets sent
                - first_seen: First scan packet timestamp
                - last_seen: Last scan packet timestamp
                - scan_duration_seconds: Duration of scanning activity

        Raises:
            MissingColumnError: If required columns are missing
            InvalidThresholdError: If threshold is not positive
        """
        if threshold <= 0:
            raise InvalidThresholdError(threshold, "threshold must be positive")

        required_cols = ["UDP_dport", "timestamp"]
        validate_dataframe_columns(self.df, required_cols)

        # Get IP columns
        src_ip_col = "IP_src" if has_column(self.df, "IP_src") else "IPv6_src"
        dst_ip_col = "IP_dst" if has_column(self.df, "IP_dst") else "IPv6_dst"

        if not has_column(self.df, src_ip_col):
            raise MissingColumnError("IP_src or IPv6_src", self.df.columns)

        # Prepare DataFrame
        df_prepared = self.df.with_columns([
            pl.col(src_ip_col).alias("src_ip"),
        ])

        # Group by source IP and count unique ports
        scan_candidates = df_prepared.group_by("src_ip").agg([
            safe_cast_to_int(pl.col("UDP_dport")).n_unique().alias("unique_ports_scanned"),
            pl.count().alias("total_packets"),
            pl.col("timestamp").min().alias("first_seen"),
            pl.col("timestamp").max().alias("last_seen"),
        ])

        # Add additional metrics if destination IP is available
        if has_column(self.df, dst_ip_col):
            df_prepared = df_prepared.with_columns([
                pl.col(dst_ip_col).alias("dst_ip"),
            ])
            scan_candidates = df_prepared.group_by("src_ip").agg([
                safe_cast_to_int(pl.col("UDP_dport")).n_unique().alias("unique_ports_scanned"),
                pl.col("dst_ip").n_unique().alias("unique_destinations"),
                pl.count().alias("total_packets"),
                pl.col("timestamp").min().alias("first_seen"),
                pl.col("timestamp").max().alias("last_seen"),
            ])

        # Calculate scan duration
        scan_candidates = scan_candidates.with_columns([
            (
                (pl.col("last_seen") - pl.col("first_seen")).dt.total_seconds()
            ).alias("scan_duration_seconds")
        ])

        # Filter sources exceeding threshold
        result = scan_candidates.filter(
            pl.col("unique_ports_scanned") >= threshold
        ).sort("unique_ports_scanned", descending=True)

        return result
