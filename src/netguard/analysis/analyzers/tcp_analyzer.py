"""TCP protocol analyzer for network traffic analysis."""

from typing import ClassVar, Optional, Union

import polars as pl

from netguard.analysis.analyzers.tcp_config import (
    PortScanConfig,
    ScanProfile,
    create_custom_config,
    get_scan_config,
)
from netguard.analysis.base_analyzer import BaseAnalyzer
from netguard.analysis.utils import has_column, parse_time_window
from netguard.core.errors import EmptyDataFrameError, MissingColumnError


class TcpAnalyzer(BaseAnalyzer):
    """
    Analyzer for TCP protocol traffic.

    Filters a DataFrame to only TCP-related packets and provides
    TCP-specific analysis methods.

    Args:
        df: Polars DataFrame containing network packet data
    """

    # TCP Protocol Constants
    TCP_PROTOCOL_NUMBER = 6

    # Port scanning detection
    DEFAULT_PORT_SCAN_THRESHOLD = 20

    # Common TCP ports
    COMMON_PORTS: ClassVar[dict[int, str]] = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-ALT",
    }

    # TCP Flag definitions
    TCP_FLAGS: ClassVar[dict[str, str]] = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }

    # Port ranges
    WELL_KNOWN_PORTS = range(0, 1024)
    REGISTERED_PORTS = range(1024, 49152)
    EPHEMERAL_PORTS = range(49152, 65536)

    def __init__(self, df: pl.DataFrame):
        """
        Initialize TCP analyzer and filter to TCP traffic only.

        Args:
            df: Polars DataFrame containing network packet data

        Raises:
            MissingColumnError: If required column 'IP_proto' is missing
            EmptyDataFrameError: If DataFrame is empty after filtering to TCP
        """
        if df is None or len(df) == 0:
            raise EmptyDataFrameError("Input DataFrame is empty")

        # Check for required column
        if not has_column(df, "IP_proto"):
            raise MissingColumnError("IP_proto", df.columns)

        # Filter to TCP traffic only (IP protocol 6)
        filtered_df = df.filter(
            pl.col("IP_proto").cast(pl.Int64, strict=False) == self.TCP_PROTOCOL_NUMBER
        )

        if len(filtered_df) == 0:
            raise EmptyDataFrameError("No TCP packets found in DataFrame")

        # Initialize base class with filtered data
        super().__init__(filtered_df)

        # Store additional metadata
        self._has_tcp_columns = any("TCP" in col for col in self.df.columns)

    # ============================================================================
    # CONNECTION ANALYSIS METHODS
    # ============================================================================

    def get_connection_success_ratio(self) -> float:
        """
        Calculate the ratio of successful connections (SYN-ACK) vs failed (RST).

        Returns:
            float: Success ratio (SYN-ACK / (SYN-ACK + RST)). Returns 0.0 if no
                   relevant packets exist.

        Raises:
            MissingColumnError: If TCP_flags column is missing

        Note:
            SYN-ACK is represented by "SA" in TCP_flags
        """
        if not has_column(self.df, "TCP_flags"):
            raise MissingColumnError("TCP_flags", self.df.columns)

        # Count SYN-ACK packets (contains both S and A)
        syn_ack_count = self.df.filter(
            pl.col("TCP_flags").str.contains("S") & pl.col("TCP_flags").str.contains("A")
        ).height

        # Count RST packets
        rst_count = self.df.filter(pl.col("TCP_flags").str.contains("R")).height

        total = syn_ack_count + rst_count
        if total == 0:
            return 0.0

        return syn_ack_count / total

    def detect_incomplete_connections(self) -> pl.DataFrame:
        """
        Detect TCP connections that started (SYN) but never finished (FIN).

        Returns:
            pl.DataFrame: Connections with SYN but no FIN, grouped by 5-tuple
                         with columns: src_ip, dst_ip, src_port, dst_port, syn_count, fin_count

        Raises:
            MissingColumnError: If required columns are missing

        Note:
            Requires columns: IP_src, IP_dst, TCP_sport, TCP_dport, TCP_flags
        """
        required_cols = ["IP_src", "IP_dst", "TCP_sport", "TCP_dport", "TCP_flags"]
        for col in required_cols:
            if not has_column(self.df, col):
                raise MissingColumnError(col, self.df.columns)

        # Group by 5-tuple and count SYN and FIN flags
        result = (
            self.df.group_by(["IP_src", "IP_dst", "TCP_sport", "TCP_dport"])
            .agg(
                [
                    pl.col("TCP_flags")
                    .filter(pl.col("TCP_flags").str.contains("S"))
                    .count()
                    .alias("syn_count"),
                    pl.col("TCP_flags")
                    .filter(pl.col("TCP_flags").str.contains("F"))
                    .count()
                    .alias("fin_count"),
                ]
            )
            .filter(pl.col("syn_count") > 0, pl.col("fin_count") == 0)
            .sort("syn_count", descending=True)
        )

        return result

    def get_connection_duration_stats(self) -> dict:
        """
        Get statistics on connection duration (SYN to FIN time).

        Returns:
            dict: Statistics with keys: min, max, mean, median (in seconds)
                  Returns empty dict if insufficient data

        Raises:
            MissingColumnError: If required columns are missing

        Note:
            Requires columns: IP_src, IP_dst, TCP_sport, TCP_dport, TCP_flags, timestamp
        """
        required_cols = [
            "IP_src",
            "IP_dst",
            "TCP_sport",
            "TCP_dport",
            "TCP_flags",
            "timestamp",
        ]
        for col in required_cols:
            if not has_column(self.df, col):
                raise MissingColumnError(col, self.df.columns)

        # Get first SYN and last FIN for each connection
        durations = (
            self.df.group_by(["IP_src", "IP_dst", "TCP_sport", "TCP_dport"])
            .agg(
                [
                    pl.col("timestamp")
                    .filter(pl.col("TCP_flags").str.contains("S"))
                    .min()
                    .alias("first_syn"),
                    pl.col("timestamp")
                    .filter(pl.col("TCP_flags").str.contains("F"))
                    .max()
                    .alias("last_fin"),
                ]
            )
            .filter(pl.col("first_syn").is_not_null(), pl.col("last_fin").is_not_null())
            .with_columns(
                (pl.col("last_fin") - pl.col("first_syn"))
                .dt.total_seconds()
                .alias("duration_seconds")
            )
            .select("duration_seconds")
        )

        if len(durations) == 0:
            return {}

        # Get statistics - values are floats (seconds) or None
        stats = durations.select(
            pl.col("duration_seconds").min().alias("min"),
            pl.col("duration_seconds").max().alias("max"),
            pl.col("duration_seconds").mean().alias("mean"),
            pl.col("duration_seconds").median().alias("median"),
        ).row(0)

        return {
            "min": stats[0] if stats[0] is not None else 0.0,
            "max": stats[1] if stats[1] is not None else 0.0,
            "mean": stats[2] if stats[2] is not None else 0.0,
            "median": stats[3] if stats[3] is not None else 0.0,
        }

    def identify_long_lived_connections(self, threshold: str) -> pl.DataFrame:
        """
        Identify connections that last longer than threshold.

        Args:
            threshold: Duration threshold (e.g., "5m", "1h")

        Returns:
            pl.DataFrame: Connections exceeding threshold with duration column

        Raises:
            InvalidTimeWindowError: If threshold format is invalid
            MissingColumnError: If required columns are missing

        Example:
            >>> analyzer.identify_long_lived_connections("5m")
        """
        required_cols = ["IP_src", "IP_dst", "TCP_sport", "TCP_dport", "timestamp"]
        for col in required_cols:
            if not has_column(self.df, col):
                raise MissingColumnError(col, self.df.columns)

        # Parse threshold
        threshold_td = parse_time_window(threshold)
        threshold_seconds = threshold_td.total_seconds()

        # Calculate connection durations
        durations = (
            self.df.group_by(["IP_src", "IP_dst", "TCP_sport", "TCP_dport"])
            .agg(
                [
                    pl.col("timestamp").min().alias("start_time"),
                    pl.col("timestamp").max().alias("end_time"),
                ]
            )
            .with_columns((pl.col("end_time") - pl.col("start_time")).alias("duration"))
            .filter(pl.col("duration") > threshold_seconds)
            .sort("duration", descending=True)
        )

        return durations

    def identify_short_lived_connections(self, threshold: str) -> pl.DataFrame:
        """
        Identify very brief connections (potential scanning).

        Args:
            threshold: Duration threshold (e.g., "100ms", "1s")

        Returns:
            pl.DataFrame: Connections below threshold with duration column

        Raises:
            InvalidTimeWindowError: If threshold format is invalid
            MissingColumnError: If required columns are missing

        Example:
            >>> analyzer.identify_short_lived_connections("100ms")
        """
        required_cols = ["IP_src", "IP_dst", "TCP_sport", "TCP_dport", "timestamp"]
        for col in required_cols:
            if not has_column(self.df, col):
                raise MissingColumnError(col, self.df.columns)

        # Parse threshold
        threshold_td = parse_time_window(threshold)
        threshold_seconds = threshold_td.total_seconds()

        # Calculate connection durations
        durations = (
            self.df.group_by(["IP_src", "IP_dst", "TCP_sport", "TCP_dport"])
            .agg(
                [
                    pl.col("timestamp").min().alias("start_time"),
                    pl.col("timestamp").max().alias("end_time"),
                ]
            )
            .with_columns((pl.col("end_time") - pl.col("start_time")).alias("duration"))
            .filter(pl.col("duration") < threshold_seconds)
            .sort("duration")
        )

        return durations

    def get_handshake_analysis(self) -> dict:
        """
        Analyze TCP handshakes (complete vs incomplete).

        Returns:
            dict: Handshake statistics with keys:
                  - total_syn: Total SYN packets
                  - total_syn_ack: Total SYN-ACK packets
                  - total_ack: Total ACK-only packets
                  - complete_handshakes: Estimated complete 3-way handshakes
                  - incomplete_handshakes: Estimated incomplete handshakes

        Raises:
            MissingColumnError: If TCP_flags column is missing

        Note:
            This is an estimation based on flag counts, not true connection tracking
        """
        if not has_column(self.df, "TCP_flags"):
            raise MissingColumnError("TCP_flags", self.df.columns)

        # Count SYN packets (S but not A)
        syn_count = self.df.filter(
            pl.col("TCP_flags").str.contains("S") & ~pl.col("TCP_flags").str.contains("A")
        ).height

        # Count SYN-ACK packets (both S and A)
        syn_ack_count = self.df.filter(
            pl.col("TCP_flags").str.contains("S") & pl.col("TCP_flags").str.contains("A")
        ).height

        # Count ACK-only packets (A but not S, R, F)
        ack_only_count = self.df.filter(
            pl.col("TCP_flags").str.contains("A")
            & ~pl.col("TCP_flags").str.contains("S")
            & ~pl.col("TCP_flags").str.contains("R")
            & ~pl.col("TCP_flags").str.contains("F")
        ).height

        # Estimate complete handshakes (minimum of SYN, SYN-ACK, ACK)
        complete = min(syn_count, syn_ack_count, ack_only_count)
        incomplete = syn_count - complete

        return {
            "total_syn": syn_count,
            "total_syn_ack": syn_ack_count,
            "total_ack": ack_only_count,
            "complete_handshakes": complete,
            "incomplete_handshakes": incomplete,
        }

    # ============================================================================
    # FLAG ANALYSIS METHODS
    # ============================================================================

    def get_flag_distribution(self) -> pl.DataFrame:
        """
        Get distribution of TCP flags across all packets.

        Returns:
            pl.DataFrame: Flag counts with columns: flag, count, percentage

        Raises:
            MissingColumnError: If TCP_flags column is missing

        Note:
            Counts individual flag occurrences (packets can have multiple flags)
        """
        if not has_column(self.df, "TCP_flags"):
            raise MissingColumnError("TCP_flags", self.df.columns)

        total_packets = len(self.df)

        # Count each flag type
        flag_counts = []
        for flag_char, flag_name in self.TCP_FLAGS.items():
            count = self.df.filter(pl.col("TCP_flags").str.contains(flag_char)).height
            flag_counts.append(
                {
                    "flag": flag_name,
                    "flag_char": flag_char,
                    "count": count,
                    "percentage": ((count / total_packets * 100) if total_packets > 0 else 0.0),
                }
            )

        return pl.DataFrame(flag_counts).sort("count", descending=True)

    def get_syn_count(self) -> int:
        """
        Get total count of SYN packets.

        Returns:
            int: SYN packet count

        Raises:
            MissingColumnError: If TCP_flags column is missing
        """
        if not has_column(self.df, "TCP_flags"):
            raise MissingColumnError("TCP_flags", self.df.columns)

        return self.df.filter(pl.col("TCP_flags").str.contains("S")).height

    def get_rst_count(self) -> int:
        """
        Get total count of RST packets.

        Returns:
            int: RST packet count

        Raises:
            MissingColumnError: If TCP_flags column is missing
        """
        if not has_column(self.df, "TCP_flags"):
            raise MissingColumnError("TCP_flags", self.df.columns)

        return self.df.filter(pl.col("TCP_flags").str.contains("R")).height

    def get_fin_count(self) -> int:
        """
        Get total count of FIN packets.

        Returns:
            int: FIN packet count

        Raises:
            MissingColumnError: If TCP_flags column is missing
        """
        if not has_column(self.df, "TCP_flags"):
            raise MissingColumnError("TCP_flags", self.df.columns)

        return self.df.filter(pl.col("TCP_flags").str.contains("F")).height

    def get_ack_count(self) -> int:
        """
        Get total count of ACK packets.

        Returns:
            int: ACK packet count

        Raises:
            MissingColumnError: If TCP_flags column is missing
        """
        if not has_column(self.df, "TCP_flags"):
            raise MissingColumnError("TCP_flags", self.df.columns)

        return self.df.filter(pl.col("TCP_flags").str.contains("A")).height

    def get_psh_count(self) -> int:
        """
        Get total count of PSH packets.

        Returns:
            int: PSH packet count

        Raises:
            MissingColumnError: If TCP_flags column is missing
        """
        if not has_column(self.df, "TCP_flags"):
            raise MissingColumnError("TCP_flags", self.df.columns)

        return self.df.filter(pl.col("TCP_flags").str.contains("P")).height

    def analyze_flag_sequences(self) -> pl.DataFrame:
        """
        Analyze common TCP flag sequences in connections.

        Returns:
            pl.DataFrame: Common flag sequences with columns:
                         - src_ip, dst_ip, src_port, dst_port
                         - flag_sequence: Space-separated flag sequence
                         - packet_count: Number of packets in connection

        Raises:
            MissingColumnError: If required columns are missing

        Note:
            Requires columns: IP_src, IP_dst, TCP_sport, TCP_dport, TCP_flags, timestamp
        """
        required_cols = [
            "IP_src",
            "IP_dst",
            "TCP_sport",
            "TCP_dport",
            "TCP_flags",
            "timestamp",
        ]
        for col in required_cols:
            if not has_column(self.df, col):
                raise MissingColumnError(col, self.df.columns)

        # Group by connection and create flag sequence
        result = (
            self.df.sort("timestamp")
            .group_by(["IP_src", "IP_dst", "TCP_sport", "TCP_dport"])
            .agg(
                [
                    pl.col("TCP_flags").str.join(" ").alias("flag_sequence"),
                    pl.col("TCP_flags").count().alias("packet_count"),
                ]
            )
            .sort("packet_count", descending=True)
        )

        return result

    # ============================================================================
    # PERFORMANCE METHODS
    # ============================================================================

    def get_window_size_stats(self) -> dict:
        """
        Analyze TCP window size statistics.

        Returns:
            dict: Window size statistics with keys: min, max, mean, median, std

        Raises:
            MissingColumnError: If TCP_window column is missing

        Note:
            Returns empty dict if no valid window sizes exist
        """
        if not has_column(self.df, "TCP_window"):
            raise MissingColumnError("TCP_window", self.df.columns)

        # Filter out null values and calculate stats
        window_sizes = self.df.select(pl.col("TCP_window").cast(pl.Int64, strict=False)).filter(
            pl.col("TCP_window").is_not_null()
        )

        if len(window_sizes) == 0:
            return {}

        # Get all statistics in one query
        stats = window_sizes.select(
            pl.col("TCP_window").min().alias("min"),
            pl.col("TCP_window").max().alias("max"),
            pl.col("TCP_window").mean().alias("mean"),
            pl.col("TCP_window").median().alias("median"),
            pl.col("TCP_window").std().alias("std"),
        ).row(0)

        return {
            "min": int(stats[0]) if stats[0] is not None else 0,
            "max": int(stats[1]) if stats[1] is not None else 0,
            "mean": float(stats[2]) if stats[2] is not None else 0.0,
            "median": float(stats[3]) if stats[3] is not None else 0.0,
            "std": float(stats[4]) if stats[4] is not None else 0.0,
        }

    def detect_retransmissions(self) -> pl.DataFrame:
        """
        Identify retransmitted TCP packets.

        Returns:
            pl.DataFrame: Suspected retransmissions with duplicate sequence numbers

        Raises:
            MissingColumnError: If required columns are missing

        Note:
            Requires columns: IP_src, IP_dst, TCP_sport, TCP_dport, TCP_seq
            Detects duplicate sequence numbers within same connection
        """
        required_cols = ["IP_src", "IP_dst", "TCP_sport", "TCP_dport", "TCP_seq"]
        for col in required_cols:
            if not has_column(self.df, col):
                raise MissingColumnError(col, self.df.columns)

        # Find duplicate sequence numbers per connection
        result = (
            self.df.group_by(["IP_src", "IP_dst", "TCP_sport", "TCP_dport", "TCP_seq"])
            .agg(pl.count().alias("seq_count"))
            .filter(pl.col("seq_count") > 1)
            .sort("seq_count", descending=True)
        )

        return result

    def get_throughput_by_connection(self) -> pl.DataFrame:
        """
        Calculate bytes/sec throughput per connection.

        Returns:
            pl.DataFrame: Connection throughput with columns:
                         - src_ip, dst_ip, src_port, dst_port
                         - total_bytes, duration, bytes_per_sec

        Raises:
            MissingColumnError: If required columns are missing

        Note:
            Requires columns: IP_src, IP_dst, TCP_sport, TCP_dport, IP_len, timestamp
        """
        required_cols = [
            "IP_src",
            "IP_dst",
            "TCP_sport",
            "TCP_dport",
            "IP_len",
            "timestamp",
        ]
        for col in required_cols:
            if not has_column(self.df, col):
                raise MissingColumnError(col, self.df.columns)

        # Calculate throughput per connection
        result = (
            self.df.group_by(["IP_src", "IP_dst", "TCP_sport", "TCP_dport"])
            .agg(
                [
                    pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("total_bytes"),
                    pl.col("timestamp").min().alias("start_time"),
                    pl.col("timestamp").max().alias("end_time"),
                ]
            )
            .with_columns((pl.col("end_time") - pl.col("start_time")).alias("duration"))
            # ✅ FIX: Convert duration to seconds (float) before dividing
            .with_columns(
                (pl.col("total_bytes") / pl.col("duration").dt.total_seconds()).alias(
                    "bytes_per_sec"
                )
            )
            # Move filter UP to avoid dividing by zero if duration is 0
            .filter(pl.col("duration") > 0)
            .sort("bytes_per_sec", descending=True)
        )

        return result

    # ============================================================================
    # PORT METHODS
    # ============================================================================

    def get_most_used_ports(self, n: int = 10) -> pl.DataFrame:
        """
        Get top N most used TCP destination ports.

        Args:
            n: Number of top ports to return (default: 10)

        Returns:
            pl.DataFrame: Top ports with columns: port, count, service_name, percentage

        Raises:
            MissingColumnError: If TCP_dport column is missing
        """
        if not has_column(self.df, "TCP_dport"):
            raise MissingColumnError("TCP_dport", self.df.columns)

        total_packets = len(self.df)

        # Count destination ports
        result = (
            self.df.group_by("TCP_dport")
            .agg(pl.count().alias("count"))
            .sort("count", descending=True)
            .head(n)
            .with_columns(
                [
                    pl.col("TCP_dport")
                    .map_elements(
                        lambda p: self.COMMON_PORTS.get(p, "Unknown"),
                        return_dtype=pl.Utf8,
                    )
                    .alias("service_name"),
                    (pl.col("count") / total_packets * 100).alias("percentage"),
                ]
            )
        )

        return result

    def detect_non_standard_ports(self) -> pl.DataFrame:
        """
        Detect common services running on non-standard ports.

        Returns:
            pl.DataFrame: Suspicious port usage

        Raises:
            MissingColumnError: If TCP_dport column is missing

        Note:
            Currently detects ephemeral port usage (49152-65535)
            which may indicate port forwarding or non-standard configurations
        """
        if not has_column(self.df, "TCP_dport"):
            raise MissingColumnError("TCP_dport", self.df.columns)

        # Find traffic on ephemeral ports with high volume
        result = (
            self.df.filter((pl.col("TCP_dport") >= 49152) & (pl.col("TCP_dport") < 65536))
            .group_by(["IP_dst", "TCP_dport"])
            .agg(pl.count().alias("packet_count"))
            .filter(pl.col("packet_count") > 100)  # Threshold for "suspicious"
            .sort("packet_count", descending=True)
        )

        return result

    def get_ephemeral_vs_wellknown_ratio(self) -> dict:
        """
        Calculate ratio of ephemeral vs well-known port usage.

        Returns:
            dict: Port type distribution with keys:
                  - well_known: Count of well-known port packets (0-1023)
                  - registered: Count of registered port packets (1024-49151)
                  - ephemeral: Count of ephemeral port packets (49152-65535)
                  - total: Total packets
                  - ratios: Dict with percentage for each type

        Raises:
            MissingColumnError: If TCP_dport column is missing
        """
        if not has_column(self.df, "TCP_dport"):
            raise MissingColumnError("TCP_dport", self.df.columns)

        total = len(self.df)

        # Count each port category
        well_known = self.df.filter(
            (pl.col("TCP_dport") >= 0) & (pl.col("TCP_dport") < 1024)
        ).height

        registered = self.df.filter(
            (pl.col("TCP_dport") >= 1024) & (pl.col("TCP_dport") < 49152)
        ).height

        ephemeral = self.df.filter(
            (pl.col("TCP_dport") >= 49152) & (pl.col("TCP_dport") < 65536)
        ).height

        return {
            "well_known": well_known,
            "registered": registered,
            "ephemeral": ephemeral,
            "total": total,
            "ratios": {
                "well_known_pct": (well_known / total * 100) if total > 0 else 0.0,
                "registered_pct": (registered / total * 100) if total > 0 else 0.0,
                "ephemeral_pct": (ephemeral / total * 100) if total > 0 else 0.0,
            },
        }

    ##################################################
    ## PORT SCANNING METHODS##
    #################################################
    def detect_port_scanning(
        self,
        config: Union[PortScanConfig, ScanProfile, None] = None,
        threshold: Optional[int] = None,
        time_window: Optional[str] = None,
    ) -> pl.DataFrame:
        """
        Detect TCP port scanning activity (many ports contacted on same destination).

        Port scanning is reconnaissance where an attacker probes multiple ports
        on a target to identify open services. Common tools: nmap, masscan.

        Args:
            config: Port scan configuration profile or custom PortScanConfig
            threshold: Override threshold (number of unique ports)
            time_window: Override time window (e.g., "1m", "5m", "30m")

        Returns:
            pl.DataFrame with columns:
                - scanner_ip: Source IP performing the scan
                - target_ip: Destination IP being scanned
                - window_start: Start of detection window
                - unique_ports: Number of unique ports contacted
                - total_packets: Total packets sent in window
                - scan_start: Timestamp of first packet
                - scan_end: Timestamp of last packet
                - scan_duration: Duration of scan
                - severity: Severity level (critical/high/medium/low)
                - ports_contacted: List of ports contacted

        Examples:
            >>> # Use predefined profile
            >>> from .tcp_config import ScanProfile
            >>> results = analyzer.detect_port_scanning(config=ScanProfile.AGGRESSIVE)

            >>> # Custom configuration
            >>> from .tcp_config import create_custom_config
            >>> custom = create_custom_config(threshold=25, time_window="10m")
            >>> results = analyzer.detect_port_scanning(config=custom)

            >>> # Direct parameters (backward compatible)
            >>> results = analyzer.detect_port_scanning(threshold=30, time_window="5m")

        Detection Logic:
            1. Groups packets by (source_ip, dest_ip) within time windows
            2. Counts unique destination ports per group
            3. Flags groups exceeding threshold as potential scans
            4. Adds severity based on number of ports scanned

        Note:
            Primarily detects TCP SYN scans (most common). For comprehensive
            multiprotocol scanning, see AnomalyAnalyzer.detect_coordinated_scan()
        """
        # Step 1: Resolve configuration
        if isinstance(config, ScanProfile):
            scan_config = get_scan_config(config)
        elif isinstance(config, PortScanConfig):
            scan_config = config
        elif threshold is not None or time_window is not None:
            scan_config = create_custom_config(
                threshold=threshold or self.DEFAULT_PORT_SCAN_THRESHOLD,
                time_window=time_window or "5m",
                description="Custom port scan configuration",
            )
        else:
            # Use balanced profile as default
            scan_config = get_scan_config(ScanProfile.BALANCED)

        # Step 2: Validate required columns
        required = ["timestamp", "IP_src", "IP_dst", "TCP_dport"]
        missing = [col for col in required if not has_column(self.df, col)]
        if missing:
            raise MissingColumnError(
                f"Missing required columns for port scan detection: {missing}",
                self.df.columns,
            )

        # Step 3: Detect port scanning using Polars
        try:
            result = (
                self.df
                # Ensure timestamp is datetime type
                .with_columns([pl.col("timestamp").cast(pl.Datetime)])
                # Sort by timestamp (required for group_by_dynamic)
                .sort("timestamp")
                # Group by time windows and (src_ip, dst_ip) pairs
                .group_by_dynamic(
                    "timestamp", every=scan_config.time_window, group_by=["IP_src", "IP_dst"]
                )
                # Calculate metrics per group
                .agg(
                    [
                        pl.col("TCP_dport").n_unique().alias("unique_ports"),
                        pl.col("TCP_dport").alias("ports_contacted"),
                        pl.count().alias("total_packets"),
                        pl.col("timestamp").min().alias("scan_start"),
                        pl.col("timestamp").max().alias("scan_end"),
                    ]
                )
                # Filter only groups exceeding threshold
                .filter(pl.col("unique_ports") > scan_config.threshold)
                # Add computed columns
                .with_columns(
                    [
                        # Calculate scan duration
                        (pl.col("scan_end") - pl.col("scan_start")).alias("scan_duration"),
                        # Assign severity based on port count
                        pl.when(pl.col("unique_ports") > 50)
                        .then(pl.lit("critical"))
                        .when(pl.col("unique_ports") > 30)
                        .then(pl.lit("high"))
                        .when(pl.col("unique_ports") > scan_config.threshold)
                        .then(pl.lit("medium"))
                        .otherwise(pl.lit("low"))
                        .alias("severity"),
                    ]
                )
                # Sort by most suspicious first
                .sort("unique_ports", descending=True)
                # Rename columns for clarity
                .select(
                    [
                        pl.col("IP_src").alias("scanner_ip"),
                        pl.col("IP_dst").alias("target_ip"),
                        pl.col("timestamp").alias("window_start"),
                        "unique_ports",
                        "total_packets",
                        "scan_start",
                        "scan_end",
                        "scan_duration",
                        "severity",
                        "ports_contacted",
                    ]
                )
            )

            # Log detection results
            if len(result) == 0:
                print(
                    f"✓ No port scans detected "
                    f"(threshold={scan_config.threshold}, "
                    f"window={scan_config.time_window}, "
                    f"sensitivity={scan_config.sensitivity})"
                )
            else:
                print(
                    f"⚠ Detected {len(result)} potential port scan(s) "
                    f"using {scan_config.sensitivity} sensitivity profile"
                )
                # Show summary of findings
                critical = result.filter(pl.col("severity") == "critical")
                high = result.filter(pl.col("severity") == "high")
                if len(critical) > 0:
                    print(f"  - {len(critical)} CRITICAL (>50 ports)")
                if len(high) > 0:
                    print(f"  - {len(high)} HIGH (30-50 ports)")

            return result

        except Exception as e:
            raise Exception(f"Error detecting port scans with config {scan_config}: {e!s}") from e
