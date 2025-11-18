"""TCP protocol analyzer for network traffic analysis."""

import polars as pl

from ..errors import EmptyDataFrameError, MissingColumnError
from ..utils import has_column, parse_time_window


class TcpAnalyzer:
    """
    Analyzer for TCP protocol traffic.

    Filters a DataFrame to only TCP-related packets and provides
    TCP-specific analysis methods.

    Args:
        df: Polars DataFrame containing network packet data
    """

    # TCP Protocol Constants
    TCP_PROTOCOL_NUMBER = 6

    # Common TCP ports
    COMMON_PORTS = {
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
    TCP_FLAGS = {
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
        self.df = df.filter(
            pl.col("IP_proto").cast(pl.Int64, strict=False) == self.TCP_PROTOCOL_NUMBER
        )

        if len(self.df) == 0:
            raise EmptyDataFrameError("No TCP packets found in DataFrame")

        # Store metadata for debugging
        self._packet_count = len(self.df)
        self._has_tcp_columns = any("TCP" in col for col in self.df.columns)

    def __repr__(self) -> str:
        """Technical representation for debugging."""
        return f"TcpAnalyzer(packets={self._packet_count}, shape={self.df.shape}, has_tcp_cols={self._has_tcp_columns})"

    def __str__(self) -> str:
        """Human-readable string representation."""
        date_range = ""
        if "timestamp" in self.df.columns and len(self.df) > 0:
            min_ts = self.df["timestamp"].min()
            max_ts = self.df["timestamp"].max()
            date_range = f", {min_ts} to {max_ts}"
        return f"TCP Analyzer: {self._packet_count} packets{date_range}"

    def __eq__(self, other) -> bool:
        """Compare two TcpAnalyzer instances."""
        if not isinstance(other, TcpAnalyzer):
            return False
        return self.df.frame_equal(other.df)

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
            pl.col("TCP_flags").str.contains("S")
            & pl.col("TCP_flags").str.contains("A")
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
            .with_columns((pl.col("last_fin") - pl.col("first_syn")).alias("duration"))
            .select("duration")
        )

        if len(durations) == 0:
            return {}

        return {
            "min": float(durations["duration"].min()),
            "max": float(durations["duration"].max()),
            "mean": float(durations["duration"].mean()),
            "median": float(durations["duration"].median()),
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
            pl.col("TCP_flags").str.contains("S")
            & ~pl.col("TCP_flags").str.contains("A")
        ).height

        # Count SYN-ACK packets (both S and A)
        syn_ack_count = self.df.filter(
            pl.col("TCP_flags").str.contains("S")
            & pl.col("TCP_flags").str.contains("A")
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
                    "percentage": (
                        (count / total_packets * 100) if total_packets > 0 else 0.0
                    ),
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
                    pl.col("TCP_flags").str.concat(" ").alias("flag_sequence"),
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
        window_sizes = self.df.select(
            pl.col("TCP_window").cast(pl.Int64, strict=False)
        ).filter(pl.col("TCP_window").is_not_null())

        if len(window_sizes) == 0:
            return {}

        return {
            "min": int(window_sizes["TCP_window"].min()),
            "max": int(window_sizes["TCP_window"].max()),
            "mean": float(window_sizes["TCP_window"].mean()),
            "median": float(window_sizes["TCP_window"].median()),
            "std": float(window_sizes["TCP_window"].std()),
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
                    pl.col("IP_len")
                    .cast(pl.Int64, strict=False)
                    .sum()
                    .alias("total_bytes"),
                    pl.col("timestamp").min().alias("start_time"),
                    pl.col("timestamp").max().alias("end_time"),
                ]
            )
            .with_columns((pl.col("end_time") - pl.col("start_time")).alias("duration"))
            .with_columns(
                (pl.col("total_bytes") / pl.col("duration")).alias("bytes_per_sec")
            )
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
            self.df.filter(
                (pl.col("TCP_dport") >= 49152) & (pl.col("TCP_dport") < 65536)
            )
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
