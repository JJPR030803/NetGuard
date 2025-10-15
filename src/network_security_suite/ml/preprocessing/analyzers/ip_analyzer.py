"""IP protocol analyzer for network traffic analysis."""

import polars as pl
from ..utils import is_private_ip, is_public_ip, get_protocol_name, validate_dataframe_columns
from ..errors import EmptyDataFrameError, InvalidThresholdError, InvalidIPAddressError
import ipaddress


class IpAnalyzer:
    """
    Analyzer for IP layer traffic.

    Keeps all IP traffic (doesn't filter) and provides IP-specific analysis methods.

    Args:
        df: Polars DataFrame containing network traffic data
    """

    # IP Protocol Numbers
    PROTOCOL_NUMBERS = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
        89: "OSPF",
    }

    # IP Flags
    IP_FLAGS = {
        "DF": "Don't Fragment",
        "MF": "More Fragments",
    }

    # DSCP Classes (for QoS)
    DSCP_CLASSES = {
        0: "BE",      # Best Effort
        8: "CS1",     # Class Selector 1
        10: "AF11",   # Assured Forwarding 11
        46: "EF",     # Expedited Forwarding
    }

    def __init__(self, df: pl.DataFrame):
        """Initialize IP analyzer (keeps all IP traffic)."""
        if df.is_empty():
            raise EmptyDataFrameError("IpAnalyzer initialization")

        self.df = df

        # Store metadata for debugging
        self._packet_count = len(self.df)
        self._has_ip_columns = any("IP" in col for col in self.df.columns)

        # Prepare unified IP columns for easier analysis
        self._prepare_unified_ips()

    def _prepare_unified_ips(self) -> None:
        """Prepare unified source and destination IP columns."""
        existing_cols = self.df.columns
        src_ip_cols = [c for c in ["IP_src", "IPv6_src"] if c in existing_cols]
        dst_ip_cols = [c for c in ["IP_dst", "IPv6_dst"] if c in existing_cols]

        if src_ip_cols and dst_ip_cols:
            self.df = self.df.with_columns([
                pl.coalesce(src_ip_cols).alias("_source_ip"),
                pl.coalesce(dst_ip_cols).alias("_destination_ip")
            ])

    def __repr__(self) -> str:
        """Technical representation for debugging."""
        return (
            f"IpAnalyzer(packets={self._packet_count}, "
            f"shape={self.df.shape}, has_ip_cols={self._has_ip_columns})"
        )

    def __str__(self) -> str:
        """Human-readable string representation."""
        date_range = ""
        if "timestamp" in self.df.columns and len(self.df) > 0:
            min_ts = self.df["timestamp"].min()
            max_ts = self.df["timestamp"].max()
            date_range = f", {min_ts} to {max_ts}"
        return f"IP Analyzer: {self._packet_count} packets{date_range}"

    def __eq__(self, other) -> bool:
        """Compare two IpAnalyzer instances."""
        if not isinstance(other, IpAnalyzer):
            return False
        return self.df.frame_equal(other.df)

    # ============================================================================
    # TRAFFIC ANALYSIS METHODS
    # ============================================================================

    def get_most_active_ips(self, n: int = 10, by: str = "packets") -> pl.DataFrame:
        """
        Get top N most active IP addresses.

        Args:
            n: Number of top IPs to return
            by: Metric to rank by ("packets" or "bytes")

        Returns:
            pl.DataFrame: Top IPs by activity
        """
        if self.df.is_empty():
            raise EmptyDataFrameError("get_most_active_ips")

        if by not in ["packets", "bytes"]:
            raise ValueError("by must be 'packets' or 'bytes'")

        if "_source_ip" not in self.df.columns or "_destination_ip" not in self.df.columns:
            raise InvalidIPAddressError("No unified IP columns found")

        # Get all IPs (as source)
        src_stats = self.df.group_by("_source_ip").agg([
            pl.count().alias("packets_sent"),
            pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("bytes_sent")
        ]).rename({"_source_ip": "ip_address"})

        # Get all IPs (as destination)
        dst_stats = self.df.group_by("_destination_ip").agg([
            pl.count().alias("packets_received"),
            pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("bytes_received")
        ]).rename({"_destination_ip": "ip_address"})

        # Combine
        combined = src_stats.join(dst_stats, on="ip_address", how="outer_coalesce").fill_null(0)

        # Calculate totals
        combined = combined.with_columns([
            (pl.col("packets_sent") + pl.col("packets_received")).alias("total_packets"),
            (pl.col("bytes_sent") + pl.col("bytes_received")).alias("total_bytes")
        ])

        # Sort by metric
        sort_col = "total_packets" if by == "packets" else "total_bytes"
        return combined.sort(sort_col, descending=True).head(n)

    def get_sender_only_ips(self) -> pl.DataFrame:
        """
        Get IPs that only send packets (never receive).

        Returns:
            pl.DataFrame: Sender-only IPs
        """
        if self.df.is_empty():
            raise EmptyDataFrameError("get_sender_only_ips")

        if "_source_ip" not in self.df.columns or "_destination_ip" not in self.df.columns:
            raise InvalidIPAddressError("No unified IP columns found")

        # Get unique source IPs
        source_ips = self.df.select("_source_ip").unique().rename({"_source_ip": "ip_address"})

        # Get unique destination IPs
        dest_ips = self.df.select("_destination_ip").unique().rename({"_destination_ip": "ip_address"})

        # Find IPs that are only in source (never in destination)
        sender_only = source_ips.join(dest_ips, on="ip_address", how="anti")

        # Get stats for these IPs
        stats = self.df.filter(pl.col("_source_ip").is_in(sender_only["ip_address"])).group_by("_source_ip").agg([
            pl.count().alias("packets_sent"),
            pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("bytes_sent"),
            pl.col("_destination_ip").n_unique().alias("unique_destinations")
        ]).rename({"_source_ip": "ip_address"})

        return stats.sort("packets_sent", descending=True)

    def get_receiver_only_ips(self) -> pl.DataFrame:
        """
        Get IPs that only receive packets (never send).

        Returns:
            pl.DataFrame: Receiver-only IPs
        """
        if self.df.is_empty():
            raise EmptyDataFrameError("get_receiver_only_ips")

        if "_source_ip" not in self.df.columns or "_destination_ip" not in self.df.columns:
            raise InvalidIPAddressError("No unified IP columns found")

        # Get unique source IPs
        source_ips = self.df.select("_source_ip").unique().rename({"_source_ip": "ip_address"})

        # Get unique destination IPs
        dest_ips = self.df.select("_destination_ip").unique().rename({"_destination_ip": "ip_address"})

        # Find IPs that are only in destination (never in source)
        receiver_only = dest_ips.join(source_ips, on="ip_address", how="anti")

        # Get stats for these IPs
        stats = self.df.filter(pl.col("_destination_ip").is_in(receiver_only["ip_address"])).group_by("_destination_ip").agg([
            pl.count().alias("packets_received"),
            pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("bytes_received"),
            pl.col("_source_ip").n_unique().alias("unique_sources")
        ]).rename({"_destination_ip": "ip_address"})

        return stats.sort("packets_received", descending=True)

    def get_asymmetric_ips(self, threshold: float = 0.9) -> pl.DataFrame:
        """
        Get IPs with asymmetric traffic (heavy send or receive imbalance).

        Args:
            threshold: Imbalance ratio threshold (0.0-1.0)

        Returns:
            pl.DataFrame: IPs with asymmetric traffic
        """
        if self.df.is_empty():
            raise EmptyDataFrameError("get_asymmetric_ips")

        if not 0.0 <= threshold <= 1.0:
            raise InvalidThresholdError(threshold, "Threshold must be between 0.0 and 1.0")

        if "_source_ip" not in self.df.columns or "_destination_ip" not in self.df.columns:
            raise InvalidIPAddressError("No unified IP columns found")

        # Get sent stats
        src_stats = self.df.group_by("_source_ip").agg([
            pl.count().alias("packets_sent"),
            pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("bytes_sent")
        ]).rename({"_source_ip": "ip_address"})

        # Get received stats
        dst_stats = self.df.group_by("_destination_ip").agg([
            pl.count().alias("packets_received"),
            pl.col("IP_len").cast(pl.Int64, strict=False).sum().alias("bytes_received")
        ]).rename({"_destination_ip": "ip_address"})

        # Combine
        combined = src_stats.join(dst_stats, on="ip_address", how="outer_coalesce").fill_null(0)

        # Calculate total and ratio
        combined = combined.with_columns([
            (pl.col("packets_sent") + pl.col("packets_received")).alias("total_packets"),
            (pl.when(pl.col("packets_sent") + pl.col("packets_received") > 0)
             .then(pl.col("packets_sent") / (pl.col("packets_sent") + pl.col("packets_received")))
             .otherwise(0.5)).alias("send_ratio")
        ])

        # Filter asymmetric IPs (send_ratio > threshold or < 1-threshold)
        asymmetric = combined.filter(
            (pl.col("send_ratio") > threshold) | (pl.col("send_ratio") < (1 - threshold))
        )

        return asymmetric.sort("total_packets", descending=True)

    def get_communication_matrix(self) -> pl.DataFrame:
        """
        Get IP to IP communication matrix.

        Returns:
            pl.DataFrame: Communication pairs with counts

        TODO: Implement logic to:
            - Group by (source_ip, destination_ip) pairs
            - Count packets per pair
            - Sum bytes per pair
            - Return matrix
        """
        # TODO: Implement
        raise NotImplementedError("get_communication_matrix not yet implemented")

    def detect_hub_ips(self, threshold: int = 50) -> pl.DataFrame:
        """
        Detect hub IPs (communicating with many other IPs).

        Args:
            threshold: Minimum number of unique peers

        Returns:
            pl.DataFrame: Hub IPs

        TODO: Implement logic to:
            - Count unique peers per IP
            - Flag IPs exceeding threshold
            - Could indicate servers or scanners
        """
        # TODO: Implement
        raise NotImplementedError("detect_hub_ips not yet implemented")

    def get_ip_traffic_stats(self, ip_address: str) -> dict:
        """
        Get detailed traffic statistics for a specific IP.

        Args:
            ip_address: IP address to analyze

        Returns:
            dict: Comprehensive traffic statistics

        TODO: Implement logic to:
            - Filter to IP (source or destination)
            - Calculate sent/received packets and bytes
            - List protocols used
            - List peers communicated with
            - Time range of activity
        """
        # TODO: Implement
        raise NotImplementedError("get_ip_traffic_stats not yet implemented")

    def get_internal_vs_external_ratio(self) -> dict:
        """
        Calculate ratio of internal vs external traffic.

        Returns:
            dict: Internal/external traffic statistics

        TODO: Implement logic to:
            - Classify IPs as internal (private) or external (public)
            - Count internal-to-internal traffic
            - Count internal-to-external traffic
            - Count external-to-internal traffic
            - Calculate ratios
        """
        # TODO: Implement
        raise NotImplementedError("get_internal_vs_external_ratio not yet implemented")

    # ============================================================================
    # NETWORK IDENTIFICATION METHODS
    # ============================================================================

    def identify_internal_network(self, subnet: str) -> pl.DataFrame:
        """
        Mark internal IPs based on subnet.

        Args:
            subnet: Internal subnet in CIDR notation (e.g., "192.168.1.0/24")

        Returns:
            pl.DataFrame: IPs with internal/external flag

        TODO: Implement logic to:
            - Parse subnet CIDR
            - Check if each IP is in subnet
            - Add internal/external column
        """
        # TODO: Implement
        raise NotImplementedError("identify_internal_network not yet implemented")

    def get_border_traffic(self) -> pl.DataFrame:
        """
        Get traffic crossing network boundary (internal<->external).

        Returns:
            pl.DataFrame: Border-crossing traffic

        TODO: Implement logic to:
            - Classify IPs as internal/external
            - Filter to pairs where one is internal, one is external
            - Return border traffic
        """
        # TODO: Implement
        raise NotImplementedError("get_border_traffic not yet implemented")

    def get_lateral_traffic(self) -> pl.DataFrame:
        """
        Get east-west traffic within network (internal<->internal).

        Returns:
            pl.DataFrame: Lateral traffic

        TODO: Implement logic to:
            - Classify IPs as internal/external
            - Filter to pairs where both are internal
            - Return lateral traffic
        """
        # TODO: Implement
        raise NotImplementedError("get_lateral_traffic not yet implemented")

    # ============================================================================
    # FRAGMENTATION METHODS
    # ============================================================================

    def get_fragmentation_stats(self) -> dict:
        """
        Get overall IP fragmentation statistics.

        Returns:
            dict: Fragmentation statistics

        TODO: Implement logic to:
            - Count fragmented packets (MF flag or fragment offset > 0)
            - Calculate fragmentation ratio
            - Count DF (Don't Fragment) packets
        """
        # TODO: Implement
        raise NotImplementedError("get_fragmentation_stats not yet implemented")

    def get_top_fragmenting_ips(self, n: int = 10) -> pl.DataFrame:
        """
        Get IPs generating the most fragmented packets.

        Args:
            n: Number of top IPs to return

        Returns:
            pl.DataFrame: Top fragmenting IPs

        TODO: Implement logic to:
            - Filter to fragmented packets
            - Group by source IP
            - Count fragments per IP
            - Return top N
        """
        # TODO: Implement
        raise NotImplementedError("get_top_fragmenting_ips not yet implemented")

    def detect_excessive_fragmentation(self, threshold: int = 100) -> pl.DataFrame:
        """
        Detect excessive fragmentation (potential attack).

        Args:
            threshold: Fragment count threshold per source

        Returns:
            pl.DataFrame: IPs with excessive fragmentation

        TODO: Implement logic to:
            - Count fragments per source IP
            - Flag sources exceeding threshold
            - Could indicate fragmentation attack
        """
        # TODO: Implement
        raise NotImplementedError("detect_excessive_fragmentation not yet implemented")

    def get_fragment_size_distribution(self) -> pl.DataFrame:
        """
        Get distribution of fragment sizes.

        Returns:
            pl.DataFrame: Fragment size distribution

        TODO: Implement logic to:
            - Filter to fragmented packets
            - Extract packet lengths
            - Create size distribution histogram
        """
        # TODO: Implement
        raise NotImplementedError("get_fragment_size_distribution not yet implemented")

    # ============================================================================
    # QOS ANALYSIS METHODS
    # ============================================================================

    def analyze_tos_bits(self) -> pl.DataFrame:
        """
        Analyze Type of Service (ToS) field usage.

        Returns:
            pl.DataFrame: ToS distribution

        TODO: Implement logic to:
            - Extract ToS field
            - Count occurrences
            - Map to service classes
        """
        # TODO: Implement
        raise NotImplementedError("analyze_tos_bits not yet implemented")

    def analyze_dscp_values(self) -> pl.DataFrame:
        """
        Analyze DSCP (Differentiated Services Code Point) values.

        Returns:
            pl.DataFrame: DSCP distribution

        TODO: Implement logic to:
            - Extract DSCP field (first 6 bits of ToS)
            - Map to QoS classes
            - Count usage per class
        """
        # TODO: Implement
        raise NotImplementedError("analyze_dscp_values not yet implemented")

    def detect_priority_traffic(self) -> pl.DataFrame:
        """
        Detect high-priority traffic (based on DSCP/ToS).

        Returns:
            pl.DataFrame: Priority traffic

        TODO: Implement logic to:
            - Filter to packets with high DSCP values
            - Common: EF (46), AF4x (34-38)
            - Return priority packets
        """
        # TODO: Implement
        raise NotImplementedError("detect_priority_traffic not yet implemented")

    def analyze_ecn_flags(self) -> dict:
        """
        Analyze Explicit Congestion Notification (ECN) flags.

        Returns:
            dict: ECN usage statistics

        TODO: Implement logic to:
            - Extract ECN bits (last 2 bits of ToS)
            - Count ECN-capable traffic
            - Count congestion experienced packets
        """
        # TODO: Implement
        raise NotImplementedError("analyze_ecn_flags not yet implemented")
