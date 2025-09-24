from numpy._core.multiarray import dtype
import polars as pl
import polars.selectors as cs
import numpy as np

import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import mutual_info_classif, mutual_info_regression
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Optional, Any, Iterable


class NetworkParquetAnalysis:
    def __init__(self, path):
        self.path = path
        self.df = pl.read_parquet(self.path)
        self.PROTOCOLS = set(["TCP", "UDP", "IP", "IPv6", "DHCP", "DNS", "ARP", "ICMP"])

    """

    """
    def get_by_protocol(self,protocol:str):
        if protocol not in self.PROTOCOLS:
            raise ValueError(f"Invalid protocol: {protocol}\nValid protocols are: {', '.join(self.PROTOCOLS)}")
        return self.df.select(cs.contains(protocol))

    def find_ip_information(self, ip_address: str)->pl.DataFrame:
        ip_columns = self.df.select(cs.contains("IP") | cs.contains("IPv6")).columns
        return self.df.filter(
            pl.any_horizontal(pl.col(c) == ip_address for c in ip_columns)
        )

    def get_timestamps(self)->pl.DataFrame:
        return self.df.select(cs.contains("timestamp"))

    def get_timestamps_by_ip(self, ip_address: str)->pl.DataFrame:
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

if __name__ == "__main__":
    path = "/home/batman/Documents/networkguard2/src/network_security_suite/data/ml_testing.parquet"
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
