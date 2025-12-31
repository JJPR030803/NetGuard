"""Base class for all protocol analyzers.

This module provides the BaseAnalyzer class that all protocol-specific
analyzers (TCP, UDP, DNS, etc.) inherit from. It provides common
functionality and enforces a consistent interface across all analyzers.
"""

from typing import Any, Dict, Optional

import polars as pl

__all__ = ["BaseAnalyzer"]


class BaseAnalyzer:
    """
    Base class for protocol-specific analyzers.

    All analyzers (TCP, UDP, DNS, etc.) inherit from this class.
    Provides common functionality and enforces consistent interface.

    Args:
        df: Polars DataFrame containing packet data

    Attributes:
        df: The packet DataFrame (may be filtered to specific protocol)
        _packet_count: Cached count of packets

    Examples:
        >>> class TcpAnalyzer(BaseAnalyzer):
        ...     def __init__(self, df: pl.DataFrame):
        ...         super().__init__(df)
        ...         # Filter to TCP only
        ...         self.df = self.df.filter(pl.col("IP_proto") == 6)
        ...         self._packet_count = len(self.df)
    """

    def __init__(self, df: pl.DataFrame):
        """
        Initialize analyzer with packet DataFrame.

        Args:
            df: Polars DataFrame with packet data
        """
        self.df = df
        self._packet_count = len(df)

    def __repr__(self) -> str:
        """Technical representation for debugging."""
        return (
            f"{self.__class__.__name__}("
            f"packets={self._packet_count}, "
            f"shape={self.df.shape})"
        )

    def __str__(self) -> str:
        """Human-readable string representation."""
        date_range = ""
        if "timestamp" in self.df.columns and len(self.df) > 0:
            min_ts = self.df["timestamp"].min()
            max_ts = self.df["timestamp"].max()
            date_range = f", {min_ts} to {max_ts}"

        return f"{self.__class__.__name__}: {self._packet_count} packets{date_range}"

    def __eq__(self, other) -> bool:
        """Compare two analyzer instances."""
        if not isinstance(other, self.__class__):
            return False
        return self.df.frame_equal(other.df)

    def __len__(self) -> int:
        """Return packet count."""
        return self._packet_count

    def __bool__(self) -> bool:
        """Return True if analyzer has packets."""
        return self._packet_count > 0

    @property
    def packet_count(self) -> int:
        """Get total packet count."""
        return self._packet_count

    @property
    def is_empty(self) -> bool:
        """Check if analyzer has no packets."""
        return self._packet_count == 0

    @property
    def columns(self) -> list:
        """Get list of column names."""
        return self.df.columns

    @property
    def shape(self) -> tuple:
        """Get DataFrame shape (rows, columns)."""
        return self.df.shape

    def get_date_range(self) -> Dict[str, Any]:
        """
        Get the date range of packets.

        Returns:
            dict: Contains 'start', 'end', 'duration' (seconds)
        """
        if "timestamp" not in self.df.columns or self.is_empty:
            return {"start": None, "end": None, "duration": None}

        min_ts = self.df["timestamp"].min()
        max_ts = self.df["timestamp"].max()

        duration = None
        if min_ts and max_ts:
            try:
                duration = (max_ts - min_ts).total_seconds()
            except AttributeError:
                # If timestamps are not datetime objects
                try:
                    duration = float(max_ts - min_ts)
                except (TypeError, ValueError):
                    pass

        return {
            "start": min_ts,
            "end": max_ts,
            "duration": duration,
        }

    def get_memory_usage(self) -> Dict[str, float]:
        """
        Get memory usage information.

        Returns:
            dict: Memory usage in bytes and MB
        """
        size_bytes = self.df.estimated_size()
        return {
            "bytes": size_bytes,
            "mb": size_bytes / (1024 * 1024),
        }

    def has_column(self, column: str) -> bool:
        """
        Check if DataFrame has a specific column.

        Args:
            column: Column name to check

        Returns:
            bool: True if column exists
        """
        return column in self.df.columns

    def get_column_types(self) -> Dict[str, str]:
        """
        Get mapping of column names to data types.

        Returns:
            dict: Column name to type string mapping
        """
        return {col: str(dtype) for col, dtype in zip(self.df.columns, self.df.dtypes)}

    def sample(self, n: int = 10) -> pl.DataFrame:
        """
        Get a random sample of packets.

        Args:
            n: Number of packets to sample

        Returns:
            pl.DataFrame: Sampled packets
        """
        if self.is_empty:
            return self.df
        return self.df.sample(min(n, self._packet_count))

    def head(self, n: int = 10) -> pl.DataFrame:
        """
        Get first n packets.

        Args:
            n: Number of packets

        Returns:
            pl.DataFrame: First n packets
        """
        return self.df.head(n)

    def tail(self, n: int = 10) -> pl.DataFrame:
        """
        Get last n packets.

        Args:
            n: Number of packets

        Returns:
            pl.DataFrame: Last n packets
        """
        return self.df.tail(n)

    def describe(self) -> pl.DataFrame:
        """
        Get descriptive statistics.

        Returns:
            pl.DataFrame: Statistics for numeric columns
        """
        return self.df.describe()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert analyzer state to dictionary (for serialization).

        Returns:
            dict: Analyzer metadata
        """
        return {
            "analyzer_type": self.__class__.__name__,
            "packet_count": self._packet_count,
            "shape": self.shape,
            "columns": self.columns,
            "date_range": self.get_date_range(),
            "memory_usage": self.get_memory_usage(),
        }
