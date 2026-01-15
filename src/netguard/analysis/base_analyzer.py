import contextlib
from datetime import datetime, timedelta
from typing import Any, Optional, cast

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
        return f"{self.__class__.__name__}(packets={self._packet_count}, shape={self.df.shape})"

    def __str__(self) -> str:
        """Human-readable string representation."""
        date_range = ""
        if "timestamp" in self.df.columns and len(self.df) > 0:
            min_ts = self.df["timestamp"].min()
            max_ts = self.df["timestamp"].max()
            date_range = f", {min_ts!s} to {max_ts!s}"

        return f"{self.__class__.__name__}: {self._packet_count} packets{date_range}"

    def __eq__(self, other: object) -> bool:
        """Compare two analyzer instances."""
        if not isinstance(other, self.__class__):
            return False
        return self.df.equals(other.df)

    def __len__(self) -> int:
        """Return packet count."""
        return self._packet_count

    def __bool__(self) -> bool:
        """Return True if analyzer has packets."""
        return self._packet_count > 0

    __hash__ = None  # Make instances unhashable

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

    def get_date_range(self) -> dict[str, Any]:
        """
        Get the date range of packets.

        Returns:
            dict: Contains 'start', 'end', 'duration' (seconds)
        """
        if "timestamp" not in self.df.columns or self.is_empty:
            return {"start": None, "end": None, "duration": None}

        min_ts = self.df["timestamp"].min()
        max_ts = self.df["timestamp"].max()

        duration: Optional[float] = None
        if min_ts is not None and max_ts is not None:
            # Try to calculate duration
            with contextlib.suppress(AttributeError, TypeError, ValueError):
                if (isinstance(min_ts, datetime) and isinstance(max_ts, datetime)) or (
                    isinstance(min_ts, timedelta) and isinstance(max_ts, timedelta)
                ):
                    duration = (cast(timedelta, max_ts) - cast(timedelta, min_ts)).total_seconds()
                elif isinstance(min_ts, (int, float)) and isinstance(max_ts, (int, float)):
                    duration = float(max_ts - min_ts)

        return {
            "start": min_ts,
            "end": max_ts,
            "duration": duration,
        }

    def get_memory_usage(self) -> dict[str, float]:
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

    def get_column_types(self) -> dict[str, str]:
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

    def to_dict(self) -> dict[str, Any]:
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
