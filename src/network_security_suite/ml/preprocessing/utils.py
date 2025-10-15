"""Utility functions for parquet analysis."""

import re
import ipaddress
from datetime import datetime, timedelta
from typing import Any, Dict, List, Union
import polars as pl
from .errors import InvalidTimeWindowError, InvalidIPAddressError


def parse_tcp_flags(flags: str) -> Dict[str, bool]:
    """
    Parse TCP flags string into a dictionary of boolean values.

    Args:
        flags: TCP flags string (e.g., "SA", "PA", "F")

    Returns:
        dict: Mapping of flag name to boolean (present or not)

    Example:
        >>> parse_tcp_flags("SA")
        {'FIN': False, 'SYN': True, 'RST': False, 'PSH': False,
         'ACK': True, 'URG': False, 'ECE': False, 'CWR': False}
    """
    flag_map = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR'
    }

    result = {name: False for name in flag_map.values()}

    if flags:
        for char in flags.upper():
            if char in flag_map:
                result[flag_map[char]] = True

    return result


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private (RFC 1918).

    Args:
        ip: IP address string

    Returns:
        bool: True if IP is private, False otherwise

    Raises:
        InvalidIPAddressError: If IP address format is invalid

    Example:
        >>> is_private_ip("192.168.1.1")
        True
        >>> is_private_ip("8.8.8.8")
        False
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError as e:
        raise InvalidIPAddressError(ip) from e


def is_public_ip(ip: str) -> bool:
    """
    Check if an IP address is public (not private).

    Args:
        ip: IP address string

    Returns:
        bool: True if IP is public, False otherwise
    """
    try:
        return not is_private_ip(ip)
    except InvalidIPAddressError:
        return False


def calculate_entropy(values: List[Any]) -> float:
    """
    Calculate Shannon entropy of a list of values.

    Args:
        values: List of values to calculate entropy for

    Returns:
        float: Entropy value (higher means more random/diverse)

    Example:
        >>> calculate_entropy([1, 1, 1, 1])
        0.0
        >>> calculate_entropy([1, 2, 3, 4])
        2.0
    """
    if not values:
        return 0.0

    import math
    from collections import Counter

    counts = Counter(values)
    total = len(values)
    entropy = 0.0

    for count in counts.values():
        probability = count / total
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def format_bytes(bytes_count: int) -> str:
    """
    Format bytes into human-readable string.

    Args:
        bytes_count: Number of bytes

    Returns:
        str: Human-readable format (e.g., "1.5 MB")

    Example:
        >>> format_bytes(1024)
        '1.00 KB'
        >>> format_bytes(1536000)
        '1.46 MB'
    """
    if bytes_count < 0:
        return "0 B"

    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    unit_index = 0

    size = float(bytes_count)
    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1

    return f"{size:.2f} {units[unit_index]}"


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        str: Human-readable format (e.g., "1h 30m 45s")

    Example:
        >>> format_duration(3665)
        '1h 1m 5s'
        >>> format_duration(45.5)
        '45.50s'
    """
    if seconds < 0:
        return "0s"

    if seconds < 60:
        return f"{seconds:.2f}s"

    parts = []
    remaining = seconds

    # Days
    if remaining >= 86400:
        days = int(remaining // 86400)
        parts.append(f"{days}d")
        remaining %= 86400

    # Hours
    if remaining >= 3600:
        hours = int(remaining // 3600)
        parts.append(f"{hours}h")
        remaining %= 3600

    # Minutes
    if remaining >= 60:
        minutes = int(remaining // 60)
        parts.append(f"{minutes}m")
        remaining %= 60

    # Seconds
    if remaining > 0 or not parts:
        parts.append(f"{remaining:.2f}s")

    return " ".join(parts)


def create_flow_id(
    src_ip: str,
    dst_ip: str,
    src_port: Union[int, None],
    dst_port: Union[int, None],
    protocol: str
) -> str:
    """
    Create a unique flow identifier from 5-tuple.

    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port (can be None for protocols without ports)
        dst_port: Destination port (can be None for protocols without ports)
        protocol: Protocol name

    Returns:
        str: Unique flow ID

    Example:
        >>> create_flow_id("192.168.1.1", "8.8.8.8", 12345, 53, "UDP")
        '192.168.1.1:12345->8.8.8.8:53:UDP'
    """
    src_port_str = str(src_port) if src_port is not None else "*"
    dst_port_str = str(dst_port) if dst_port is not None else "*"
    return f"{src_ip}:{src_port_str}->{dst_ip}:{dst_port_str}:{protocol}"


def parse_timestamp(ts: Any) -> datetime:
    """
    Parse various timestamp formats to datetime object.

    Args:
        ts: Timestamp in various formats (datetime, string, int/float epoch)

    Returns:
        datetime: Parsed datetime object

    Raises:
        ValueError: If timestamp format is not recognized

    Example:
        >>> parse_timestamp(1609459200)
        datetime.datetime(2021, 1, 1, 0, 0)
    """
    if isinstance(ts, datetime):
        return ts

    if isinstance(ts, (int, float)):
        # Assume Unix epoch timestamp
        return datetime.fromtimestamp(ts)

    if isinstance(ts, str):
        # Try various formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue

        raise ValueError(f"Unable to parse timestamp: {ts}")

    raise ValueError(f"Unsupported timestamp type: {type(ts)}")


def calculate_packet_rate(count: int, duration: float) -> float:
    """
    Calculate packets per second rate.

    Args:
        count: Number of packets
        duration: Duration in seconds

    Returns:
        float: Packets per second

    Example:
        >>> calculate_packet_rate(1000, 10.0)
        100.0
    """
    if duration <= 0:
        return 0.0
    return count / duration


def parse_time_window(time_window: str) -> timedelta:
    """
    Parse time window string to timedelta object.

    Args:
        time_window: Time window string (e.g., "5m", "1h", "100ms")

    Returns:
        timedelta: Parsed time duration

    Raises:
        InvalidTimeWindowError: If format is invalid

    Example:
        >>> parse_time_window("5m")
        datetime.timedelta(seconds=300)
        >>> parse_time_window("1h")
        datetime.timedelta(seconds=3600)
    """
    pattern = r'^(\d+(?:\.\d+)?)(ms|s|m|h|d)$'
    match = re.match(pattern, time_window.lower())

    if not match:
        raise InvalidTimeWindowError(time_window)

    value, unit = match.groups()
    value = float(value)

    unit_map = {
        'ms': timedelta(milliseconds=value),
        's': timedelta(seconds=value),
        'm': timedelta(minutes=value),
        'h': timedelta(hours=value),
        'd': timedelta(days=value),
    }

    return unit_map[unit]


def time_window_to_polars(time_window: str) -> str:
    """
    Convert time window string to Polars duration format.

    Args:
        time_window: Time window string (e.g., "5m", "1h")

    Returns:
        str: Polars-compatible duration string

    Example:
        >>> time_window_to_polars("5m")
        '5m'
        >>> time_window_to_polars("1.5h")
        '90m'
    """
    # Parse to validate
    td = parse_time_window(time_window)

    # Convert to total seconds
    total_seconds = td.total_seconds()

    # Choose appropriate unit
    if total_seconds < 1:
        return f"{int(total_seconds * 1000)}ms"
    elif total_seconds < 60:
        return f"{int(total_seconds)}s"
    elif total_seconds < 3600:
        return f"{int(total_seconds / 60)}m"
    elif total_seconds < 86400:
        return f"{int(total_seconds / 3600)}h"
    else:
        return f"{int(total_seconds / 86400)}d"


def classify_port(port: int) -> str:
    """
    Classify port into well-known, registered, or ephemeral.

    Args:
        port: Port number (0-65535)

    Returns:
        str: Port classification

    Example:
        >>> classify_port(80)
        'well-known'
        >>> classify_port(8080)
        'registered'
        >>> classify_port(50000)
        'ephemeral'
    """
    if 0 <= port < 1024:
        return "well-known"
    elif 1024 <= port < 49152:
        return "registered"
    elif 49152 <= port < 65536:
        return "ephemeral"
    else:
        return "invalid"


def get_protocol_name(protocol_number: int) -> str:
    """
    Get protocol name from IP protocol number.

    Args:
        protocol_number: IP protocol number

    Returns:
        str: Protocol name

    Example:
        >>> get_protocol_name(6)
        'TCP'
        >>> get_protocol_name(17)
        'UDP'
    """
    protocol_map = {
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
        132: "SCTP",
    }
    return protocol_map.get(protocol_number, f"Protocol-{protocol_number}")


def validate_dataframe_columns(df: pl.DataFrame, required_columns: List[str]) -> None:
    """
    Validate that DataFrame contains required columns.

    Args:
        df: Polars DataFrame
        required_columns: List of required column names

    Raises:
        MissingColumnError: If required column is missing
    """
    from .errors import MissingColumnError

    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        raise MissingColumnError(missing[0], df.columns)


def has_column(df: pl.DataFrame, column: str) -> bool:
    """
    Check if DataFrame has a specific column.

    Args:
        df: Polars DataFrame
        column: Column name

    Returns:
        bool: True if column exists
    """
    return column in df.columns


def safe_cast_to_int(series: pl.Series, default: int = 0) -> pl.Series:
    """
    Safely cast a series to integer, replacing nulls with default.

    Args:
        series: Polars Series
        default: Default value for null entries

    Returns:
        pl.Series: Integer series
    """
    return series.cast(pl.Int64, strict=False).fill_null(default)


def safe_cast_to_str(series: pl.Series, default: str = "") -> pl.Series:
    """
    Safely cast a series to string, replacing nulls with default.

    Args:
        series: Polars Series
        default: Default value for null entries

    Returns:
        pl.Series: String series
    """
    return series.cast(pl.Utf8, strict=False).fill_null(default)
