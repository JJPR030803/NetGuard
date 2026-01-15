"""Tests for preprocessing utility functions."""

import unittest
from datetime import datetime, timedelta, timezone

import polars as pl
import pytest

from netguard.analysis.utils import (
    calculate_entropy,
    calculate_packet_rate,
    classify_port,
    create_flow_id,
    format_bytes,
    format_duration,
    get_protocol_name,
    has_column,
    is_private_ip,
    is_public_ip,
    parse_tcp_flags,
    parse_time_window,
    parse_timestamp,
    safe_cast_to_int,
    safe_cast_to_str,
    time_window_to_polars,
    validate_dataframe_columns,
)
from netguard.core.errors import (
    InvalidIPAddressError,
    InvalidTimeWindowError,
    MissingColumnError,
)


class TestParseTcpFlags:
    """Test parse_tcp_flags function."""

    def test_empty_flags(self):
        """Test parsing empty flags string."""
        result = parse_tcp_flags("")
        assert all(not value for value in result.values())
        assert "SYN" in result
        assert "ACK" in result

    def test_syn_flag(self):
        """Test parsing SYN flag."""
        result = parse_tcp_flags("S")
        assert result["SYN"] is True
        assert result["ACK"] is False
        assert result["FIN"] is False

    def test_syn_ack_flags(self):
        """Test parsing SYN-ACK flags."""
        result = parse_tcp_flags("SA")
        assert result["SYN"] is True
        assert result["ACK"] is True
        assert result["FIN"] is False

    def test_all_flags(self):
        """Test parsing all TCP flags."""
        result = parse_tcp_flags("FSRPAUEC")
        assert result["FIN"] is True
        assert result["SYN"] is True
        assert result["RST"] is True
        assert result["PSH"] is True
        assert result["ACK"] is True
        assert result["URG"] is True
        assert result["ECE"] is True
        assert result["CWR"] is True

    def test_lowercase_flags(self):
        """Test that lowercase flags work."""
        result = parse_tcp_flags("sa")
        assert result["SYN"] is True
        assert result["ACK"] is True


class TestIsPrivateIP:
    """Test is_private_ip function."""

    def test_private_ipv4_192(self):
        """Test private IP in 192.168.0.0/16 range."""
        assert is_private_ip("192.168.1.1") is True

    def test_private_ipv4_10(self):
        """Test private IP in 10.0.0.0/8 range."""
        assert is_private_ip("10.0.0.1") is True

    def test_private_ipv4_172(self):
        """Test private IP in 172.16.0.0/12 range."""
        assert is_private_ip("172.16.0.1") is True

    def test_public_ipv4(self):
        """Test public IP address."""
        assert is_private_ip("8.8.8.8") is False

    def test_localhost(self):
        """Test localhost."""
        assert is_private_ip("127.0.0.1") is True

    def test_invalid_ip(self):
        """Test invalid IP address raises error."""
        with pytest.raises(InvalidIPAddressError) as exc_info:
            is_private_ip("not.an.ip")
        assert "not.an.ip" in str(exc_info.value)


class TestIsPublicIP:
    """Test is_public_ip function."""

    def test_public_ipv4(self):
        """Test public IP address."""
        assert is_public_ip("8.8.8.8") is True

    def test_private_ipv4(self):
        """Test private IP address."""
        assert is_public_ip("192.168.1.1") is False

    def test_invalid_ip(self):
        """Test invalid IP returns False."""
        assert is_public_ip("invalid") is False


class TestCalculateEntropy:
    """Test calculate_entropy function."""

    def test_empty_list(self):
        """Test entropy of empty list."""
        assert calculate_entropy([]) == 0.0

    def test_uniform_values(self):
        """Test entropy of all same values."""
        assert calculate_entropy([1, 1, 1, 1]) == 0.0

    def test_diverse_values(self):
        """Test entropy of diverse values."""
        entropy = calculate_entropy([1, 2, 3, 4])
        assert entropy == 2.0

    def test_mixed_values(self):
        """Test entropy of mixed values."""
        entropy = calculate_entropy([1, 1, 2, 2])
        assert entropy == 1.0


class TestFormatBytes:
    """Test format_bytes function."""

    def test_bytes(self):
        """Test formatting bytes."""
        assert format_bytes(512) == "512.00 B"

    def test_kilobytes(self):
        """Test formatting kilobytes."""
        assert format_bytes(1024) == "1.00 KB"

    def test_megabytes(self):
        """Test formatting megabytes."""
        assert format_bytes(1536000) == "1.46 MB"

    def test_gigabytes(self):
        """Test formatting gigabytes."""
        assert format_bytes(1073741824) == "1.00 GB"

    def test_negative_bytes(self):
        """Test negative bytes returns 0 B."""
        assert format_bytes(-100) == "0 B"

    def test_zero_bytes(self):
        """Test zero bytes."""
        assert format_bytes(0) == "0.00 B"


class TestFormatDuration:
    """Test format_duration function."""

    def test_seconds(self):
        """Test formatting seconds."""
        assert format_duration(45.5) == "45.50s"

    def test_minutes(self):
        """Test formatting minutes."""
        assert "1m" in format_duration(65)

    def test_hours(self):
        """Test formatting hours."""
        result = format_duration(3665)
        assert "1h" in result
        assert "1m" in result

    def test_days(self):
        """Test formatting days."""
        result = format_duration(86400 + 3600)
        assert "1d" in result
        assert "1h" in result

    def test_negative_duration(self):
        """Test negative duration returns 0s."""
        assert format_duration(-10) == "0s"


class TestCreateFlowID:
    """Test create_flow_id function."""

    def test_flow_id_with_ports(self):
        """Test creating flow ID with ports."""
        flow_id = create_flow_id("192.168.1.1", "8.8.8.8", 12345, 53, "UDP")
        assert flow_id == "192.168.1.1:12345->8.8.8.8:53:UDP"

    def test_flow_id_without_ports(self):
        """Test creating flow ID without ports (None)."""
        flow_id = create_flow_id("192.168.1.1", "8.8.8.8", None, None, "ICMP")
        assert flow_id == "192.168.1.1:*->8.8.8.8:*:ICMP"

    def test_flow_id_mixed_ports(self):
        """Test creating flow ID with one port None."""
        flow_id = create_flow_id("192.168.1.1", "8.8.8.8", 12345, None, "TCP")
        assert flow_id == "192.168.1.1:12345->8.8.8.8:*:TCP"


class TestParseTimestamp:
    """Test parse_timestamp function."""

    def test_datetime_passthrough(self):
        """Test datetime object passes through."""
        dt = datetime(2021, 1, 1, 0, 0)
        result = parse_timestamp(dt)
        assert result == dt

    def test_unix_epoch_int(self):
        """Test parsing Unix epoch as int."""
        result = parse_timestamp(1609459200)
        expected = datetime(2021, 1, 1, 0, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_unix_epoch_float(self):
        """Test parsing Unix epoch as float."""
        result = parse_timestamp(1609459200.5)
        assert isinstance(result, datetime)

    def test_string_iso_format(self):
        """Test parsing ISO format string."""
        result = parse_timestamp("2021-01-01T00:00:00")
        assert result.year == 2021
        assert result.month == 1
        assert result.day == 1

    def test_string_simple_format(self):
        """Test parsing simple date format."""
        result = parse_timestamp("2021-01-01")
        assert result.year == 2021
        assert result.month == 1
        assert result.day == 1

    def test_invalid_string(self):
        """Test invalid string raises ValueError."""
        with pytest.raises(ValueError, match="Unable to parse timestamp"):
            parse_timestamp("invalid")

    def test_invalid_type(self):
        """Test invalid type raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported timestamp type"):
            parse_timestamp([1, 2, 3])


class TestCalculatePacketRate:
    """Test calculate_packet_rate function."""

    def test_normal_rate(self):
        """Test normal packet rate calculation."""
        assert calculate_packet_rate(1000, 10.0) == 100.0

    def test_zero_duration(self):
        """Test zero duration returns 0."""
        assert calculate_packet_rate(1000, 0.0) == 0.0

    def test_negative_duration(self):
        """Test negative duration returns 0."""
        assert calculate_packet_rate(1000, -5.0) == 0.0


class TestParseTimeWindow:
    """Test parse_time_window function."""

    def test_milliseconds(self):
        """Test parsing milliseconds."""
        result = parse_time_window("100ms")
        assert result == timedelta(milliseconds=100)

    def test_seconds(self):
        """Test parsing seconds."""
        result = parse_time_window("30s")
        assert result == timedelta(seconds=30)

    def test_minutes(self):
        """Test parsing minutes."""
        result = parse_time_window("5m")
        assert result == timedelta(minutes=5)

    def test_hours(self):
        """Test parsing hours."""
        result = parse_time_window("2h")
        assert result == timedelta(hours=2)

    def test_days(self):
        """Test parsing days."""
        result = parse_time_window("7d")
        assert result == timedelta(days=7)

    def test_float_value(self):
        """Test parsing float values."""
        result = parse_time_window("1.5h")
        assert result == timedelta(hours=1.5)

    def test_invalid_format(self):
        """Test invalid format raises error."""
        with pytest.raises(InvalidTimeWindowError):
            parse_time_window("invalid")

    def test_invalid_unit(self):
        """Test invalid unit raises error."""
        with pytest.raises(InvalidTimeWindowError):
            parse_time_window("5x")


class TestTimeWindowToPolars:
    """Test time_window_to_polars function."""

    def test_minutes(self):
        """Test converting minutes."""
        result = time_window_to_polars("5m")
        assert result == "5m"

    def test_hours_to_minutes(self):
        """Test converting hours to minutes."""
        result = time_window_to_polars("1.5h")
        assert result == "90m"

    def test_milliseconds(self):
        """Test converting milliseconds."""
        result = time_window_to_polars("500ms")
        assert result == "500ms"

    def test_seconds(self):
        """Test converting seconds."""
        result = time_window_to_polars("30s")
        assert result == "30s"

    def test_days_to_hours(self):
        """Test converting days to hours."""
        result = time_window_to_polars("2d")
        assert result == "48h"


class TestClassifyPort:
    """Test classify_port function."""

    def test_well_known_port(self):
        """Test well-known port classification."""
        assert classify_port(80) == "well-known"
        assert classify_port(443) == "well-known"
        assert classify_port(0) == "well-known"
        assert classify_port(1023) == "well-known"

    def test_registered_port(self):
        """Test registered port classification."""
        assert classify_port(1024) == "registered"
        assert classify_port(8080) == "registered"
        assert classify_port(49151) == "registered"

    def test_ephemeral_port(self):
        """Test ephemeral port classification."""
        assert classify_port(49152) == "ephemeral"
        assert classify_port(50000) == "ephemeral"
        assert classify_port(65535) == "ephemeral"

    def test_invalid_port(self):
        """Test invalid port number."""
        assert classify_port(65536) == "invalid"
        assert classify_port(-1) == "invalid"


class TestGetProtocolName:
    """Test get_protocol_name function."""

    def test_tcp(self):
        """Test TCP protocol number."""
        assert get_protocol_name(6) == "TCP"

    def test_udp(self):
        """Test UDP protocol number."""
        assert get_protocol_name(17) == "UDP"

    def test_icmp(self):
        """Test ICMP protocol number."""
        assert get_protocol_name(1) == "ICMP"

    def test_unknown_protocol(self):
        """Test unknown protocol number."""
        assert get_protocol_name(999) == "Protocol-999"


class TestValidateDataframeColumns:
    """Test validate_dataframe_columns function."""

    def test_valid_columns(self):
        """Test validation with all required columns present."""
        df = pl.DataFrame({"col1": [1, 2], "col2": [3, 4], "col3": [5, 6]})
        # Should not raise
        validate_dataframe_columns(df, ["col1", "col2"])

    def test_missing_column(self):
        """Test validation with missing column."""
        df = pl.DataFrame({"col1": [1, 2], "col2": [3, 4]})
        with pytest.raises(MissingColumnError) as exc_info:
            validate_dataframe_columns(df, ["col1", "col3"])
        assert "col3" in str(exc_info.value)


class TestHasColumn:
    """Test has_column function."""

    def test_existing_column(self):
        """Test with existing column."""
        df = pl.DataFrame({"col1": [1, 2], "col2": [3, 4]})
        assert has_column(df, "col1") is True

    def test_missing_column(self):
        """Test with missing column."""
        df = pl.DataFrame({"col1": [1, 2], "col2": [3, 4]})
        assert has_column(df, "col3") is False


class TestSafeCastToInt:
    """Test safe_cast_to_int function."""

    def test_cast_valid_integers(self):
        """Test casting valid integers."""
        series = pl.Series([1, 2, 3])
        result = safe_cast_to_int(series)
        assert result.dtype == pl.Int64
        assert result.to_list() == [1, 2, 3]

    def test_cast_with_nulls(self):
        """Test casting with null values."""
        series = pl.Series([1, None, 3])
        result = safe_cast_to_int(series, default=0)
        assert result.to_list() == [1, 0, 3]

    def test_cast_with_custom_default(self):
        """Test casting with custom default."""
        series = pl.Series([1, None, 3])
        result = safe_cast_to_int(series, default=-1)
        assert result.to_list() == [1, -1, 3]


class TestSafeCastToStr:
    """Test safe_cast_to_str function."""

    def test_cast_valid_strings(self):
        """Test casting valid strings."""
        series = pl.Series(["a", "b", "c"])
        result = safe_cast_to_str(series)
        assert result.dtype == pl.Utf8
        assert result.to_list() == ["a", "b", "c"]

    def test_cast_with_nulls(self):
        """Test casting with null values."""
        series = pl.Series(["a", None, "c"])
        result = safe_cast_to_str(series, default="")
        assert result.to_list() == ["a", "", "c"]

    def test_cast_with_custom_default(self):
        """Test casting with custom default."""
        series = pl.Series(["a", None, "c"])
        result = safe_cast_to_str(series, default="N/A")
        assert result.to_list() == ["a", "N/A", "c"]


if __name__ == "__main__":
    unittest.main()
