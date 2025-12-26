"""Custom exceptions for parquet analysis module."""


class ParquetAnalysisError(Exception):
    """Base exception for all parquet analysis errors."""

    pass


class InvalidProtocolError(ParquetAnalysisError):
    """Raised when an invalid protocol is specified."""

    def __init__(self, protocol: str, valid_protocols: set):
        self.protocol = protocol
        self.valid_protocols = valid_protocols
        super().__init__(
            f"Invalid protocol: '{protocol}'. Valid protocols are: {', '.join(sorted(valid_protocols))}"
        )


class MissingColumnError(ParquetAnalysisError):
    """Raised when a required column is missing from the DataFrame."""

    def __init__(self, column: str, available_columns: list = None):
        self.column = column
        self.available_columns = available_columns
        msg = f"Required column '{column}' not found in DataFrame"
        if available_columns:
            msg += f". Available columns: {', '.join(available_columns[:10])}"
            if len(available_columns) > 10:
                msg += f"... ({len(available_columns)} total)"
        super().__init__(msg)


class InvalidTimeWindowError(ParquetAnalysisError):
    """Raised when an invalid time window format is provided."""

    def __init__(self, time_window: str):
        self.time_window = time_window
        super().__init__(
            f"Invalid time window format: '{time_window}'. "
            "Expected format: '<number><unit>' where unit is one of: "
            "ms (milliseconds), s (seconds), m (minutes), h (hours), d (days). "
            "Examples: '100ms', '5m', '1h', '7d'"
        )


class EmptyDataFrameError(ParquetAnalysisError):
    """Raised when operations are attempted on an empty DataFrame."""

    def __init__(self, operation: str = None):
        msg = "Cannot perform operation on empty DataFrame"
        if operation:
            msg = f"Cannot perform '{operation}' on empty DataFrame"
        super().__init__(msg)


class InvalidThresholdError(ParquetAnalysisError):
    """Raised when an invalid threshold value is provided."""

    def __init__(self, threshold, message: str = None):
        self.threshold = threshold
        msg = f"Invalid threshold: {threshold}"
        if message:
            msg += f". {message}"
        super().__init__(msg)


class InvalidIPAddressError(ParquetAnalysisError):
    """Raised when an invalid IP address is provided."""

    def __init__(self, ip_address: str):
        self.ip_address = ip_address
        super().__init__(f"Invalid IP address format: '{ip_address}'")


class AnalyzerNotInitializedError(ParquetAnalysisError):
    """Raised when trying to access an analyzer that hasn't been initialized."""

    def __init__(self, analyzer_name: str):
        self.analyzer_name = analyzer_name
        super().__init__(
            f"Analyzer '{analyzer_name}' not initialized. Make sure the DataFrame contains the required protocol columns."
        )


class FileNotFoundError(ParquetAnalysisError):
    """Raised when the specified parquet file is not found."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        super().__init__(f"Parquet file not found: '{file_path}'")


class InvalidFileFormatError(ParquetAnalysisError):
    """Raised when the file is not a valid parquet file."""

    def __init__(self, file_path: str, original_error: Exception = None):
        self.file_path = file_path
        self.original_error = original_error
        msg = f"Invalid parquet file format: '{file_path}'"
        if original_error:
            msg += f". Error: {str(original_error)}"
        super().__init__(msg)
