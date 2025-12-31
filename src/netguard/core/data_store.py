"""Centralized parquet file operations.

This module provides a single point for all parquet I/O operations,
avoiding duplication across the codebase and ensuring consistent
schema handling.
"""

from pathlib import Path
from typing import Any, Dict, Optional

import polars as pl

from netguard.core.exceptions import DataExportError, DataImportError
from netguard.core.loggers import get_logger

__all__ = ["DataStore"]


class DataStore:
    """
    Centralized parquet data operations.

    All parquet read/write operations go through this class to avoid
    duplication and ensure consistent schema handling.

    Examples:
        >>> # Save packets to parquet
        >>> DataStore.save_packets(df, "output.parquet")

        >>> # Load packets from parquet
        >>> df = DataStore.load_packets("input.parquet")

        >>> # Get schema without loading full file
        >>> schema = DataStore.get_schema("input.parquet")
    """

    @staticmethod
    def save_packets(
        df: pl.DataFrame,
        filepath: str,
        compression: str = "snappy",
    ) -> None:
        """
        Save packet DataFrame to parquet file.

        Args:
            df: Polars DataFrame with packet data
            filepath: Output file path
            compression: Compression algorithm (snappy, gzip, lz4, zstd)

        Raises:
            DataExportError: If save fails
        """
        logger = get_logger()
        try:
            logger.info(f"Saving packets to {filepath}")

            # Ensure directory exists
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)

            # Write parquet
            df.write_parquet(filepath, compression=compression)

            logger.info(
                f"Saved {len(df)} packets to {filepath} "
                f"({df.estimated_size('mb'):.2f} MB)"
            )
        except Exception as e:
            raise DataExportError(
                export_format="parquet",
                destination=filepath,
                error_details=str(e),
            ) from e

    @staticmethod
    def load_packets(filepath: str) -> pl.DataFrame:
        """
        Load packet DataFrame from parquet file.

        Args:
            filepath: Input file path

        Returns:
            pl.DataFrame: Loaded packet data

        Raises:
            FileNotFoundError: If file doesn't exist
            DataImportError: If load fails
        """
        logger = get_logger()
        try:
            if not Path(filepath).exists():
                raise FileNotFoundError(f"File not found: {filepath}")

            logger.info(f"Loading packets from {filepath}")
            df = pl.read_parquet(filepath)

            logger.info(
                f"Loaded {len(df)} packets from {filepath} "
                f"({df.estimated_size('mb'):.2f} MB)"
            )
            return df
        except FileNotFoundError:
            raise
        except Exception as e:
            raise DataImportError(
                import_format="parquet",
                source=filepath,
                error_details=str(e),
            ) from e

    @staticmethod
    def get_schema(filepath: str) -> Dict[str, str]:
        """
        Get parquet file schema without loading full file.

        Args:
            filepath: Input file path

        Returns:
            dict: Schema mapping column names to types
        """
        df = pl.read_parquet(filepath, n_rows=1)
        return {col: str(dtype) for col, dtype in zip(df.columns, df.dtypes)}

    @staticmethod
    def get_file_info(filepath: str) -> Dict[str, Any]:
        """
        Get parquet file metadata without loading data.

        Args:
            filepath: Input file path

        Returns:
            dict: File information including path, size, columns
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        # Read minimal data for schema
        df = pl.read_parquet(filepath, n_rows=1)

        return {
            "path": str(path.absolute()),
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "size_mb": path.stat().st_size / (1024 * 1024),
            "columns": df.columns,
            "column_count": len(df.columns),
            "schema": {col: str(dtype) for col, dtype in zip(df.columns, df.dtypes)},
        }

    @staticmethod
    def append_packets(
        df: pl.DataFrame,
        filepath: str,
        compression: str = "snappy",
    ) -> None:
        """
        Append packets to existing parquet file.

        If file doesn't exist, creates it. If it exists, loads existing
        data, concatenates new data, and rewrites the file.

        Args:
            df: Polars DataFrame with new packet data
            filepath: File path to append to
            compression: Compression algorithm

        Raises:
            DataExportError: If operation fails
        """
        logger = get_logger()
        try:
            if Path(filepath).exists():
                # Load existing data
                existing_df = pl.read_parquet(filepath)
                logger.debug(f"Loaded {len(existing_df)} existing packets")

                # Concatenate
                combined_df = pl.concat([existing_df, df], how="diagonal")
                logger.debug(f"Combined to {len(combined_df)} packets")

                # Save
                DataStore.save_packets(combined_df, filepath, compression)
            else:
                # Just save new data
                DataStore.save_packets(df, filepath, compression)
        except Exception as e:
            raise DataExportError(
                export_format="parquet",
                destination=filepath,
                error_details=f"Append failed: {str(e)}",
            ) from e

    @staticmethod
    def validate_parquet(filepath: str) -> bool:
        """
        Validate that a file is a valid parquet file.

        Args:
            filepath: File path to validate

        Returns:
            bool: True if valid parquet, False otherwise
        """
        try:
            if not Path(filepath).exists():
                return False
            # Try to read schema only
            pl.read_parquet(filepath, n_rows=0)
            return True
        except Exception:
            return False
