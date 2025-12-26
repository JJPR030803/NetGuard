#!/usr/bin/env python3
"""
Project Context Collector
Collects source files from a project and outputs them to a single file for AI context.
Supports multiple directories, ignore patterns, and .gitignore integration.
"""

import argparse
import fnmatch
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Set


class ProjectContextCollector:
    """Collects project files and outputs them with clear separations."""

    DEFAULT_EXTENSIONS = [".py", ".sh", ".yml", ".yaml"]
    DEFAULT_IGNORE_DIRS = {
        "__pycache__",
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        ".pytest_cache",
        ".mypy_cache",
        "dist",
        "build",
        ".egg-info",
        ".tox",
    }

    def __init__(
        self,
        sources: List[Path],
        output_file: Path,
        extensions: List[str] = None,
        ignore_patterns: List[str] = None,
        use_gitignore: bool = True,
        max_file_size: int = 1_000_000,  # 1MB default
    ):
        self.sources = sources
        self.output_file = output_file
        self.extensions = extensions or self.DEFAULT_EXTENSIONS
        self.ignore_patterns = ignore_patterns or []
        self.use_gitignore = use_gitignore
        self.max_file_size = max_file_size
        self.gitignore_patterns = set()
        self.file_count = 0
        self.skipped_count = 0

    def load_gitignore(self, directory: Path) -> Set[str]:
        """Load patterns from .gitignore file."""
        patterns = set()
        gitignore_file = directory / ".gitignore"

        if gitignore_file.exists():
            with open(gitignore_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith("#"):
                        patterns.add(line)

        return patterns

    def should_ignore(self, path: Path, base_dir: Path) -> bool:
        """Check if a path should be ignored based on patterns."""
        relative_path = path.relative_to(base_dir)
        path_str = str(relative_path)

        # Check default ignore directories
        for part in relative_path.parts:
            if part in self.DEFAULT_IGNORE_DIRS:
                return True

        # Check custom ignore patterns
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path_str, pattern):
                return True

        # Check gitignore patterns
        if self.use_gitignore:
            for pattern in self.gitignore_patterns:
                # Simple gitignore matching (could be enhanced)
                if fnmatch.fnmatch(path_str, pattern.rstrip("/")):
                    return True
                if fnmatch.fnmatch(path.name, pattern):
                    return True

        return False

    def find_files(self, source_dir: Path) -> List[Path]:
        """Find all matching files in the source directory."""
        files = []

        if not source_dir.exists():
            print(f"⚠️  Warning: {source_dir} does not exist, skipping...")
            return files

        if not source_dir.is_dir():
            print(f"⚠️  Warning: {source_dir} is not a directory, skipping...")
            return files

        # Load gitignore if enabled
        if self.use_gitignore:
            self.gitignore_patterns.update(self.load_gitignore(source_dir))

        print(f"📁 Searching in: {source_dir}")

        for ext in self.extensions:
            pattern = f"**/*{ext}" if not ext.startswith("*") else f"**/{ext}"

            for file_path in source_dir.glob(pattern):
                if file_path.is_file():
                    if self.should_ignore(file_path, source_dir):
                        self.skipped_count += 1
                        continue

                    # Check file size
                    if file_path.stat().st_size > self.max_file_size:
                        print(f"⚠️  Skipping large file: {file_path.relative_to(source_dir)}")
                        self.skipped_count += 1
                        continue

                    files.append(file_path)

        return sorted(files)

    def write_file_content(self, file_path: Path, base_dir: Path, output):
        """Write a single file's content to the output."""
        relative_path = file_path.relative_to(base_dir)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Write header
            output.write("\n" + "=" * 80 + "\n")
            output.write(f"FILE: {relative_path}\n")
            output.write(f"Full path: {file_path.absolute()}\n")
            output.write(f"Size: {file_path.stat().st_size:,} bytes\n")
            output.write(f"Lines: {len(content.splitlines()):,}\n")
            output.write("=" * 80 + "\n\n")

            # Write content
            output.write(content)

            # Ensure file ends with newline
            if not content.endswith("\n"):
                output.write("\n")

            # Write footer
            output.write("\n" + "=" * 80 + "\n")
            output.write(f"END OF FILE: {relative_path}\n")
            output.write("=" * 80 + "\n\n")

            self.file_count += 1
            print(f"  ✓ Added: {relative_path}")

        except Exception as e:
            print(f"  ✗ Error reading {relative_path}: {e}")
            self.skipped_count += 1

    def collect(self):
        """Main collection process."""
        print("\n" + "=" * 80)
        print("PROJECT CONTEXT COLLECTOR")
        print("=" * 80)
        print(f"Output file: {self.output_file}")
        print(f"Extensions: {', '.join(self.extensions)}")
        print(f"Use .gitignore: {self.use_gitignore}")
        print("=" * 80 + "\n")

        all_files = []

        # Collect files from all sources
        for source in self.sources:
            files = self.find_files(source)
            all_files.extend([(f, source) for f in files])

        if not all_files:
            print("⚠️  No files found matching the criteria.")
            return

        # Write to output file
        with open(self.output_file, "w", encoding="utf-8") as output:
            # Write header
            output.write("=" * 80 + "\n")
            output.write("PROJECT CONTEXT DUMP\n")
            output.write("=" * 80 + "\n")
            output.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            output.write(f"Source directories:\n")
            for source in self.sources:
                output.write(f"  - {source.absolute()}\n")
            output.write(f"Total files found: {len(all_files)}\n")
            output.write("=" * 80 + "\n\n")

            # Write each file
            for file_path, base_dir in all_files:
                self.write_file_content(file_path, base_dir, output)

            # Write summary
            output.write("\n" + "=" * 80 + "\n")
            output.write("SUMMARY\n")
            output.write("=" * 80 + "\n")
            output.write(f"Total files processed: {self.file_count}\n")
            output.write(f"Files skipped: {self.skipped_count}\n")
            output.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            output.write("=" * 80 + "\n")

        print("\n" + "=" * 80)
        print(f"✅ Complete! Processed {self.file_count} files")
        print(f"📝 Skipped {self.skipped_count} files")
        print(f"💾 Output saved to: {self.output_file.absolute()}")
        print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Collect project files for AI context",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Current directory
  %(prog)s -s src tests -o context.txt       # Multiple sources
  %(prog)s -s . -e .py .js .ts              # Custom extensions
  %(prog)s -s . -i "*/temp/*" "*.log"       # Ignore patterns
  %(prog)s -s . --no-gitignore               # Disable .gitignore
        """,
    )

    parser.add_argument(
        "-s", "--sources", nargs="+", default=["."], help="Source directories to search (default: current directory)"
    )

    parser.add_argument("-o", "--output", default="project_context.txt", help="Output file path (default: project_context.txt)")

    parser.add_argument(
        "-e",
        "--extensions",
        nargs="+",
        help=f"File extensions to include (default: {' '.join(ProjectContextCollector.DEFAULT_EXTENSIONS)})",
    )

    parser.add_argument("-i", "--ignore", nargs="+", default=[], help="Additional patterns to ignore (glob format)")

    parser.add_argument("--no-gitignore", action="store_true", help="Disable .gitignore integration")

    parser.add_argument("--max-size", type=int, default=1_000_000, help="Maximum file size in bytes (default: 1MB)")

    args = parser.parse_args()

    # Convert sources to Path objects
    sources = [Path(s).resolve() for s in args.sources]
    output_file = Path(args.output)

    collector = ProjectContextCollector(
        sources=sources,
        output_file=output_file,
        extensions=args.extensions,
        ignore_patterns=args.ignore,
        use_gitignore=not args.no_gitignore,
        max_file_size=args.max_size,
    )

    try:
        collector.collect()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
