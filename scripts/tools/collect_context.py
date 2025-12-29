#!/usr/bin/env python3
"""
Project Context Collector
Collects source files from a project and outputs them to a single file for AI context.
Supports multiple directories, ignore patterns, and .gitignore integration.
"""

import argparse
import fnmatch
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Tuple


class ProjectContextCollector:
    """Collects project files and outputs them with clear separations."""

    DEFAULT_EXTENSIONS = [".py", ".sh", ".yml", ".yaml", ".md", ".toml"]
    DEFAULT_IGNORE_DIRS = {
        "__pycache__",
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".egg-info",
        ".tox",
        "site",
    }
    TREE_IGNORE_PATTERN = "|".join(
        [d for d in DEFAULT_IGNORE_DIRS if d not in (".git",)]
    )

    def __init__(
        self,
        sources: List[Path],
        output_file: Path,
        extensions: List[str] = None,
        ignore_patterns: List[str] = None,
        use_gitignore: bool = True,
        max_file_size: int = 1_000_000,  # 1MB default
        include_deps_tree: bool = False,
        include_project_tree: bool = False,
    ):
        self.sources = sources
        self.output_file = output_file
        self.extensions = extensions or self.DEFAULT_EXTENSIONS
        self.ignore_patterns = ignore_patterns or []
        self.use_gitignore = use_gitignore
        self.max_file_size = max_file_size
        self.include_deps_tree = include_deps_tree
        self.include_project_tree = include_project_tree
        self.gitignore_patterns = set()
        self.file_count = 0
        self.skipped_count = 0

    def get_system_info(self) -> List[Tuple[str, str]]:
        """Get dependency and project tree information."""
        info = []

        if self.include_deps_tree:
            try:
                result = subprocess.run(
                    ["uv", "pip", "tree"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                info.append(("DEPENDENCY TREE (uv pip tree)", result.stdout))
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                error_msg = f"Could not run 'uv pip tree': {e}"
                info.append(("DEPENDENCY TREE ERROR", error_msg))

        if self.include_project_tree:
            try:
                cmd = [
                    "tree",
                    "-a",
                    "-I",
                    self.TREE_IGNORE_PATTERN,
                ]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                info.append(("PROJECT STRUCTURE (tree)", result.stdout))
            except (subprocess.CalledProcessError, FileNotFoundError):
                error_msg = (
                    "Could not run 'tree'. Please install it (`apt-get install tree` "
                    "or `brew install tree`) for a visual project overview."
                )
                info.append(("PROJECT STRUCTURE ERROR", error_msg))

        return info

    def load_gitignore(self, directory: Path) -> Set[str]:
        """Load patterns from .gitignore file."""
        patterns = set()
        gitignore_file = directory / ".gitignore"

        if gitignore_file.exists():
            with open(gitignore_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.add(line)
        return patterns

    def should_ignore(self, path: Path, base_dir: Path) -> bool:
        """Check if a path should be ignored based on patterns."""
        relative_path = path.relative_to(base_dir)
        path_str = str(relative_path)

        for part in relative_path.parts:
            if part in self.DEFAULT_IGNORE_DIRS:
                return True

        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path_str, pattern):
                return True

        if self.use_gitignore:
            for pattern in self.gitignore_patterns:
                if pattern.endswith("/") and path.is_dir():
                    if fnmatch.fnmatch(path_str + "/", pattern) or fnmatch.fnmatch(path.name + "/", pattern):
                        return True
                if fnmatch.fnmatch(path_str, pattern.rstrip("/")) or fnmatch.fnmatch(path.name, pattern):
                    return True
        return False

    def find_files(self, source_dir: Path) -> List[Path]:
        """Find all matching files in the source directory."""
        files = []
        if not source_dir.is_dir():
            print(f"⚠️  Warning: {source_dir} is not a directory, skipping.")
            return files

        if self.use_gitignore:
            self.gitignore_patterns.update(self.load_gitignore(source_dir))

        print(f"📁 Searching in: {source_dir}")

        for item in source_dir.rglob("*"):
            if self.should_ignore(item, source_dir):
                if item.is_dir():
                    self.skipped_count += 1
                continue

            if item.is_file() and any(item.name.endswith(ext) for ext in self.extensions):
                if item.stat().st_size > self.max_file_size:
                    print(f"⚠️  Skipping large file: {item.relative_to(source_dir)}")
                    self.skipped_count += 1
                    continue
                files.append(item)

        return sorted(list(set(files)))

    def write_file_content(self, file_path: Path, base_dir: Path, output):
        """Write a single file's content to the output."""
        relative_path = file_path.relative_to(base_dir)
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            output.write("\n" + "=" * 80 + "\n")
            output.write(f"FILE: {relative_path}\n")
            output.write("=" * 80 + "\n\n")
            output.write(content)

            if not content.endswith("\n"):
                output.write("\n")

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

        system_info = self.get_system_info()
        all_files = []
        for source in self.sources:
            files = self.find_files(source)
            all_files.extend([(f, source) for f in files])

        if not all_files and not system_info:
            print("⚠️  No files found or system info requested.")
            return

        with open(self.output_file, "w", encoding="utf-8") as output:
            output.write("=" * 80 + "\n")
            output.write("PROJECT CONTEXT DUMP\n")
            output.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            output.write("=" * 80 + "\n\n")

            for title, content in system_info:
                output.write("=" * 80 + "\n")
                output.write(f"{title}\n")
                output.write("=" * 80 + "\n\n")
                output.write(content)
                output.write("\n\n")

            output.write("=" * 80 + "\n")
            output.write("PROJECT FILES\n")
            output.write("=" * 80 + "\n")
            output.write(f"Source directories: {', '.join(str(s) for s in self.sources)}\n")
            output.write(f"Extensions: {', '.join(self.extensions)}\n")
            output.write(f"Total files to process: {len(all_files)}\n")
            output.write("=" * 80 + "\n\n")

            for file_path, base_dir in all_files:
                self.write_file_content(file_path, base_dir, output)

            output.write("\n" + "=" * 80 + "\n")
            output.write("SUMMARY\n")
            output.write("=" * 80 + "\n")
            output.write(f"Total files processed: {self.file_count}\n")
            output.write(f"Items skipped (files/dirs): {self.skipped_count}\n")
            output.write("=" * 80 + "\n")

        print("\n" + "=" * 80)
        print(f"✅ Complete! Processed {self.file_count} files.")
        print(f"📝 Skipped {self.skipped_count} items.")
        print(f"💾 Output saved to: {self.output_file.absolute()}")
        print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Collect project files for AI context.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-s", "--sources", nargs="+", default=["."], help="Source directories (default: .)"
    )
    parser.add_argument(
        "-o", "--output", default="project_context.txt", help="Output file path"
    )
    parser.add_argument(
        "--extensions", nargs="+", help="File extensions to include"
    )
    parser.add_argument(
        "-i", "--ignore", nargs="+", default=[], help="Additional glob patterns to ignore"
    )
    parser.add_argument(
        "--no-gitignore", action="store_true", help="Disable .gitignore integration"
    )
    parser.add_argument(
        "--max-size", type=int, default=1_000_000, help="Max file size in bytes (default: 1MB)"
    )
    parser.add_argument(
        "--include-deps-tree", action="store_true", help="Include dependency tree from 'uv pip tree'"
    )
    parser.add_argument(
        "--include-project-tree", action="store_true", help="Include project structure from 'tree'"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()
    sources = [Path(s).resolve() for s in args.sources]

    collector = ProjectContextCollector(
        sources=sources,
        output_file=Path(args.output),
        extensions=args.extensions,
        ignore_patterns=args.ignore,
        use_gitignore=not args.no_gitignore,
        max_file_size=args.max_size,
        include_deps_tree=args.include_deps_tree,
        include_project_tree=args.include_project_tree,
    )

    try:
        collector.collect()
    except KeyboardInterrupt:
        print("\n\n⚠️ Interrupted by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
