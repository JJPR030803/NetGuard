"""
Project Management CLI
"""

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from typer.models import Typer

app = Typer(help="Netguard project management commands", add_completion=True)


# ============================================================================
# Testing Commands
# ============================================================================


@app.command()
def test(
    path: Optional[str] = typer.Argument(None, help="Specific test path"),
    unit: bool = typer.Option(False, "--unit", "-u", help="Run only unit tests"),
    integration: bool = typer.Option(False, "--integration", "-i", help="Run only integration tests"),
    e2e: bool = typer.Option(False, "--e2e", help="Run only e2e tests"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
    coverage: bool = typer.Option(True, "--cov/--no-cov", help="Run with coverage"),
    html: bool = typer.Option(False, "--html", help="Generate HTML coverage report"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Quick run (no coverage)"),
    marker: Optional[str] = typer.Option(None, "-m", help="Run tests with specific marker"),
    keyword: Optional[str] = typer.Option(None, "-k", help="Run tests matching keyword"),
    failed: bool = typer.Option(False, "--failed", "--lf", help="Run last failed tests"),
    parallel: bool = typer.Option(False, "-n", "--parallel", help="Run tests in parallel"),
):
    """Run tests with pytest"""
    cmd = ["pytest"]

    # Test selection
    if path:
        cmd.append(path)
    elif unit:
        cmd.append("tests/unit/")
    elif integration:
        cmd.append("tests/integration/")
    elif e2e:
        cmd.append("tests/e2e/")

    # Markers
    if marker:
        cmd.extend(["-m", marker])

    # Keyword filtering
    if keyword:
        cmd.extend(["-k", keyword])

    # Failed tests only
    if failed:
        cmd.append("--lf")

    # Verbosity
    if verbose:
        cmd.append("-vv")

    # Coverage
    if coverage and not quick:
        cmd.extend(["--cov=src/netguard", "--cov-report=term-missing"])
        if html:
            cmd.append("--cov-report=html")

    # Parallel execution
    if parallel:
        cmd.extend(["-n", "auto"])

    typer.echo(f"🧪 Running tests: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    sys.exit(result.returncode)


@app.command()
def test_watch():
    """Run tests in watch mode (re-run on file changes)"""
    try:
        typer.echo("👀 Watching for changes...")
        subprocess.run(["pytest-watch", "--", "-v", "--tb=short"])
    except FileNotFoundError:
        typer.secho(
            "❌ pytest-watch not found. Install with: uv add --dev pytest-watch",
            fg=typer.colors.RED,
        )
        sys.exit(1)


# =====================================================
# Code Quality
# =====================================================


@app.command()
def lint(
    fix: bool = typer.Option(False, "--fix", help="Fix lint errors"),
    check_only: bool = typer.Option(False, "--check", help="Check without fixing"),
) -> None:
    """Run linting with ruff"""
    cmd = ["ruff", "check", "src/", "tests/"]
    if fix:
        cmd.append("--fix")
    typer.echo("🔍 Linting code...")
    result = subprocess.run(cmd)
    if result.returncode == 0:
        typer.secho("✅ No linting errors!", fg=typer.colors.GREEN)
    else:
        typer.secho("❌ Linting errors found", fg=typer.colors.RED)
    sys.exit(result.returncode)


@app.command()
def format(
    check: bool = typer.Option(False, "--check", help="Check without formatting"),
) -> None:
    """Format code"""
    cmd = ["ruff", "format"]
    if check:
        cmd.append("--check")
        typer.echo("🔍 Checking code formatting...")
    else:
        typer.echo("🔧 Formatting code...")
    cmd.extend(["src/", "tests/"])
    result = subprocess.run(cmd)
    sys.exit(result.returncode)


@app.command()
def check() -> None:
    """Run all checks (linting, formatting, type checking)"""
    typer.echo("Running all checks...")
    results = []
    # Format checks)
    typer.echo("1. Formatting code...")
    format_result = subprocess.run(["ruff", "format", "src/", "tests/"])
    results.append(("Formatting", format_result.returncode == 0))
    # Lint checks
    typer.echo("2. Linting code...")
    lint_result = subprocess.run(["ruff", "check", "src/", "tests/"])
    results.append(("Linting", lint_result.returncode == 0))
    # Type checks
    typer.echo("3. Type checking code...")
    type_check_result = subprocess.run(["mypy", "src/netguard"])
    results.append(("Type Checking", type_check_result.returncode == 0))
    # Tests
    typer.echo("4. Running tests...")
    test_result = subprocess.run(["pytest", "-m", "unit", "-q", "--tb=no"])
    results.append(("Tests", test_result.returncode == 0))
    typer.echo("\n" + "=" * 50)
    # Summary
    typer.echo("\n" + "=" * 60)
    typer.echo("Check Summary:")
    typer.echo("=" * 60)

    for name, passed in results:
        status = "Passed" if passed else "Failed"
        color = typer.colors.GREEN if passed else typer.colors.RED
        typer.secho(f"{status} {name}", fg=color)
    typer.echo("=" * 60)
    all_passed = all(passed for _, passed in results)
    if all_passed:
        typer.secho("All checks passed!", fg=typer.colors.GREEN, bold=True)
        sys.exit(0)
    else:
        typer.secho("Some checks failed!", fg=typer.colors.RED, bold=True)
        sys.exit(1)


# ==========================================================
# Serve Documentation
# ==========================================================
@app.command()
def docs(
    serve: bool = typer.Option(False, "--serve/--build", help="Serve or build documentation"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to serve documentation on"),
    open_browser: bool = typer.Option(False, "--open/--no-open", help="Open browser after serving"),
) -> None:
    """Build and serve documentation locally with MkDocs"""
    if serve:
        typer.secho("Serving Documentation at http://localhost:8000", color=True, fg=typer.colors.GREEN, bold=True)
        typer.secho(f"Serving Documentation at http://127.0.0.1:{port}", color=True, fg=typer.colors.GREEN, bold=True)
        typer.echo("Press Ctrl+C to stop the server.")

        cmd = ["mkdocs", "serve", "--dev-addr", f"127.0.0.1:{port}"]

        if not open_browser:
            cmd.append("--no-livereload")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            typer.secho("Documentation server stopped.", color=True, fg=typer.colors.GREEN, bold=True)
        else:
            typer.echo("Building Documentation...")
            result = subprocess.run(["mkdocs", "build"])
            if result.returncode == 0:
                typer.secho("Documentation built successfully!", color=True, fg=typer.colors.GREEN, bold=True)
            else:
                typer.secho("Documentation build failed!", color=True, fg=typer.colors.RED, bold=True)
                sys.exit(1)


# ============================================================================
# Network Capture & Analysis - TODO
# ============================================================================


@app.command()
def capture(
    interface: str = typer.Option("eth0", "--interface", "-i", help="Network interface"),
    count: int = typer.Option(100, "--count", "-c", help="Number of packets"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
):
    """[TODO] Capture network packets"""
    typer.secho("🚧 TODO: Packet capture not yet implemented", fg=typer.colors.YELLOW)
    typer.echo(f"\nPlanned functionality:")
    typer.echo(f"  - Capture {count} packets from {interface}")
    if output:
        typer.echo(f"  - Save to {output}")
    typer.echo(f"\nThis will use: netguard.capture.packet_capture.PacketCapture")


@app.command()
def analyze(
    input_file: Path = typer.Argument(..., help="Input parquet file"),
    analyzer: str = typer.Option("tcp", "--analyzer", "-a", help="Analyzer type"),
):
    """[TODO] Analyze captured packets"""
    if not input_file.exists():
        typer.secho(f"❌ File not found: {input_file}", fg=typer.colors.RED)
        sys.exit(1)

    typer.secho("🚧 TODO: Analysis not yet implemented", fg=typer.colors.YELLOW)
    typer.echo(f"\nPlanned functionality:")
    typer.echo(f"  - Analyze {input_file}")
    typer.echo(f"  - Using {analyzer} analyzer")
    typer.echo(f"\nThis will use: netguard.analysis.analyzers")


@app.command()
def workflow(
    name: str = typer.Argument(..., help="Workflow name"),
    input_file: Path = typer.Option(..., "--input", "-i", help="Input file"),
):
    """[TODO] Run analysis workflow"""
    workflows = {
        "daily-audit": "Daily Security Audit",
        "threat-hunt": "Threat Hunting",
        "ip-investigation": "IP Investigation",
    }

    if name not in workflows:
        typer.secho(f"❌ Unknown workflow: {name}", fg=typer.colors.RED)
        typer.echo(f"Available workflows: {', '.join(workflows.keys())}")
        sys.exit(1)

    if not input_file.exists():
        typer.secho(f"❌ File not found: {input_file}", fg=typer.colors.RED)
        sys.exit(1)

    typer.secho("🚧 TODO: Workflows not yet implemented", fg=typer.colors.YELLOW)
    typer.echo(f"\nPlanned functionality:")
    typer.echo(f"  - Run {workflows[name]} workflow")
    typer.echo(f"  - Input: {input_file}")
    typer.echo(f"\nThis will use: netguard.workflows.workflows.WorkflowRunner")


# ============================================================================
# FastAPI Server - TODO
# ============================================================================


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind"),
    reload: bool = typer.Option(True, "--reload/--no-reload", help="Auto-reload"),
):
    """[TODO] Start the FastAPI development server"""
    typer.secho("🚧 TODO: API server not yet implemented", fg=typer.colors.YELLOW)
    typer.echo(f"\nPlanned functionality:")
    typer.echo(f"  - Start FastAPI server at http://{host}:{port}")
    typer.echo(f"  - Auto-reload: {reload}")
    typer.echo(f"\nThis will use: uvicorn netguard.api.main:app")


# ============================================================================
# Data & Utilities
# ============================================================================


@app.command()
def clean(
    cache: bool = typer.Option(True, "--cache/--no-cache", help="Clean __pycache__"),
    coverage: bool = typer.Option(True, "--coverage/--no-coverage", help="Clean coverage data"),
    docs: bool = typer.Option(True, "--docs/--no-docs", help="Clean documentation"),
    data: bool = typer.Option(True, "--data/--no-data", help="Clean test data files"),
    all: bool = typer.Option(False, "--all/--no-all", help="Clean everything"),
):
    """Clean temporary files and caches"""
    typer.echo("Cleaning project...\n")

    removed_count = 0

    if cache or all:
        typer.echo("Cleaning Python cache files....")
        for pycache in Path(".").rglob("__pycache__"):
            try:
                shutil.rmtree(pycache)
                typer.echo(f"Removed {pycache}")
                removed_count += 1
            except Exception as e:
                typer.echo(f"Failed to remove {pycache}: {e}")
        for pyc in Path(".").rglob("*.pyc"):
            try:
                pyc.unlink()
                typer.echo(f"Removed {pyc}")
                removed_count += 1
            except Exception as e:
                typer.echo(f"Failed to remove {pyc}: {e}")
        for pyo in Path(".").rglob("*.pyo"):
            try:
                pyo.unlink()
                typer.echo(f"Removed {pyo}")
                removed_count += 1
            except Exception as e:
                typer.echo(f"Failed to remove {pyo}: {e}")
    if coverage or all:
        typer.echo("Cleaning coverage data...")
        paths = [Path(".coverage"), Path("htmlcov"), Path(".pytest_cache")]
        for path in paths:
            if path.exists():
                try:
                    if path.is_dir():
                        shutil.rmtree(path)
                    else:
                        path.unlink()
                    typer.echo(f"Removed {path}")
                except Exception as e:
                    typer.echo(f"Failed to remove {path}: {e}")
    if docs or all:
        typer.echo("Cleaning documentation...")
        site_dir = Path("site")
        if site_dir.exists():
            try:
                shutil.rmtree(site_dir)
                typer.echo(f"Removed {site_dir}")
            except Exception as e:
                typer.echo(f"Failed to remove {site_dir}: {e}")
    if data or all:
        typer.echo("Cleaning test data files...")
        data_dir = Path("src/netguard/data")
        if data_dir.exists():
            # TODO: improve hardcoded paths
            test_files = [data_dir / "testing.parquet", data_dir / "ml_testing.parquet"]
            for file in test_files:
                if file.exists():
                    try:
                        file.unlink()
                        typer.echo(f"Removed {file}")
                        removed_count += 1
                    except Exception as e:
                        typer.echo(f"Failed to remove {file}: {e}")
    ruff_cache = Path(".ruff_cache")
    if ruff_cache.exists():
        try:
            shutil.rmtree(ruff_cache)
            typer.echo(f"\n Removed {ruff_cache}")
            removed_count += 1
        except Exception as e:
            typer.echo(f"\n Failed to remove {ruff_cache}: {e}")

    # Clean mypy cache
    my_py_cache = Path(".mypy_cache")
    if my_py_cache.exists():
        try:
            shutil.rmtree(my_py_cache)
            typer.echo(f"\n Removed {my_py_cache}")
            removed_count += 1
        except Exception as e:
            typer.echo(f"\n Failed to remove {my_py_cache}: {e}")

    # Summary
    typer.echo("\n" + "=" * 60)
    if removed_count > 0:
        typer.secho(f"Cleanup complete! Removed {removed_count} items", fg=typer.colors.GREEN, bold=True)
    else:
        typer.secho("No items to remove", fg=typer.colors.YELLOW, bold=True)
