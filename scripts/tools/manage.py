"""
Project Management CLI
"""

import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from typer.models import Typer

app = Typer(help="Netguard project management commands", add_completion=True)


# ==================================================
# Test Project
# =====================================================
@app.command()
def test(
    path: Optional[str] = typer.Argument(None, help="Path to test file or directory"),
    unit: bool = typer.Option(False, "--unit", "u", help="Run only unit tests"),
    integration: bool = typer.Option(False, "--integration", "-i", help="Run only integration tests"),
    e2e: bool = typer.Option(False, "--e2e", help="Run only end-to-end tests"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    coverage: bool = typer.Option(False, "--coverage", "-c", help="Generate coverage report"),
    html: bool = typer.Option(False, "--html", help="Generate HTML report"),
    quick: bool = typer.Option(False, "--quick", help="Run quick tests with no coverage report"),
    marker: Optional[str] = typer.Option(None, "--marker", "-m", help="Run tests with specific marker"),
    keyword: Optional[str] = typer.Option(None, "--keywords", "-k", help="Run tests with specific keywords"),
    failed: bool = typer.Option(False, "--failed", "--lf", help="Run only failed tests"),
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
    if marker:
        cmd.extend(["-m", marker])
    if keyword:
        cmd.extend(["-k", keyword])
    if failed:
        cmd.append("--lf")
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
    typer.echo("👀 Watching for changes...")
    subprocess.run(["pytest-watch", "--", "-v", "--tb=short"])
    pass


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
def type_check() -> None:
    """Type check code"""
    subprocess.run(["mypy", "."])


# ==========================================================
# Serve Documentation
# ==========================================================


@app.command()
def serve_docs() -> None:
    """Serve documentation"""
    subprocess.run(["mkdocs", "serve"])
