"""
Project Management CLI
"""

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from typer import Typer

# ============================================================================
# App & Command Groups
# ============================================================================

app = Typer(help="Netguard project management commands", add_completion=True)
code_app = Typer(name="code", help="Code quality, formatting, and checking")
docs_app = Typer(name="docs", help="Documentation building and serving")
project_app = Typer(name="project", help="Project utilities and dependency management")
docker_app = Typer(name="docker", help="Docker-related commands")

app.add_typer(code_app)
app.add_typer(docs_app)
app.add_typer(project_app)
app.add_typer(docker_app)


# ============================================================================
# Helper Functions
# ============================================================================


def run_uv_command(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run a command using 'uv run' to ensure it's executed in the virtual environment."""
    return subprocess.run(["uv", "run"] + cmd)


# ============================================================================
# Testing Commands
# ============================================================================


@app.command()
def test(
    path: Optional[str] = typer.Argument(None, help="Specific test path"),
    unit: bool = typer.Option(False, "--unit", "-u", help="Run only unit tests"),
    integration: bool = typer.Option(
        False, "--integration", "-i", help="Run only integration tests"
    ),
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
    result = run_uv_command(cmd)
    sys.exit(result.returncode)


@app.command()
def test_watch():
    """Run tests in watch mode (re-run on file changes)"""
    try:
        typer.echo("👀 Watching for changes...")
        run_uv_command(["pytest-watch", "--", "-v", "--tb=short"])
    except FileNotFoundError:
        typer.secho(
            "❌ pytest-watch not found. Install with: uv add --dev pytest-watch",
            fg=typer.colors.RED,
        )
        sys.exit(1)


# =====================================================
# Code Quality
# =====================================================


@code_app.command("lint")
def lint(
    fix: bool = typer.Option(False, "--fix", help="Fix lint errors"),
    unsafe_fix:bool = typer.Option(False,"--unsafe-fixes",help="3 hidden fixes can be enabled with the '--unsafe-fixes' option")
) -> None:
    """Run linting with ruff"""
    cmd = ["ruff", "check", "src/", "tests/"]
    if fix:
        cmd.append("--fix")
    if unsafe_fix:
        cmd.append("--unsafe-fixes")
    typer.echo("🔍 Linting code...")
    result = run_uv_command(cmd)
    if result.returncode == 0:
        typer.secho("✅ No linting errors!", fg=typer.colors.GREEN)
    else:
        typer.secho("❌ Linting errors found", fg=typer.colors.RED)
    sys.exit(result.returncode)


@code_app.command("format")
def format_code(
    check: bool = typer.Option(False, "--check", help="Check without formatting"),
) -> None:
    """Format code with ruff"""
    cmd = ["ruff", "format"]
    if check:
        cmd.append("--check")
        typer.echo("🔍 Checking code formatting...")
    else:
        typer.echo("🔧 Formatting code...")
    cmd.extend(["src/", "tests/"])
    result = run_uv_command(cmd)
    sys.exit(result.returncode)

@code_app.command("type_check")
def type_check(
        type_checck:bool = typer.Option(False, "--check", help="Type check"),
)->None:
    """Type check with mypy"""
    cmd:list[str] = ["mypy","src/netguard"]
    typer.secho("Checking type annotations",color=True,fg='green')
    result = run_uv_command(cmd)
    sys.exit(result.returncode)


@code_app.command("check")
def check_all() -> None:
    """Run all checks (linting, formatting, type checking, and unit tests)"""
    typer.echo("Running all checks...")
    results = []

    typer.echo("\n1. Checking code formatting...")
    format_result = run_uv_command(["ruff", "format", "--check", "src/", "tests/"])
    results.append(("Formatting", format_result.returncode == 0))

    typer.echo("\n2. Linting code...")
    lint_result = run_uv_command(["ruff", "check", "src/", "tests/"])
    results.append(("Linting", lint_result.returncode == 0))

    typer.echo("\n3. Type checking code...")
    type_check_result = run_uv_command(["mypy", "src/netguard"])
    results.append(("Type Checking", type_check_result.returncode == 0))

    typer.echo("\n4. Running unit tests...")
    test_result = run_uv_command(["pytest", "tests/unit/", "-q", "--tb=short"])
    results.append(("Unit Tests", test_result.returncode == 0))

    typer.echo("\n" + "=" * 60)
    typer.echo("Check Summary:")
    typer.echo("=" * 60)

    for name, passed in results:
        status = "✅ Passed" if passed else "❌ Failed"
        color = typer.colors.GREEN if passed else typer.colors.RED
        typer.secho(f"{name:<20} {status}", fg=color)

    typer.echo("=" * 60)
    all_passed = all(passed for _, passed in results)
    if all_passed:
        typer.secho("\nAll checks passed!", fg=typer.colors.GREEN, bold=True)
        sys.exit(0)
    else:
        typer.secho("\nSome checks failed!", fg=typer.colors.RED, bold=True)
        sys.exit(1)


# ============================================================================
# Documentation
# ============================================================================


@docs_app.command("serve")
def docs_serve(
    port: int = typer.Option(8000, "--port", "-p", help="Port for serving"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open browser on start"),
):
    """Serve docs locally with live-reload."""
    typer.echo(f"📚 Serving documentation at http://127.0.0.1:{port}")
    typer.echo("   Press Ctrl+C to stop\n")
    cmd = ["mkdocs", "serve", "--dev-addr", f"127.0.0.1:{port}"]
    if not open_browser:
        cmd.append("--no-livereload")
    try:
        run_uv_command(cmd)
    except KeyboardInterrupt:
        typer.echo("\n\n👋 Stopping documentation server.")
        sys.exit(0)
    except FileNotFoundError:
        typer.secho("❌ mkdocs not found. Install with: uv add --dev mkdocs", fg=typer.colors.RED)
        sys.exit(1)


@docs_app.command("build")
def docs_build():
    """Build docs to the site/ directory."""
    typer.echo("📖 Building documentation...")
    try:
        result = run_uv_command(["mkdocs", "build"])
        if result.returncode == 0:
            site_dir = Path("site")
            if site_dir.exists():
                html_files = list(site_dir.rglob("*.html"))
                typer.echo("\n📊 Build Statistics:")
                typer.echo(f"   - HTML files: {len(html_files)}")
                typer.echo(f"   - Output dir: {site_dir.resolve()}")
            typer.secho("\n✅ Documentation built successfully!", fg=typer.colors.GREEN)
        else:
            typer.secho("\n❌ Documentation build failed.", fg=typer.colors.RED)
            sys.exit(1)
    except FileNotFoundError:
        typer.secho("❌ mkdocs not found. Install with: uv add --dev mkdocs", fg=typer.colors.RED)
        sys.exit(1)


@docs_app.callback(invoke_without_command=True)
def docs_main(ctx: typer.Context):
    """Build and serve documentation. Defaults to 'serve'."""
    if ctx.invoked_subcommand is None:
        typer.echo("No subcommand specified. Defaulting to 'docs serve'.\n")
        ctx.invoke(docs_serve)


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
    typer.echo("\nPlanned functionality:")
    typer.echo(f"  - Capture {count} packets from {interface}")
    if output:
        typer.echo(f"  - Save to {output}")
    typer.echo("\nThis will use: netguard.capture.packet_capture.PacketCapture")


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
    typer.echo("\nPlanned functionality:")
    typer.echo(f"  - Analyze {input_file}")
    typer.echo(f"  - Using {analyzer} analyzer")
    typer.echo("\nThis will use: netguard.analysis.analyzers")


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
    typer.echo("\nPlanned functionality:")
    typer.echo(f"  - Run {workflows[name]} workflow")
    typer.echo(f"  - Input: {input_file}")
    typer.echo("\nThis will use: netguard.workflows.workflows.WorkflowRunner")


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
    typer.echo("\nPlanned functionality:")
    typer.echo(f"  - Start FastAPI server at http://{host}:{port}")
    typer.echo(f"  - Auto-reload: {reload}")
    typer.echo("\nThis will use: uvicorn netguard.api.main:app")


# ============================================================================
# Project Utilities
# ============================================================================


@project_app.command("clean")
def clean(
    cache: bool = typer.Option(True, "--cache/--no-cache", help="Clean __pycache__"),
    coverage: bool = typer.Option(True, "--coverage/--no-coverage", help="Clean coverage data"),
    docs: bool = typer.Option(True, "--docs/--no-docs", help="Clean documentation build"),
    data: bool = typer.Option(True, "--data/--no-data", help="Clean test data files"),
    all_caches: bool = typer.Option(False, "--all", help="Clean all caches"),
):
    """Clean temporary files and caches"""
    typer.echo("🧹 Cleaning project...\n")
    removed_count = 0

    def rmtree(path: Path):
        nonlocal removed_count
        if path.exists():
            try:
                shutil.rmtree(path)
                typer.echo(f"  - Removed {path}")
                removed_count += 1
            except Exception as e:
                typer.secho(f"  - Failed to remove {path}: {e}", fg=typer.colors.RED)

    def rmfile(path: Path):
        nonlocal removed_count
        if path.exists():
            try:
                path.unlink()
                typer.echo(f"  - Removed {path}")
                removed_count += 1
            except Exception as e:
                typer.secho(f"  - Failed to remove {path}: {e}", fg=typer.colors.RED)

    if cache or all_caches:
        typer.echo("Cleaning Python cache files...")
        for p in Path(".").rglob("__pycache__"):
            rmtree(p)
        for p in Path(".").rglob("*.pyc"):
            rmfile(p)
        for p in Path(".").rglob("*.pyo"):
            rmfile(p)

    if coverage or all_caches:
        typer.echo("\nCleaning test and coverage caches...")
        rmfile(Path(".coverage"))
        rmtree(Path("htmlcov"))
        rmtree(Path(".pytest_cache"))

    if docs or all_caches:
        typer.echo("\nCleaning documentation build...")
        rmtree(Path("site"))

    if data:
        typer.echo("\nCleaning generated data files...")
        data_dir = Path("src/netguard/data")
        # TODO: This could be improved by using a glob pattern from config
        test_files = [data_dir / "testing.parquet", data_dir / "ml_testing.parquet"]
        for file in test_files:
            rmfile(file)

    if all_caches:
        typer.echo("\nCleaning tool caches...")
        rmtree(Path(".ruff_cache"))
        rmtree(Path(".mypy_cache"))

    typer.echo("\n" + "=" * 60)
    if removed_count > 0:
        typer.secho(
            f"✅ Cleanup complete! Removed {removed_count} items.", fg=typer.colors.GREEN, bold=True
        )
    else:
        typer.secho("✨ Project is already clean.", fg=typer.colors.YELLOW, bold=True)


@project_app.command("deps")
def deps(
    tree: bool = typer.Option(False, "--tree", help="Show dependency tree"),
    outdated: bool = typer.Option(False, "--outdated", help="Check for outdated packages"),
    export: bool = typer.Option(False, "--export", help="Export to requirements.txt"),
):
    """Manage and inspect project dependencies."""
    try:
        run_uv_command(["uv", "--version"])
    except (FileNotFoundError, subprocess.CalledProcessError):
        typer.secho(
            "❌ uv not found. Make sure uv is installed and in your PATH.", fg=typer.colors.RED
        )
        sys.exit(1)

    if tree:
        typer.echo("🌳 Dependency Tree\n")
        run_uv_command(["uv", "pip", "tree"])
    elif outdated:
        typer.echo("📦 Checking for Outdated Packages...\n")
        run_uv_command(["uv", "pip", "list", "--outdated"])
    elif export:
        output_file = Path("requirements.txt")
        typer.echo(f"📦 Exporting dependencies to {output_file}...\n")
        result = run_uv_command(["uv", "pip", "freeze"])
        if result.returncode == 0:
            output_file.write_text(result.stdout)
            count = len(
                [
                    line
                    for line in result.stdout.splitlines()
                    if line.strip() and not line.startswith("#")
                ]
            )
            typer.secho(f"✅ Exported {count} packages to {output_file}", fg=typer.colors.GREEN)
        else:
            typer.secho(f"❌ Failed to export dependencies:\n{result.stderr}", fg=typer.colors.RED)
            sys.exit(1)
    else:
        typer.echo("📦 Installed Packages (via uv)\n")
        run_uv_command(["uv", "pip", "list"])


@project_app.command("collect-context")
def collect_context(
    output: Path = typer.Option(
        Path("project_context.txt"), "--output", "-o", help="Output file path"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    deps_tree: bool = typer.Option(False, "--deps-tree", help="Include dependency tree in context"),
    project_tree: bool = typer.Option(
        False, "--project-tree", help="Include project folder tree in context"
    ),
):
    """Collect project context into a single file."""
    typer.echo(f"📋 Collecting project context to {output}...\n")
    script_path = Path("scripts/tools/collect_context.py")
    if not script_path.exists():
        typer.secho(
            f"⚠️ Collection script not found at {script_path}, cannot proceed.",
            fg=typer.colors.YELLOW,
        )
        sys.exit(1)

    cmd = ["python", str(script_path), "--output", str(output)]
    if verbose:
        cmd.append("--verbose")
    if deps_tree:
        cmd.append("--include-deps-tree")
    if project_tree:
        cmd.append("--include-project-tree")

    result = subprocess.run(cmd)
    if result.returncode == 0:
        typer.secho(f"✅ Context collected successfully.", fg=typer.colors.GREEN)
    else:
        typer.secho("❌ Context collection failed.", fg=typer.colors.RED)
        sys.exit(1)


# ============================================================================
# Docker Commands
# ============================================================================


def _get_docker_compose_cmd(prod: bool = False) -> list[str]:
    cmd = ["docker-compose"]
    if prod:
        cmd.extend(["-f", "docker-compose.prod.yml"])
    return cmd


@docker_app.command("up")
def docker_up(
    prod: bool = typer.Option(False, "--prod", help="Use production configuration"),
    build: bool = typer.Option(False, "--build", help="Build images before starting"),
    detach: bool = typer.Option(True, "-d/--no-detach", help="Run in detached mode"),
):
    """Start services with docker-compose."""
    cmd = _get_docker_compose_cmd(prod)
    cmd.append("up")
    if build:
        cmd.append("--build")
    if detach:
        cmd.append("-d")
    typer.echo(f"🐳 Starting services: {' '.join(cmd)}")
    subprocess.run(cmd)


@docker_app.command("down")
def docker_down(
    prod: bool = typer.Option(False, "--prod", help="Use production configuration"),
    volumes: bool = typer.Option(False, "-v", "--volumes", help="Remove named volumes"),
):
    """Stop services with docker-compose."""
    cmd = _get_docker_compose_cmd(prod)
    cmd.append("down")
    if volumes:
        cmd.append("-v")
    typer.echo(f"🐳 Stopping services: {' '.join(cmd)}")
    subprocess.run(cmd)


@docker_app.command("logs")
def docker_logs(
    prod: bool = typer.Option(False, "--prod", help="Use production configuration"),
    follow: bool = typer.Option(True, "-f", "--follow/--no-follow", help="Follow log output"),
    tail: Optional[int] = typer.Option(None, "--tail", help="Number of lines to show from the end"),
):
    """View output from containers."""
    cmd = _get_docker_compose_cmd(prod)
    cmd.append("logs")
    if follow:
        cmd.append("-f")
    if tail:
        cmd.extend(["--tail", str(tail)])
    typer.echo(f"📜 Viewing logs: {' '.join(cmd)}")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        typer.echo("\n👋 Exiting log view.")
        sys.exit(0)


@docker_app.command("build")
def docker_build(
    prod: bool = typer.Option(False, "--prod", help="Use production configuration"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Do not use cache when building"),
):
    """Build or rebuild services."""
    cmd = _get_docker_compose_cmd(prod)
    cmd.append("build")
    if no_cache:
        cmd.append("--no-cache")
    typer.echo(f"🏗️ Building services: {' '.join(cmd)}")
    subprocess.run(cmd)


# ============================================================================
# Interactive Shell & Info
# ============================================================================


@app.command()
def shell():
    """Start an interactive Python shell with pre-imported modules."""
    import code
    from importlib.metadata import version

    typer.echo("🐍 Starting NetGuard interactive shell...")

    context = {}
    imports_successful = []
    imports_failed = []

    def try_import(name, alias=None):
        try:
            module = __import__(name)
            key = alias or name
            context[key] = module
            try:
                ver = version(name)
                imports_successful.append(f"  - {key} ({ver})")
            except Exception:
                imports_successful.append(f"  - {key}")
        except ImportError:
            imports_failed.append(f"  - {name}")

    try_import("polars", "pl")
    try:
        from netguard.capture.packet_capture import PacketCapture

        context["PacketCapture"] = PacketCapture
        imports_successful.append("  - PacketCapture")
    except ImportError:
        imports_failed.append("  - PacketCapture")

    banner = "\n" + "=" * 60 + "\n"
    banner += "  Welcome to the NetGuard Interactive Shell!\n"
    banner += "=" * 60 + "\n"

    if imports_successful:
        banner += "Available imports:\n" + "\n".join(imports_successful)
    if imports_failed:
        banner += "\nFailed imports:\n" + "\n".join(imports_failed)
    banner += "\n" + "=" * 60

    code.interact(banner=banner, local=context)


@app.command()
def info():
    """Show project information and statistics."""
    from importlib.metadata import PackageNotFoundError, version

    typer.echo("=" * 60)
    typer.echo("📋 NetGuard Project Information")
    typer.echo("=" * 60 + "\n")

    typer.echo(f"  - Python version: {sys.version.split()[0]}")
    typer.echo(f"  - Project root:   {Path.cwd()}\n")

    typer.echo("📦 Key Dependencies:")
    packages = ["polars", "scapy", "fastapi", "pytest", "typer", "uv", "ruff", "mypy"]
    for pkg in packages:
        try:
            ver = version(pkg)
            typer.secho(f"  ✓ {pkg:<10} {ver}", fg=typer.colors.GREEN)
        except PackageNotFoundError:
            typer.secho(f"  ✗ {pkg:<10} not installed", fg=typer.colors.YELLOW)

    typer.echo("\n📊 Project Statistics:")
    src_files = list(Path("src/netguard").rglob("*.py"))
    test_files = list(Path("tests").rglob("test_*.py"))
    doc_files = list(Path("docs").rglob("*.md"))

    typer.echo(f"  - Source files:      {len(src_files)}")
    typer.echo(f"  - Test files:        {len(test_files)}")
    typer.echo(f"  - Documentation:     {len(doc_files)} files")

    total_lines = sum(len(p.read_text().splitlines()) for p in src_files)
    typer.echo(f"  - Lines of code:     ~{total_lines:,} (in src)")
    typer.echo("\n" + "=" * 60)


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    app()
