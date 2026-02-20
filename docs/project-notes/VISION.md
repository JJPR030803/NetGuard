# NetGuard Vision

NetGuard is a network security analysis tool built as a Master's thesis project,
designed to demonstrate expertise across systems programming, distributed
architecture, network security, and machine learning.

## What It Is Now
A hybrid Rust/Python CLI tool that captures network packets, runs protocol
analysis, and produces security audit reports. The Rust orchestrator manages
system lifecycle and IPC. The Python core handles capture, analysis, and ML.

## What It's Growing Into
A TUI-first tool with a future web interface. The architecture is deliberately
designed to support this expansion without rewrites — the orchestrator pattern,
IPC envelope format, and capability discovery protocol all exist to make new
frontends trivially addable.

## What It Will Never Be
An attempt to replace Wireshark, Zeek, or Darktrace. NetGuard is focused,
opinionated, and built to demonstrate that a small, well-architected tool
can be more useful than a large, unfocused one.

## Core Bets
- Rust for safety, Python for ecosystem — the hybrid is a feature not a compromise
- CLI first, TUI second, web third — always usable without a GUI
- Capture + Analysis + ML in one tool — no pipeline assembly required
- Thesis-quality engineering that also ships
