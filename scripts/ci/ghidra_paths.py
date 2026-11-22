"""Resolve platform-specific Ghidra launcher paths."""

import os
from pathlib import Path


def analyze_headless(ghidra_home: Path) -> str:
    """Return the executable headless launcher for this host platform."""
    launcher_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    launcher = ghidra_home / "support" / launcher_name
    if not launcher.is_file():
        raise FileNotFoundError(f"Ghidra headless launcher not found: {launcher}")
    return str(launcher)
