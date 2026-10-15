"""External CLI tool availability reporting.

Many modules shell out to optional external binaries (nuclei, subfinder,
amass, ...). When a binary is missing the scan continues but that capability
silently contributes nothing. Printing a one-shot availability summary at
startup makes it obvious which capabilities are actually active, so a partial
run is never mistaken for a complete one.
"""

from __future__ import annotations

import shutil

import utils.colors as colors
from utils.colors import log_info, log_success, log_warning

# Binary -> short capability it powers. Curated to the external CLI tools the
# scanner actually invokes; keep in sync with new tool integrations.
EXTERNAL_TOOLS: dict[str, str] = {
    "nuclei": "template-based vuln scanning",
    "subfinder": "passive subdomain enum",
    "amass": "subdomain enum (OWASP)",
    "assetfinder": "subdomain enum",
    "puredns": "DNS brute/resolve",
    "ffuf": "content/endpoint fuzzing",
    "gobuster": "directory/content brute",
    "katana": "crawling",
    "nmap": "port/service scanning",
    "masscan": "fast port scanning",
    "sqlmap": "SQL injection exploitation",
    "nikto": "web server scanning",
    "trufflehog": "secret scanning (2nd opinion)",
    "garak": "LLM red-teaming",
    "docker": "sandboxed exploit execution",
    "git": "repo history scanning",
}


def check_tool_availability(tools: dict[str, str] | None = None) -> dict[str, bool]:
    """Return a mapping of tool name -> whether its binary is on PATH."""
    catalog = tools if tools is not None else EXTERNAL_TOOLS
    return {name: shutil.which(name) is not None for name in catalog}


def print_tool_availability(tools: dict[str, str] | None = None) -> dict[str, bool]:
    """Print a compact present/missing summary and return the availability map.

    Suppressed entirely in quiet mode (only ``log_info`` honours the quiet
    flag, so the whole summary is gated explicitly here).
    """
    catalog = tools if tools is not None else EXTERNAL_TOOLS
    availability = check_tool_availability(catalog)

    if colors.QUIET_MODE:
        return availability

    present = sorted(name for name, ok in availability.items() if ok)
    missing = sorted(name for name, ok in availability.items() if not ok)

    log_info(
        f"External tools: {len(present)}/{len(catalog)} available"
    )
    if present:
        log_success(f"Active: {', '.join(present)}")
    if missing:
        detail = ", ".join(f"{name} ({catalog[name]})" for name in missing)
        log_warning(
            f"Unavailable ({len(missing)}) — related checks will be skipped: {detail}"
        )

    return availability
