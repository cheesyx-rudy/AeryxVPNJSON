"""Safe diagnostics helpers for official Xray-core config validation."""
from __future__ import annotations

import re
from pathlib import Path
from subprocess import CompletedProcess


def safe_xray_diagnostic(proc: CompletedProcess[str], config_path: Path) -> str | None:
    """Combine both output streams and prefer actionable errors over warning noise."""
    # Xray can write deprecation warnings to stderr and the actual parse/start error
    # to stdout. Choosing stderr with ``or`` masks the useful explanation.
    streams = [str(proc.stderr or ""), str(proc.stdout or "")]
    raw = "\n".join(part.strip() for part in streams if part.strip()).strip()
    if not raw:
        return None
    raw = raw.replace(str(config_path), "<config>")
    raw = re.sub(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>", raw)
    raw = re.sub(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", "<ip>", raw)
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        return None

    actionable_tokens = (
        "failed to start", "failed to load", "failed to build", "invalid", "unsupported",
        "not found", "not permitted", "prohibited", "cannot", "parse error", "decode error",
        "unknown field", "unknown config", "error:", "fatal:",
    )
    # Drop warning/deprecation lines unless they are all the program emitted.
    non_warning = [line for line in lines if not re.search(r"(?i)\bwarning\b|deprecated", line)]
    candidates = non_warning or lines
    chosen = next(
        (line for line in candidates if any(token in line.lower() for token in actionable_tokens)),
        candidates[-1],
    )
    # Avoid publishing complete or potentially sensitive debug output.
    return chosen[:500] or None
