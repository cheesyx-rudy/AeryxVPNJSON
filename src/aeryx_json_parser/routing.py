from __future__ import annotations

import base64
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temp_name, path)
    finally:
        try:
            Path(temp_name).unlink(missing_ok=True)
        except Exception:
            pass


def refresh_happ_routing(profile_path: Path, deeplink_path: Path) -> str:
    raw = profile_path.read_text(encoding="utf-8-sig")
    profile: Any = json.loads(raw)
    if not isinstance(profile, dict):
        raise ValueError("Happ routing profile must be a JSON object")
    required = {"Name", "GlobalProxy", "RouteOrder"}
    missing = required - set(profile)
    if missing:
        raise ValueError("Happ routing profile missing keys: " + ", ".join(sorted(missing)))
    profile["LastUpdated"] = str(int(time.time()))
    compact = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    link = "happ://routing/onadd/" + base64.b64encode(compact).decode("ascii")
    _atomic_text(profile_path, json.dumps(profile, ensure_ascii=False, indent=2) + "\n")
    _atomic_text(deeplink_path, link + "\n")
    return link
