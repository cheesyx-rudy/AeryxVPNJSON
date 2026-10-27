from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ProgressReporter:
    """Live, credential-free progress for logs and the GitHub Actions job summary.

    Progress is written only to the runner workspace and GITHUB_STEP_SUMMARY; the
    publication workflow copies only the final subscription to the public repo.
    """

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.summary_path = os.getenv("GITHUB_STEP_SUMMARY", "").strip()
        self._summary_started = False

    @staticmethod
    def _clean(value: Any) -> str:
        text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
        return text[:600]

    def emit(self, stage: str, message: str, details: dict[str, Any] | None = None,
             *, summary: bool = True) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "stage": stage,
            "message": message,
            "details": details or {},
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        details_text = " ".join(f"{key}={value}" for key, value in (details or {}).items())
        print(f"[AeryxJSON-Parser] [{stage}] {message}" + (f" | {details_text}" if details_text else ""), flush=True)

        if not summary or not self.summary_path:
            return
        try:
            with Path(self.summary_path).open("a", encoding="utf-8") as fh:
                if not self._summary_started:
                    fh.write("\n## AeryxJSON-Parser — ход проверки\n\n| Этап | Событие | Итог |\n|---|---|---|\n")
                    self._summary_started = True
                compact = ", ".join(f"{key}: {value}" for key, value in (details or {}).items())
                fh.write(f"| {self._clean(stage)} | {self._clean(message)} | {self._clean(compact or '—')} |\n")
        except OSError:
            # Log/JSON progress remains available if GitHub's summary file cannot be written.
            pass
