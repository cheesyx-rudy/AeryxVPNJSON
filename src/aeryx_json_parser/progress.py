from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


_PROTOCOL_COLORS = {
    "vless": "96",
    "vmess": "94",
    "trojan": "93",
    "ss": "92",
    "ssr": "32",
    "hysteria": "95",
    "hysteria2": "95",
    "hy2": "95",
    "tuic": "35",
    "anytls": "36",
    "socks": "97",
    "socks5": "97",
    "http": "90",
    "https": "90",
}


class ProgressReporter:
    """Live, credential-free progress for logs and the GitHub Actions job summary.

    Progress is written only to the runner workspace and GITHUB_STEP_SUMMARY; the
    publication workflow copies only the final subscription to the public repo.
    """

    def __init__(self, path: Path, timezone_name: str = "Europe/Berlin"):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.summary_path = os.getenv("GITHUB_STEP_SUMMARY", "").strip()
        self._summary_started = False
        try:
            self._timezone = ZoneInfo(timezone_name)
        except (ZoneInfoNotFoundError, ValueError):
            self._timezone = timezone.utc
        force_color = os.getenv("FORCE_COLOR", "").strip().lower()
        self._use_color = (
            os.getenv("GITHUB_ACTIONS", "").lower() == "true"
            or force_color not in {"", "0", "false", "no"}
            or bool(getattr(sys.stdout, "isatty", lambda: False)())
        )

    @staticmethod
    def _clean(value: Any) -> str:
        text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
        return text[:600]

    def _paint(self, value: str, color: str) -> str:
        if not self._use_color:
            return value
        return f"\033[{color}m{value}\033[0m"

    @staticmethod
    def _elapsed_text(elapsed_ms: int) -> str:
        elapsed = max(0, int(elapsed_ms))
        if elapsed >= 1000:
            return f"{elapsed / 1000:.2f}s"
        return f"{elapsed}ms"

    def emit(
        self,
        stage: str,
        message: str,
        details: dict[str, Any] | None = None,
        *,
        summary: bool = True,
        console_message: str | None = None,
    ) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "stage": stage,
            "message": message,
            "details": details or {},
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        details_text = " ".join(f"{key}={value}" for key, value in (details or {}).items())
        rendered = console_message
        if rendered is None:
            rendered = (
                f"[AeryxJSON-Parser] [{stage}] {message}"
                + (f" | {details_text}" if details_text else "")
            )
        print(rendered, flush=True)

        if not summary or not self.summary_path:
            return
        try:
            with Path(self.summary_path).open("a", encoding="utf-8") as fh:
                if not self._summary_started:
                    fh.write(
                        "\n## AeryxJSON-Parser — ход проверки\n\n"
                        "| Этап | Событие | Итог |\n|---|---|---|\n"
                    )
                    self._summary_started = True
                compact = ", ".join(
                    f"{key}: {value}" for key, value in (details or {}).items()
                )
                fh.write(
                    f"| {self._clean(stage)} | {self._clean(message)} | "
                    f"{self._clean(compact or '—')} |\n"
                )
        except OSError:
            # Log/JSON progress remains available if GitHub's summary file cannot be written.
            pass

    def emit_source(
        self,
        domain: str,
        protocols: dict[str, int],
        elapsed_ms: int,
        *,
        error_code: str | None = None,
        invalid: int = 0,
        providers: int = 0,
    ) -> None:
        """Emit one compact, live result for a fetched and parsed source."""
        timestamp = datetime.now(self._timezone).strftime("%H:%M:%S")
        source_label = self._paint("[SOURCE]", "36")
        domain_label = self._paint(domain[:100] or "unknown-source", "96")
        elapsed_label = self._paint(self._elapsed_text(elapsed_ms), "90")
        total = sum(max(0, int(count)) for count in protocols.values())

        if error_code:
            status = f"ERROR {error_code}"
            first_line = (
                f"{timestamp} {source_label} {domain_label} | "
                f"{self._paint(status, '91')} | {elapsed_label}"
            )
        elif not total and providers:
            status = f"DISCOVERED {providers} provider(s)"
            first_line = (
                f"{timestamp} {source_label} {domain_label} | "
                f"{self._paint(status, '93')} | {elapsed_label}"
            )
        else:
            status = f"Quantity {total}"
            extras = f" | Invalid {invalid}" if invalid else ""
            first_line = (
                f"{timestamp} {source_label} {domain_label} | "
                f"{self._paint(status, '92')}{extras} | {elapsed_label}"
            )

        lines = [first_line]
        if protocols:
            protocol_line = " | ".join(
                self._paint(f"{name} {count}", _PROTOCOL_COLORS.get(name.lower(), "97"))
                for name, count in sorted(protocols.items())
                if count > 0
            )
            if protocol_line:
                lines.append(f"    {protocol_line}")
        elif providers and not error_code:
            lines.append(f"    providers {providers}")

        details = {
            "domain": domain,
            "status": "error" if error_code else ("discovered" if providers and not total else "ok"),
            "error_code": error_code,
            "quantity": total,
            "protocols": protocols,
            "invalid": invalid,
            "providers_discovered": providers,
            "elapsed_ms": max(0, int(elapsed_ms)),
        }
        self.emit(
            "source",
            status,
            details,
            console_message="\n".join(lines),
        )
