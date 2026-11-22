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

    @staticmethod
    def _source_ref(source_index: int, source_total: int | None = None) -> str:
        if source_total:
            return f"#{source_index:02d}/{source_total}"
        return f"#{source_index:02d}"

    def emit_source_queued(self, source_index: int, source_total: int, domain: str) -> None:
        source_ref = self._paint(self._source_ref(source_index, source_total), "90")
        label = self._paint("[QUEUED]", "93")
        host = self._paint(domain[:100] or "unknown-source", "96")
        self.emit(
            "source_queued",
            "Источник добавлен в очередь",
            {"source_index": source_index, "source_total": source_total, "domain": domain},
            summary=False,
            console_message=f"{label} {source_ref} {host}",
        )

    def emit_source_started(
        self,
        source_index: int,
        source_total: int | None,
        domain: str,
    ) -> None:
        source_ref = self._paint(self._source_ref(source_index, source_total), "90")
        label = self._paint("[FETCHING]", "94")
        host = self._paint(domain[:100] or "unknown-source", "96")
        self.emit(
            "source_fetch_started",
            "Начата загрузка источника",
            {"source_index": source_index, "source_total": source_total, "domain": domain},
            summary=False,
            console_message=f"{label} {source_ref} {host}",
        )

    def emit_source(
        self,
        domain: str,
        protocols: dict[str, int],
        elapsed_ms: int,
        *,
        error_code: str | None = None,
        invalid: int = 0,
        providers: int = 0,
        source_index: int | None = None,
        source_total: int | None = None,
    ) -> None:
        """Emit one compact, live result for a fetched and parsed source."""
        timestamp = datetime.now(self._timezone).strftime("%H:%M:%S")
        source_label = self._paint("[SOURCE]", "36")
        source_ref = (
            self._paint(self._source_ref(source_index, source_total), "90") + " "
            if source_index is not None
            else ""
        )
        domain_label = self._paint(domain[:100] or "unknown-source", "96")
        elapsed_label = self._paint(self._elapsed_text(elapsed_ms), "90")
        total = sum(max(0, int(count)) for count in protocols.values())

        if error_code:
            status = f"ERROR {error_code}"
            first_line = (
                f"{timestamp} {source_label} {source_ref}{domain_label} | "
                f"{self._paint(status, '91')} | {elapsed_label}"
            )
        elif not total and providers:
            status = f"DISCOVERED {providers} provider(s)"
            first_line = (
                f"{timestamp} {source_label} {source_ref}{domain_label} | "
                f"{self._paint(status, '93')} | {elapsed_label}"
            )
        else:
            status = f"Quantity {total}"
            extras = f" | Invalid {invalid}" if invalid else ""
            first_line = (
                f"{timestamp} {source_label} {source_ref}{domain_label} | "
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
            "source_index": source_index,
            "source_total": source_total,
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

    def emit_source_summary(
        self,
        source_results: list[dict[str, Any]],
        source_inventory: dict[str, int],
        *,
        configured_manifest: list[dict[str, Any]] | None = None,
        submitted_total: int,
        parsed_configs: int,
        unique_configs: int,
    ) -> dict[str, Any]:
        """Print and persist the complete per-source parsing breakdown."""
        ordered = sorted(
            source_results,
            key=lambda item: int(item.get("source_index", 0)),
        )
        initial_count = int(source_inventory.get("unique_sources", 0))
        processed_indexes = {
            int(item.get("source_index", 0))
            for item in ordered
        }
        # Always render every configured entry in the final report. If the global
        # runtime/source cap prevented a fetch, show it explicitly instead of making
        # the report appear to begin at an arbitrary later source number.
        missing_configured = [
            {
                "source_index": int(item["source_index"]),
                "domain": str(item.get("domain") or "unknown-source"),
                "parse_status": "not_processed",
                "parse_error_code": "NOT_PROCESSED",
                "parsed_nodes": 0,
                "protocol_counts": {},
                "invalid_links": 0,
                "providers_discovered": 0,
            }
            for item in (configured_manifest or [])
            if int(item["source_index"]) not in processed_indexes
        ]
        ordered = sorted(
            [*ordered, *missing_configured],
            key=lambda item: int(item.get("source_index", 0)),
        )
        initial_processed = sum(
            1 for item in ordered
            if int(item.get("source_index", 0)) <= initial_count
        )
        protocol_totals: dict[str, int] = {}
        for item in ordered:
            for protocol, count in (item.get("protocol_counts") or {}).items():
                protocol_totals[protocol] = protocol_totals.get(protocol, 0) + int(count)

        result = {
            **source_inventory,
            "submitted_total": int(submitted_total),
            "processed_total": len(source_results),
            "initial_processed": initial_processed,
            "initial_not_processed": max(0, initial_count - initial_processed),
            "source_errors": sum(1 for item in source_results if item.get("parse_status") == "error"),
            "parsed_configs": int(parsed_configs),
            "unique_configs_after_deduplication": int(unique_configs),
            "protocol_totals": dict(sorted(protocol_totals.items())),
        }

        lines = [
            self._paint(
                "[SOURCE SUMMARY] "
                f"configured={result['configured_sources']} | "
                f"unique={result['unique_sources']} | "
                f"exact_duplicates_skipped={result['duplicates_skipped']} | "
                f"initial_processed={initial_processed}/{initial_count} | "
                f"all_processed={len(source_results)}/{submitted_total} | "
                f"errors={result['source_errors']}",
                "96",
            ),
            self._paint(
                "[PARSED TOTAL] "
                f"extracted={parsed_configs} | "
                f"unique_after_dedup={unique_configs}",
                "92",
            ),
        ]
        if protocol_totals:
            lines.append(
                "[PROTOCOL TOTALS] "
                + " | ".join(
                    f"{name} {count}"
                    for name, count in sorted(protocol_totals.items())
                    if count > 0
                )
            )
        lines.append("[SOURCE BREAKDOWN]")
        for item in ordered:
            index = int(item.get("source_index", 0))
            source_total = initial_count if index <= initial_count else None
            source_ref = self._source_ref(index, source_total)
            domain = str(item.get("domain") or item.get("name") or "unknown-source")
            status = str(item.get("parse_status") or "unknown").upper()
            error_code = str(item.get("parse_error_code") or "")
            if error_code:
                status = f"ERROR {error_code}"
            protocols = item.get("protocol_counts") or {}
            protocol_text = " | ".join(
                f"{name} {count}"
                for name, count in sorted(protocols.items())
                if int(count) > 0
            ) or "no supported configs"
            lines.append(
                f"{source_ref} {domain} | {status} | "
                f"parsed={int(item.get('parsed_nodes', 0))} | {protocol_text}"
            )

        self.emit(
            "source_summary",
            "Сводка по всем источникам",
            result,
            summary=False,
            console_message="\n".join(lines),
        )

        if self.summary_path:
            try:
                with Path(self.summary_path).open("a", encoding="utf-8") as fh:
                    fh.write("\n### Источники и количество конфигураций\n\n")
                    fh.write(
                        "| № | Источник | Статус | Спарсено | Протоколы | Ошибки ссылок |\n"
                        "|---:|---|---|---:|---|---:|\n"
                    )
                    for item in ordered:
                        index = int(item.get("source_index", 0))
                        source_total = initial_count if index <= initial_count else None
                        source_ref = self._source_ref(index, source_total)
                        domain = self._clean(item.get("domain") or item.get("name") or "unknown-source")
                        status = self._clean(item.get("parse_status") or "unknown")
                        if item.get("parse_error_code"):
                            status += " (" + self._clean(item["parse_error_code"]) + ")"
                        protocols = item.get("protocol_counts") or {}
                        protocol_text = self._clean(
                            ", ".join(
                                f"{name}: {count}"
                                for name, count in sorted(protocols.items())
                                if int(count) > 0
                            ) or "нет"
                        )
                        fh.write(
                            f"| {source_ref} | {domain} | {status} | "
                            f"{int(item.get('parsed_nodes', 0))} | {protocol_text} | "
                            f"{int(item.get('invalid_links', 0))} |\n"
                        )
                    fh.write(
                        "\n**Итого:** "
                        f"{result['parsed_configs']} извлечено, "
                        f"{result['unique_configs_after_deduplication']} уникальных после дедупликации; "
                        f"{result['processed_total']} источников обработано, "
                        f"{result['source_errors']} с ошибкой.\n"
                    )
            except OSError:
                pass
        return result
