from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class ProgressReporter:
    """Structured live progress with local timestamps and elapsed stage timings."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.summary_path = os.getenv("GITHUB_STEP_SUMMARY", "").strip()
        timezone_name = os.getenv("AERYX_LOG_TIMEZONE", "Europe/Moscow")
        try:
            self.timezone = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError:
            self.timezone = ZoneInfo("UTC")
        self.timezone_name = timezone_name if self.timezone.key == timezone_name else "UTC"
        self.started_monotonic = time.monotonic()
        self.stage_started: dict[str, float] = {}
        self.sequence = 0
        self._lock = threading.Lock()
        self._summary_started = False

    def local_timestamp(self) -> str:
        return datetime.now(self.timezone).isoformat(timespec="seconds")

    @staticmethod
    def _clean(value: Any) -> str:
        text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
        return text[:300]

    @staticmethod
    def _duration(seconds: float) -> str:
        seconds = max(0.0, seconds)
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes, remainder = divmod(seconds, 60)
        if minutes < 60:
            return f"{int(minutes)}m {remainder:04.1f}s"
        hours, remainder = divmod(minutes, 60)
        return f"{int(hours)}h {int(remainder):02d}m {remainder % 1 * 60:04.1f}s"

    def emit(
        self,
        stage: str,
        message: str,
        details: dict[str, Any] | None = None,
        *,
        summary: bool = True,
    ) -> None:
        monotonic_now = time.monotonic()
        with self._lock:
            self.sequence += 1
            stage_started = self.stage_started.setdefault(stage, monotonic_now)
            elapsed = monotonic_now - self.started_monotonic
            stage_elapsed = monotonic_now - stage_started
            timestamp = datetime.now(self.timezone)
            event = {
                "sequence": self.sequence,
                "timestamp": timestamp.isoformat(timespec="seconds"),
                "timezone": self.timezone_name,
                "elapsed_seconds": round(elapsed, 3),
                "stage_elapsed_seconds": round(stage_elapsed, 3),
                "stage": stage,
                "message": message,
                "details": details or {},
            }
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")

            detail_text = " | ".join(
                f"{key}={value}" for key, value in (details or {}).items()
            )
            line = (
                f"[{timestamp:%H:%M:%S}] [+{self._duration(elapsed)}] "
                f"[{self.sequence:04d}] [{stage.upper()}] {message} "
                f"(этап: {self._duration(stage_elapsed)})"
            )
            if detail_text:
                line += f" | {detail_text}"
            print(line, flush=True)

            if not summary or not self.summary_path:
                return
            try:
                with Path(self.summary_path).open("a", encoding="utf-8") as fh:
                    if not self._summary_started:
                        fh.write(
                            "\n## AeryxJSON-Parser — ход выполнения\n\n"
                            f"Часовой пояс: {self.timezone_name}. "
                            "Время — локальное; + — время с начала запуска.\n\n"
                            "| Время | С начала | Этап | Событие | Подробности |\n"
                            "|---:|---:|---|---|---|\n"
                        )
                        self._summary_started = True
                    compact = ", ".join(
                        f"{key}: {value}" for key, value in (details or {}).items()
                    )
                    fh.write(
                        f"| {timestamp:%H:%M:%S} | +{self._duration(elapsed)} | "
                        f"{self._clean(stage)} | {self._clean(message)} | "
                        f"{self._clean(compact or '—')} |\n"
                    )
            except OSError:
                pass

    def write_final_summary(self, report: dict[str, Any]) -> None:
        """Append the stage timeline, counters, and publication decision."""
        if not self.summary_path:
            return
        counts = report.get("counts") or {}
        validation = report.get("validation") or {}
        publish = report.get("publish") or {}
        status_counts = validation.get("status_counts") or {}
        confidence = validation.get("confidence_counts") or {}
        source_rows = report.get("sources") or []
        stages = report.get("stages") or []
        lines = [
            "\n## AeryxJSON-Parser — итог запуска\n",
            f"Часовой пояс: {self.timezone_name}. "
            f"Начало: {report.get('started_at_local', '—')}; "
            f"окончание: {report.get('finished_at_local', '—')}.\n",
            "| Показатель | Значение |",
            "|---|---:|",
            f"| Источников в списке | {counts.get('configured_sources', 0)} |",
            f"| Источников обработано | {counts.get('fetched_sources', 0)} |",
            f"| Успешных загрузок | {counts.get('successful_sources', 0)} |",
            f"| Ошибок загрузки | {counts.get('source_errors', 0)} |",
            f"| Источников без конфигов | {counts.get('sources_without_configs', 0)} |",
            f"| Ссылок извлечено | {counts.get('extracted_links', 0)} |",
            f"| Ссылок удалось разобрать | {counts.get('parsed_links', 0)} |",
            f"| Ошибок разбора ссылок | {counts.get('invalid_link_occurrences', 0)} |",
            f"| Уникальных конфигов | {counts.get('unique_nodes', 0)} |",
            f"| Удалено дубликатов | {counts.get('duplicates_removed', 0)} |",
            f"| Источников не обработано | {counts.get('unprocessed_sources', 0)} |",
            f"| Кандидатов после IP/CIDR-фильтра | {next((stage.get('output', 0) for stage in stages if stage.get('name') == 'ip_cidr_filter'), 0)} |",
            f"| Заблокировано IP/CIDR-фильтром | {counts.get('blocked', 0)} |",
            f"| Туннель подтверждён | {sum(v for k, v in status_counts.items() if k.startswith('proxy_ok'))} |",
            f"| Не удалось проверить | {sum(v for k, v in status_counts.items() if k in {'proxy_failed', 'proxy_suspect', 'tcp_closed', 'tcp_only'})} |",
            f"| Не проверено / не хватило времени | {status_counts.get('not_checked', 0)} |",
            f"| Кандидатов к публикации | {counts.get('candidate_nodes', 0)} |",
            f"| Узлов в предыдущей подписке | {counts.get('previous_subscription_nodes', 0)} |",
            f"| Решение публикации | **{self._clean(publish.get('status', 'не сформировано'))}** |",
            f"| Общее время | {self._duration(float(counts.get('total_elapsed_seconds') or 0))} |",
            "",
        ]
        if stages:
            lines.extend([
                "### Длительность этапов",
                "",
                "| Этап | Вход | Выход | Удалено / ошибок | Время |",
                "|---|---:|---:|---:|---:|",
            ])
            for stage in stages:
                name = self._clean(stage.get("name", "—"))
                input_count = stage.get("input", stage.get("configured_sources", "—"))
                output_count = stage.get("output", stage.get("fetched_sources", stage.get("unique_nodes", "—")))
                removed = stage.get("removed", stage.get("fetch_errors", "—"))
                duration = self._duration(float(stage.get("elapsed_seconds") or 0))
                lines.append(f"| {name} | {input_count} | {output_count} | {removed} | {duration} |")
            lines.append("")
        if status_counts:
            lines.extend(["### Результаты проверки", "", "| Статус | Количество |", "|---|---:|"])
            lines.extend(f"| {self._clean(key)} | {value} |" for key, value in sorted(status_counts.items()))
            lines.append("")
        if confidence:
            lines.extend(["### Уверенность подтверждённых узлов", "", "| Уровень | Количество |", "|---|---:|"])
            lines.extend(f"| {self._clean(key)} | {value} |" for key, value in sorted(confidence.items()))
            lines.append("")
        if source_rows:
            lines.extend([
                "### Источники",
                "",
                "| Источник | Загрузка | HTTP | Ссылок | Разобрано | Ошибок | Время |",
                "|---|---|---:|---:|---:|---:|---:|",
            ])
            for row in source_rows[:50]:
                lines.append(
                    f"| {self._clean(row.get('name', 'source'))} | "
                    f"{self._clean(row.get('status', 'unknown'))} | "
                    f"{self._clean(row.get('status_code') or '—')} | "
                    f"{row.get('links_extracted', 0)} | {row.get('parsed_links', 0)} | "
                    f"{row.get('invalid_links', 0)} | "
                    f"{float(row.get('elapsed_ms') or 0) / 1000:.1f}s |"
                )
            if len(source_rows) > 50:
                lines.append(f"\n_Показаны первые 50 из {len(source_rows)} источников; полный список — в отчёте._")
            lines.append("")
        warnings = report.get("warnings") or []
        if warnings:
            lines.extend(["### Предупреждения", ""])
            lines.extend(f"- {self._clean(item)}" for item in warnings[:20])
            if len(warnings) > 20:
                lines.append(f"- Ещё предупреждений: {len(warnings) - 20}")
            lines.append("")
        try:
            with Path(self.summary_path).open("a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        except OSError:
            pass
