import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from aeryx_json_parser.progress import ProgressReporter


class SourceProgressTests(unittest.TestCase):
    def test_success_shows_total_and_only_present_protocols(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "progress.jsonl"
            reporter = ProgressReporter(path, "Europe/Berlin")
            reporter._use_color = False
            output = io.StringIO()

            with redirect_stdout(output):
                reporter.emit_source(
                    "is.wepogp.gay",
                    {"vless": 23, "trojan": 10, "hysteria": 20, "ss": 10},
                    1234,
                    invalid=2,
                )

            lines = output.getvalue().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertIn("[SOURCE] is.wepogp.gay", lines[0])
            self.assertIn("Quantity 63", lines[0])
            self.assertIn("Invalid 2", lines[0])
            self.assertIn("vless 23", lines[1])
            self.assertIn("trojan 10", lines[1])
            self.assertIn("hysteria 20", lines[1])
            self.assertIn("ss 10", lines[1])
            self.assertNotIn("vmess", output.getvalue())
            self.assertNotIn("tuic", output.getvalue())

            event = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(event["stage"], "source")
            self.assertEqual(event["details"]["quantity"], 63)
            self.assertEqual(
                event["details"]["protocols"],
                {"hysteria": 20, "ss": 10, "trojan": 10, "vless": 23},
            )

    def test_failed_source_shows_machine_readable_error_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "progress.jsonl"
            reporter = ProgressReporter(path, "Europe/Berlin")
            reporter._use_color = False
            output = io.StringIO()

            with redirect_stdout(output):
                reporter.emit_source(
                    "panel.example",
                    {},
                    87,
                    error_code="HTTP_403",
                )

            self.assertIn("[SOURCE] panel.example", output.getvalue())
            self.assertIn("ERROR HTTP_403", output.getvalue())
            self.assertNotIn("Quantity 0", output.getvalue())

            event = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(event["details"]["status"], "error")
            self.assertEqual(event["details"]["error_code"], "HTTP_403")

    def test_queue_and_result_keep_same_domain_sources_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "progress.jsonl"
            reporter = ProgressReporter(path, "Europe/Berlin")
            reporter._use_color = False
            output = io.StringIO()

            with redirect_stdout(output):
                reporter.emit_source_queued(1, 2, "same.example")
                reporter.emit_source_queued(2, 2, "same.example")
                reporter.emit_source_started(1, 2, "same.example")
                reporter.emit_source(
                    "same.example",
                    {"vless": 5},
                    100,
                    source_index=1,
                    source_total=2,
                )
                reporter.emit_source(
                    "same.example",
                    {"trojan": 7},
                    120,
                    source_index=2,
                    source_total=2,
                )

            rendered = output.getvalue()
            self.assertIn("[QUEUED] #01/2 same.example", rendered)
            self.assertIn("[QUEUED] #02/2 same.example", rendered)
            self.assertIn("[FETCHING] #01/2 same.example", rendered)
            self.assertIn("[SOURCE] #01/2 same.example", rendered)
            self.assertIn("[SOURCE] #02/2 same.example", rendered)

    def test_summary_reports_each_source_and_aggregated_counts(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "progress.jsonl"
            reporter = ProgressReporter(path, "Europe/Berlin")
            reporter._use_color = False
            output = io.StringIO()
            inventory = {
                "source_entries": 2,
                "configured_sources": 2,
                "unique_sources": 2,
                "duplicates_skipped": 0,
            }
            records = [
                {
                    "source_index": 1, "domain": "same.example",
                    "parse_status": "ok", "parsed_nodes": 5,
                    "protocol_counts": {"vless": 5}, "invalid_links": 0,
                },
                {
                    "source_index": 2, "domain": "same.example",
                    "parse_status": "error", "parse_error_code": "HTTP_403",
                    "parsed_nodes": 0, "protocol_counts": {},
                    "invalid_links": 0,
                },
            ]

            with redirect_stdout(output):
                summary = reporter.emit_source_summary(
                    records, inventory, submitted_total=2,
                    parsed_configs=5, unique_configs=4,
                )

            self.assertEqual(summary["initial_processed"], 2)
            self.assertEqual(summary["source_errors"], 1)
            self.assertEqual(summary["protocol_totals"], {"vless": 5})
            self.assertIn("#01/2 same.example", output.getvalue())
            self.assertIn("#02/2 same.example", output.getvalue())
            self.assertIn("unique_after_dedup=4", output.getvalue())

    def test_summary_keeps_unprocessed_configured_sources_in_original_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            reporter = ProgressReporter(Path(temporary) / "progress.jsonl", "Europe/Berlin")
            reporter._use_color = False
            output = io.StringIO()
            inventory = {
                "source_entries": 2,
                "configured_sources": 2,
                "unique_sources": 2,
                "duplicates_skipped": 0,
            }
            records = [
                {
                    "source_index": 2, "domain": "second.example",
                    "parse_status": "ok", "parsed_nodes": 3,
                    "protocol_counts": {"vless": 3}, "invalid_links": 0,
                },
            ]
            manifest = [
                {"source_index": 1, "domain": "first.example"},
                {"source_index": 2, "domain": "second.example"},
            ]
            with redirect_stdout(output):
                summary = reporter.emit_source_summary(
                    records,
                    inventory,
                    configured_manifest=manifest,
                    submitted_total=1,
                    parsed_configs=3,
                    unique_configs=3,
                )
            rendered = output.getvalue()
            self.assertLess(
                rendered.index("#01/2 first.example"),
                rendered.index("#02/2 second.example"),
            )
            self.assertIn("NOT_PROCESSED", rendered)
            self.assertEqual(summary["initial_processed"], 1)
            self.assertEqual(summary["initial_not_processed"], 1)
            self.assertEqual(summary["processed_total"], 1)

    def test_provider_discovery_is_not_reported_as_a_fetch_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "progress.jsonl"
            reporter = ProgressReporter(path, "Europe/Berlin")
            reporter._use_color = False
            output = io.StringIO()

            with redirect_stdout(output):
                reporter.emit_source("panel.example", {}, 250, providers=3)

            self.assertIn("DISCOVERED 3 provider(s)", output.getvalue())
            self.assertIn("providers 3", output.getvalue())
            event = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(event["details"]["status"], "discovered")


if __name__ == "__main__":
    unittest.main()
