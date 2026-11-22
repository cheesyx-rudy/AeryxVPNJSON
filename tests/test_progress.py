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
