from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aeryx_json_parser.progress import ProgressReporter


class ProgressReporterTests(unittest.TestCase):
    def test_events_include_local_timestamp_sequence_and_elapsed_time(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "progress.jsonl"
            with patch.dict(os.environ, {"AERYX_LOG_TIMEZONE": "Europe/Moscow"}):
                reporter = ProgressReporter(path)
                reporter.emit("start", "Запуск", {"sources": 3})
                reporter.emit("fetch", "Загрузка завершена", {"completed": 3})

            events = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual([event["sequence"] for event in events], [1, 2])
            self.assertEqual(events[0]["timezone"], "Europe/Moscow")
            self.assertIn("+03:00", events[0]["timestamp"])
            self.assertGreaterEqual(
                events[1]["elapsed_seconds"], events[0]["elapsed_seconds"]
            )
            self.assertIn("stage_elapsed_seconds", events[1])


if __name__ == "__main__":
    unittest.main()
