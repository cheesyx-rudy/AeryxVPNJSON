from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from tools import install_cores


class DownloadRetryTests(unittest.TestCase):
    def test_retries_transient_release_asset_http_error(self) -> None:
        url = "https://github.com/XTLS/Xray-core/releases/download/v-test/Xray-linux-64.zip"
        transient = HTTPError(url, 503, "Service Unavailable", {}, None)
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "xray.zip"
            with (
                patch.object(install_cores.urllib.request, "urlopen", side_effect=[transient, __import__("io").BytesIO(b"archive")]),
                patch.object(install_cores.time, "sleep") as sleep,
            ):
                install_cores.download(url, destination)
            self.assertEqual(destination.read_bytes(), b"archive")
            self.assertFalse(destination.with_name(destination.name + ".part").exists())
            sleep.assert_called_once()

    def test_does_not_retry_permanent_not_found(self) -> None:
        url = "https://github.com/XTLS/Xray-core/releases/download/v-test/missing.zip"
        missing = HTTPError(url, 404, "Not Found", {}, None)
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "missing.zip"
            with patch.object(install_cores.urllib.request, "urlopen", side_effect=missing) as request:
                with self.assertRaises(HTTPError):
                    install_cores.download(url, destination)
            request.assert_called_once()
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
