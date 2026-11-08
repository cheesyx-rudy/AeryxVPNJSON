from __future__ import annotations

import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from tools import install_cores


class GitHubApiTests(unittest.TestCase):
    def test_release_metadata_request_uses_github_token(self) -> None:
        payload = b'{"tag_name":"v-test","assets":[]}'
        with (
            patch.dict(os.environ, {"GITHUB_TOKEN": "ghs-test-token"}),
            patch.object(install_cores.urllib.request, "urlopen", return_value=io.BytesIO(payload)) as request,
        ):
            result = install_cores.get_json(
                "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
            )

        self.assertEqual(result["tag_name"], "v-test")
        sent_request = request.call_args.args[0]
        self.assertEqual(
            sent_request.get_header("Authorization"),
            "Bearer ghs-test-token",
        )

    def test_retries_transient_release_metadata_http_error(self) -> None:
        url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        transient = HTTPError(url, 503, "Service Unavailable", {}, None)
        payload = b'{"tag_name":"v-test"}'
        with (
            patch.dict(os.environ, {"GITHUB_TOKEN": "ghs-test-token"}),
            patch.object(
                install_cores.urllib.request,
                "urlopen",
                side_effect=[transient, io.BytesIO(payload)],
            ) as request,
            patch.object(install_cores.time, "sleep") as sleep,
        ):
            result = install_cores.get_json(url)

        self.assertEqual(result["tag_name"], "v-test")
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once()

    def test_retries_rate_limited_release_metadata_request(self) -> None:
        url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        limited = HTTPError(
            url,
            403,
            "rate limit exceeded",
            {"X-RateLimit-Remaining": "0"},
            io.BytesIO(b'{"message":"API rate limit exceeded"}'),
        )
        payload = b'{"tag_name":"v-test"}'
        with (
            patch.dict(os.environ, {"GITHUB_TOKEN": "ghs-test-token"}),
            patch.object(
                install_cores.urllib.request,
                "urlopen",
                side_effect=[limited, io.BytesIO(payload)],
            ) as request,
            patch.object(install_cores.time, "sleep") as sleep,
        ):
            result = install_cores.get_json(url)

        self.assertEqual(result["tag_name"], "v-test")
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once()

    def test_does_not_retry_forbidden_metadata_request(self) -> None:
        url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        forbidden = HTTPError(url, 403, "Forbidden", {}, io.BytesIO(b"Forbidden"))
        with (
            patch.dict(os.environ, {"GITHUB_TOKEN": "ghs-test-token"}),
            patch.object(
                install_cores.urllib.request,
                "urlopen",
                side_effect=forbidden,
            ) as request,
        ):
            with self.assertRaises(HTTPError):
                install_cores.get_json(url)
        request.assert_called_once()


class DownloadRetryTests(unittest.TestCase):
    def test_retries_transient_release_asset_http_error(self) -> None:
        url = "https://github.com/XTLS/Xray-core/releases/download/v-test/Xray-linux-64.zip"
        transient = HTTPError(url, 503, "Service Unavailable", {}, None)
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "xray.zip"
            with (
                patch.object(
                    install_cores.urllib.request,
                    "urlopen",
                    side_effect=[transient, io.BytesIO(b"archive")],
                ),
                patch.object(install_cores.time, "sleep") as sleep,
            ):
                install_cores.download(url, destination)
            self.assertEqual(destination.read_bytes(), b"archive")
            self.assertFalse(destination.with_name(destination.name + ".part").exists())
            sleep.assert_called_once()

    def test_download_uses_authenticated_asset_api_and_verifies_digest(self) -> None:
        payload = b"official-core-archive"
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        url = "https://api.github.com/repos/XTLS/Xray-core/releases/assets/12345"
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "xray.zip"
            with (
                patch.dict(os.environ, {"GITHUB_TOKEN": "ghs-test-token"}),
                patch.object(
                    install_cores.urllib.request,
                    "urlopen",
                    return_value=io.BytesIO(payload),
                ) as request,
            ):
                install_cores.download(
                    url,
                    destination,
                    expected_digest=digest,
                )

            sent_request = request.call_args.args[0]
            self.assertEqual(sent_request.get_header("Authorization"), "Bearer ghs-test-token")
            self.assertEqual(destination.read_bytes(), payload)

    def test_rejects_release_asset_with_wrong_digest(self) -> None:
        url = "https://github.com/XTLS/Xray-core/releases/download/v-test/Xray-linux-64.zip"
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "xray.zip"
            with patch.object(
                install_cores.urllib.request,
                "urlopen",
                return_value=io.BytesIO(b"corrupted"),
            ):
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    install_cores.download(
                        url,
                        destination,
                        expected_digest="sha256:" + ("0" * 64),
                    )
            self.assertFalse(destination.exists())
            self.assertFalse(destination.with_name(destination.name + ".part").exists())

    def test_does_not_retry_permanent_not_found(self) -> None:
        url = "https://github.com/XTLS/Xray-core/releases/download/v-test/missing.zip"
        missing = HTTPError(url, 404, "Not Found", {}, None)
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "missing.zip"
            with patch.object(
                install_cores.urllib.request,
                "urlopen",
                side_effect=missing,
            ) as request:
                with self.assertRaises(HTTPError):
                    install_cores.download(url, destination)
            request.assert_called_once()
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
