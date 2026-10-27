import json
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from pathlib import Path

import aeryx_json_parser.json_builder as json_builder
from aeryx_json_parser.json_builder import build_country_outputs

UUIDS = [
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
    "55555555-5555-4555-8555-555555555555",
]


def node(code: str, country: str, i: int, status="proxy_ok_high", scheme="vless"):
    from urllib.parse import quote

    flags = {"DE": "🇩🇪", "US": "🇺🇸", "NL": "🇳🇱"}
    flag = flags[code]
    label = quote(f"{flag} {country} • AeryxVPN", safe="")
    host_prefix = "de" if code == "DE" else "us"
    host = f"{host_prefix}{i}.example.org"
    if scheme == "hysteria2":
        uri = f"hysteria2://password-{i}@host-{i}.example.org:443?sni=host-{i}.example.org#{label}"
    else:
        uri = (
            f"vless://{UUIDS[i-1]}@{host}:443?encryption=none&security=tls"
            f"&sni={host}&type=tcp#{label}"
        )
    return {
        "uri": uri,
        "scheme": scheme,
        "host": host,
        "port": 443,
        "name": f"{flag} {country} • AeryxVPN",
        "check_status": status,
        "validation_confidence": "high",
    }


class UnifiedJSONBuilderTests(unittest.TestCase):
    def _fixture(self, root: Path):
        input_file = root / "parsed_proxies.json"
        records = [
            node("DE", "Germany", 1),
            node("DE", "Germany", 2),
            node("DE", "Germany", 3, scheme="hysteria2"),
            node("US", "United States", 4),
            node("US", "United States", 5),
            node("DE", "Germany", 1, status="tcp_open"),  # must never be published
        ]
        input_file.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")
        cfg_path = root / "settings.yaml"
        cfg = Path(__file__).resolve().parents[1] / "config" / "settings.yaml"
        cfg_path.write_text(cfg.read_text(encoding="utf-8"), encoding="utf-8")
        return input_file, cfg_path

    def _build(self, root: Path):
        source, config = self._fixture(root)
        out = root / "publish"
        report = build_country_outputs(
            source, out, config, "cheesyx-rudy/aeryx-json-parser", "main",
            datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc),
        )
        return out, report

    def test_builds_one_complete_subscription_and_metadata_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            out, report = self._build(Path(td))
            self.assertEqual(report["status"], "built")
            self.assertEqual(report["published_config_count"], 5)
            self.assertEqual(report["country_count"], 2)
            self.assertTrue((out / "AeryxVPN.json").is_file())
            self.assertTrue((out / "AeryxVPN.metadata.json").is_file())
            self.assertFalse((out / "index.json").exists())
            self.assertFalse((out / "countries").exists())
            self.assertFalse((out / "xray").exists())
            metadata = json.loads((out / "AeryxVPN.metadata.json").read_text(encoding="utf-8"))["metadata"]
            self.assertEqual(metadata["validated_config_count"], 5)
            self.assertEqual(metadata["country_count"], 2)
            self.assertEqual(metadata["generated_at"], "2026-10-27T12:00:00Z")
            self.assertIn("https://raw.githubusercontent.com/cheesyx-rudy/aeryx-json-parser/main/AeryxVPN.json",
                          metadata["subscription_url"])

    def test_one_profile_contains_country_urltests_and_one_country_selector(self):
        with tempfile.TemporaryDirectory() as td:
            out, _ = self._build(Path(td))
            cfg = json.loads((out / "AeryxVPN.json").read_text(encoding="utf-8"))
            by_tag = {item["tag"]: item for item in cfg["outbounds"]}
            self.assertEqual(cfg["route"]["final"], "🌍 Выбор страны · AeryxVPN")
            selector = by_tag[cfg["route"]["final"]]
            self.assertEqual(cfg["experimental"]["clash_api"]["external_controller"], "127.0.0.1:9090")
            self.assertEqual(selector["type"], "selector")
            self.assertEqual(len(selector["outbounds"]), 2)
            self.assertIn(selector["default"], selector["outbounds"])
            de_auto = by_tag["🇩🇪 Germany · Автовыбор"]
            us_auto = by_tag["🇺🇸 United States · Автовыбор"]
            self.assertEqual(de_auto["type"], "urltest")
            self.assertEqual(us_auto["type"], "urltest")
            self.assertEqual(len(de_auto["outbounds"]), 3)
            self.assertEqual(len(us_auto["outbounds"]), 2)
            self.assertTrue(all(by_tag[tag]["type"] in {"vless", "hysteria2"} for tag in de_auto["outbounds"]))
            self.assertEqual(de_auto["url"], "https://www.gstatic.com/generate_204")

    def test_each_node_has_unique_tag_and_all_groups_resolve(self):
        with tempfile.TemporaryDirectory() as td:
            out, _ = self._build(Path(td))
            cfg = json.loads((out / "AeryxVPN.json").read_text(encoding="utf-8"))
            tags = [item["tag"] for item in cfg["outbounds"]]
            self.assertEqual(len(tags), len(set(tags)))
            by_tag = {item["tag"]: item for item in cfg["outbounds"]}
            for outbound in cfg["outbounds"]:
                if outbound["type"] in {"urltest", "selector"}:
                    self.assertTrue(outbound["outbounds"])
                    self.assertTrue(all(tag in by_tag for tag in outbound["outbounds"]))

    def test_unchecked_nodes_do_not_enter_single_subscription(self):
        with tempfile.TemporaryDirectory() as td:
            out, _ = self._build(Path(td))
            cfg = json.loads((out / "AeryxVPN.json").read_text(encoding="utf-8"))
            nodes = [v for v in cfg["outbounds"] if v.get("type") not in {"urltest", "selector", "direct"}]
            self.assertEqual(len(nodes), 5)
            report = json.loads((out / "build-report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["rejected_counts"]["not_tunnel_validated"], 1)

    def test_diagnostics_do_not_expose_proxy_uris_or_passwords(self):
        with tempfile.TemporaryDirectory() as td:
            out, _ = self._build(Path(td))
            report = (out / "build-report.json").read_text(encoding="utf-8")
            metadata = (out / "AeryxVPN.metadata.json").read_text(encoding="utf-8")
            self.assertNotIn("vless://", report)
            self.assertNotIn("password-3", report)
            self.assertNotIn("vless://", metadata)
            self.assertNotIn("password-3", metadata)

    def test_safety_stop_preserves_existing_previous_subscription(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            input_file = root / "parsed_proxies.json"
            input_file.write_text("[]", encoding="utf-8")
            out = root / "publish"
            out.mkdir()
            previous = out / "AeryxVPN.json"
            previous.write_text('{"existing": true}', encoding="utf-8")
            config = Path(__file__).resolve().parents[1] / "config" / "settings.yaml"
            with self.assertRaisesRegex(ValueError, "Safety stop"):
                build_country_outputs(input_file, out, config)
            self.assertEqual(previous.read_text(encoding="utf-8"), '{"existing": true}')

    def test_failed_late_build_preserves_previous_complete_output(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, config = self._fixture(root)
            out = root / "publish"
            out.mkdir()
            previous = out / "AeryxVPN.json"
            previous.write_text('{"previous": true}', encoding="utf-8")
            original_writer = json_builder._write_json

            def fail_metadata(path, value):
                if Path(path).name == "AeryxVPN.metadata.json":
                    raise RuntimeError("simulated late write failure")
                return original_writer(path, value)

            with patch.object(json_builder, "_write_json", side_effect=fail_metadata):
                with self.assertRaisesRegex(RuntimeError, "simulated late write failure"):
                    build_country_outputs(source, out, config, "owner/repo", "main")
            self.assertEqual(previous.read_text(encoding="utf-8"), '{"previous": true}')
            self.assertFalse(any(p.name.startswith(".publish.staging-") for p in root.iterdir()))


if __name__ == "__main__":
    unittest.main()
