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


class CountryJSONBuilderTests(unittest.TestCase):
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
        text = cfg.read_text(encoding="utf-8")
        text = text.replace("minimum_total_configs: 5", "minimum_total_configs: 5")
        cfg_path.write_text(text, encoding="utf-8")
        return input_file, cfg_path

    def test_builds_separate_country_configs_and_metadata_index(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, config = self._fixture(root)
            out = root / "publish"
            report = build_country_outputs(
                source, out, config, "cheesyx-rudy/aeryx-json-parser", "main",
                datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(report["status"], "built")
            self.assertEqual(report["sing_box_config_count"], 5)
            self.assertEqual(report["country_count"], 2)
            self.assertTrue((out / "countries" / "DE.json").is_file())
            self.assertTrue((out / "countries" / "US.json").is_file())
            self.assertTrue((out / "country-metadata" / "DE.json").is_file())
            self.assertTrue((out / "xray" / "DE.json").is_file())
            index = json.loads((out / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["metadata"]["country_count"], 2)
            self.assertEqual(index["metadata"]["validated_sing_box_config_count"], 5)
            self.assertIn("https://raw.githubusercontent.com/cheesyx-rudy/aeryx-json-parser/main/countries/DE.json",
                          index["countries"][0]["files"]["sing_box"]["url"])

    def test_singbox_urltest_is_final_outbound_and_references_only_country_nodes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, config = self._fixture(root)
            out = root / "publish"
            build_country_outputs(source, out, config, "owner/repo", "main")
            cfg = json.loads((out / "countries" / "DE.json").read_text(encoding="utf-8"))
            by_tag = {item["tag"]: item for item in cfg["outbounds"]}
            auto = by_tag[cfg["route"]["final"]]
            self.assertEqual(auto["type"], "urltest")
            self.assertEqual(len(auto["outbounds"]), 3)
            self.assertTrue(all(by_tag[tag]["type"] in {"vless", "hysteria2"} for tag in auto["outbounds"]))
            self.assertEqual(auto["url"], "https://www.gstatic.com/generate_204")

    def test_xray_least_ping_has_observatory_and_country_selector(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, config = self._fixture(root)
            out = root / "publish"
            build_country_outputs(source, out, config, "owner/repo", "main")
            cfg = json.loads((out / "xray" / "DE.json").read_text(encoding="utf-8"))
            balancer = cfg["routing"]["balancers"][0]
            self.assertEqual(balancer["strategy"]["type"], "leastPing")
            self.assertTrue(cfg["observatory"]["subjectSelector"])
            prefix = balancer["selector"][0]
            selected_tags = [item["tag"] for item in cfg["outbounds"] if item["tag"].startswith(prefix)]
            self.assertEqual(len(selected_tags), 2)  # Hysteria2 is sing-box-only
            self.assertEqual(cfg["routing"]["rules"][0]["balancerTag"], balancer["tag"])

    def test_unchecked_nodes_do_not_enter_published_json(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, config = self._fixture(root)
            out = root / "publish"
            build_country_outputs(source, out, config, "owner/repo", "main")
            for path in (out / "countries").glob("*.json"):
                cfg = json.loads(path.read_text(encoding="utf-8"))
                nodes = [v for v in cfg["outbounds"] if v.get("type") not in {"urltest", "direct"}]
                self.assertEqual(sum("AeryxVPN 001" in v.get("tag", "") for v in nodes), 1)
            report = json.loads((out / "build-report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["rejected_counts"]["not_tunnel_validated"], 1)

    def test_json_diagnostics_do_not_expose_proxy_uris(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, config = self._fixture(root)
            out = root / "publish"
            build_country_outputs(source, out, config, "owner/repo", "main")
            report = (out / "build-report.json").read_text(encoding="utf-8")
            self.assertNotIn("vless://", report)
            self.assertNotIn("password-3", report)

    def test_safety_stop_happens_before_existing_outputs_are_touched(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            input_file = root / "parsed_proxies.json"
            input_file.write_text("[]", encoding="utf-8")
            out = root / "publish"
            out.mkdir()
            (out / "index.json").write_text('{"existing": true}', encoding="utf-8")
            config = Path(__file__).resolve().parents[1] / "config" / "settings.yaml"
            with self.assertRaisesRegex(ValueError, "Safety stop"):
                build_country_outputs(input_file, out, config)
            self.assertEqual((out / "index.json").read_text(encoding="utf-8"), '{"existing": true}')

    def test_failed_late_build_preserves_the_previous_complete_output(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, config = self._fixture(root)
            out = root / "publish"
            out.mkdir()
            previous = out / "index.json"
            previous.write_text('{"previous": true}', encoding="utf-8")
            original_writer = json_builder._write_json

            def fail_index(path, value):
                if Path(path).name == "index.json":
                    raise RuntimeError("simulated late write failure")
                return original_writer(path, value)

            with patch.object(json_builder, "_write_json", side_effect=fail_index):
                with self.assertRaisesRegex(RuntimeError, "simulated late write failure"):
                    build_country_outputs(source, out, config, "owner/repo", "main")
            self.assertEqual(previous.read_text(encoding="utf-8"), '{"previous": true}')
            self.assertFalse(any(p.name.startswith(".publish.staging-") for p in root.iterdir()))


if __name__ == "__main__":
    unittest.main()
