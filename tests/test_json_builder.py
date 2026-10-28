import base64
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

import aeryx_json_parser.json_builder as json_builder
from aeryx_json_parser.json_builder import build_country_outputs
from aeryx_json_parser.xray_builder import uri_to_xray_outbound

UUIDS = [
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
    "55555555-5555-4555-8555-555555555555",
]


def node(code: str, country: str, i: int, status="proxy_ok_high", scheme="vless"):
    flag = {"DE": "🇩🇪", "US": "🇺🇸", "NL": "🇳🇱"}[code]
    label = quote(f"{flag} {country} • AeryxVPN", safe="")
    host_prefix = "de" if code == "DE" else "us"
    host = f"{host_prefix}{i}.example.org"
    if scheme == "hysteria2":
        uri = f"hysteria2://password-{i}@{host}:443?sni={host}#{label}"
    else:
        uri = f"vless://{UUIDS[i-1]}@{host}:443?encryption=none&security=tls&sni={host}&type=tcp#{label}"
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

    def test_emits_one_happ_json_array_and_metadata_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            out, report = self._build(Path(td))
            self.assertEqual(report["status"], "built")
            self.assertEqual(report["published_config_count"], 5)
            self.assertEqual(report["country_count"], 2)
            self.assertEqual(report["profile_count"], 3)  # Germany, USA, global Auto
            self.assertTrue((out / "AeryxVPN.json").is_file())
            self.assertTrue((out / "AeryxVPN.metadata.json").is_file())
            profiles = json.loads((out / "AeryxVPN.json").read_text(encoding="utf-8"))
            self.assertIsInstance(profiles, list)
            self.assertEqual(len(profiles), 3)
            self.assertFalse((out / "index.json").exists())
            self.assertFalse((out / "countries").exists())
            self.assertFalse((out / "xray").exists())
            metadata = json.loads((out / "AeryxVPN.metadata.json").read_text(encoding="utf-8"))["metadata"]
            self.assertEqual(metadata["format"], "happ-xray-json-array")
            self.assertEqual(metadata["validated_config_count"], 5)
            self.assertEqual(metadata["country_count"], 2)
            self.assertEqual(metadata["profile_count"], 3)
            self.assertEqual(metadata["generated_at"], "2026-10-27T12:00:00Z")
            self.assertIn("https://raw.githubusercontent.com/cheesyx-rudy/aeryx-json-parser/main/AeryxVPN.json", metadata["subscription_url"])

    def test_output_passes_structural_validator(self):
        from tools.validate_outputs import validate_structure
        with tempfile.TemporaryDirectory() as td:
            out, _ = self._build(Path(td))
            result = validate_structure(out / "AeryxVPN.json", out / "AeryxVPN.metadata.json", out / "build-report.json")
            self.assertEqual(result["countries"], 2)
            self.assertEqual(result["validated_nodes"], 5)
            self.assertEqual(result["auto_profile_count"], 1)
            self.assertEqual(len(result["profiles"]), 3)

    def test_country_profiles_are_separate_happ_list_rows(self):
        with tempfile.TemporaryDirectory() as td:
            out, _ = self._build(Path(td))
            profiles = json.loads((out / "AeryxVPN.json").read_text(encoding="utf-8"))
            by_name = {item["remarks"]: item for item in profiles}
            self.assertEqual(set(by_name), {"🇩🇪 Германия", "🇺🇸 США", "🇪🇺 Автовыбор"})
            for profile in profiles:
                self.assertIsNone(profile["meta"])

    def test_each_country_profile_matches_reference_template_and_balances_with_burst_observatory(self):
        with tempfile.TemporaryDirectory() as td:
            out, _ = self._build(Path(td))
            profiles = json.loads((out / "AeryxVPN.json").read_text(encoding="utf-8"))
            for profile in profiles:
                by_tag = {item["tag"]: item for item in profile["outbounds"]}
                self.assertEqual(profile["outbounds"][0]["tag"], "proxy-1")
                self.assertEqual(by_tag["direct"]["protocol"], "freedom")
                self.assertEqual(by_tag["block"]["protocol"], "blackhole")
                self.assertEqual(profile["burstObservatory"]["subjectSelector"], ["proxy"])
                self.assertEqual(profile["burstObservatory"]["pingConfig"]["connectivity"], "https://browser.yandex.ru/generate_204")
                self.assertEqual(profile["burstObservatory"]["pingConfig"]["destination"], "https://www.google.com")
                balancer = profile["routing"]["balancers"][0]
                self.assertEqual(balancer["strategy"]["type"], "leastPing")
                self.assertNotIn("fallbackTag", balancer)
                self.assertEqual(balancer["tag"], "balancer")
                self.assertEqual(balancer["selector"], ["proxy"])
                self.assertTrue(any(rule.get("balancerTag") == balancer["tag"] and rule.get("network") == "tcp,udp" for rule in profile["routing"]["rules"]))
                self.assertEqual(profile["inbounds"][0]["tag"], "socks")
                self.assertEqual(profile["inbounds"][1]["tag"], "http")
                self.assertEqual(len(profile["routing"]["rules"]), 18)
                self.assertIn("policy", profile)
                self.assertIn("metrics", profile)
                self.assertEqual(profile["meta"], None)
                node_tags = [item["tag"] for item in profile["outbounds"] if item["tag"].startswith("proxy-")]
                self.assertEqual(node_tags, [f"proxy-{i}" for i in range(1, len(node_tags) + 1)])
                self.assertTrue(all("sockopt" in item.get("streamSettings", {}) for item in profile["outbounds"] if item.get("protocol") not in {"freedom", "blackhole"} and "streamSettings" in item))
                tags = [item["tag"] for item in profile["outbounds"]]
                self.assertEqual(len(tags), len(set(tags)))

    def test_only_tunnel_validated_and_xray_convertible_nodes_are_published(self):
        with tempfile.TemporaryDirectory() as td:
            out, _ = self._build(Path(td))
            profiles = json.loads((out / "AeryxVPN.json").read_text(encoding="utf-8"))
            country_profiles = [p for p in profiles if p["remarks"] != "🇪🇺 Автовыбор"]
            node_count = 0
            for profile in country_profiles:
                node_count += sum(item["protocol"] not in {"freedom", "blackhole"} for item in profile["outbounds"])
            self.assertEqual(node_count, 5)
            report = json.loads((out / "build-report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["rejected_counts"]["not_tunnel_validated"], 1)

    def test_converter_builds_reality_and_ws_using_xray_fields(self):
        uri = (
            "vless://11111111-1111-4111-8111-111111111111@de.example.org:443"
            "?encryption=none&security=reality&sni=www.example.com&pbk=PUBKEY&sid=1234&fp=chrome"
            "&spx=%2F&type=ws&host=www.example.com&path=%2Fsocket#Germany"
        )
        out = uri_to_xray_outbound(uri)
        self.assertEqual(out["protocol"], "vless")
        self.assertEqual(out["settings"]["vnext"][0]["users"][0]["encryption"], "none")
        stream = out["streamSettings"]
        self.assertEqual(stream["security"], "reality")
        self.assertEqual(stream["realitySettings"]["publicKey"], "PUBKEY")
        self.assertEqual(stream["realitySettings"]["spiderX"], "/")
        self.assertEqual(stream["network"], "ws")
        self.assertEqual(stream["wsSettings"]["headers"]["Host"], "www.example.com")

    def test_converter_builds_grpc_shadowsocks_and_hysteria2(self):
        trojan = uri_to_xray_outbound("trojan://secret@de.example.org:443?sni=de.example.org&type=grpc&serviceName=svc#x")
        self.assertEqual(trojan["protocol"], "trojan")
        self.assertEqual(trojan["streamSettings"]["grpcSettings"]["serviceName"], "svc")
        ss_uri = "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:secret").decode().rstrip("=") + "@de.example.org:8388#x"
        ss = uri_to_xray_outbound(ss_uri)
        self.assertEqual(ss["protocol"], "shadowsocks")
        self.assertEqual(ss["settings"]["servers"][0]["method"], "aes-256-gcm")
        hy2 = uri_to_xray_outbound("hy2://secret@de.example.org:443?sni=de.example.org&obfs=salamander&obfs-password=mask#x")
        self.assertEqual(hy2["protocol"], "hysteria")
        self.assertEqual(hy2["settings"]["version"], 2)
        self.assertEqual(hy2["streamSettings"]["hysteriaSettings"]["auth"], "secret")
        self.assertEqual(hy2["streamSettings"]["finalmask"]["udp"][0]["type"], "salamander")

    def test_https_proxy_preserves_tls_sni_fingerprint_and_alpn(self):
        outbound = uri_to_xray_outbound(
            "https://user:secret@proxy.example.org:443?sni=tls.example.org&fp=firefox&alpn=h2"
        )
        self.assertEqual(outbound["protocol"], "http")
        tls = outbound["streamSettings"]["tlsSettings"]
        self.assertEqual(tls["serverName"], "tls.example.org")
        self.assertEqual(tls["fingerprint"], "firefox")
        self.assertEqual(tls["alpn"], ["h2"])

    def test_reality_spiderx_is_not_unquoted_twice(self):
        uri = (
            "vless://11111111-1111-4111-8111-111111111111@de.example.org:443"
            "?encryption=none&security=reality&sni=www.example.com&pbk=PUBKEY&sid=1234"
            "&spx=%252Falready-escaped&type=tcp#x"
        )
        outbound = uri_to_xray_outbound(uri)
        self.assertEqual(outbound["streamSettings"]["realitySettings"]["spiderX"], "%2Falready-escaped")

    def test_xhttp_extra_query_is_decoded_once(self):
        extra = {"path": "/percent%2Fkept", "header": "X-Test"}
        encoded_extra = quote(json.dumps(extra, separators=(",", ":")), safe="")
        uri = (
            "vless://11111111-1111-4111-8111-111111111111@de.example.org:443"
            "?security=tls&type=xhttp&extra=" + encoded_extra + "#x"
        )
        outbound = uri_to_xray_outbound(uri)
        self.assertEqual(outbound["streamSettings"]["xhttpSettings"]["extra"], extra)

    def test_converter_builds_vmess_socks_and_httpupgrade(self):
        payload = {
            "add": "de.example.org", "port": "443", "id": UUIDS[0], "aid": "0",
            "scy": "auto", "net": "ws", "type": "none", "host": "cdn.example.org",
            "path": "/socket", "tls": "tls", "sni": "de.example.org",
        }
        encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
        vmess = uri_to_xray_outbound(f"vmess://{encoded}#Germany")
        self.assertEqual(vmess["protocol"], "vmess")
        self.assertEqual(vmess["streamSettings"]["network"], "ws")
        self.assertEqual(vmess["streamSettings"]["wsSettings"]["path"], "/socket")
        self.assertEqual(vmess["streamSettings"]["wsSettings"]["headers"]["Host"], "cdn.example.org")

        socks = uri_to_xray_outbound("socks://user:pass@de.example.org:1080#Germany")
        self.assertEqual(socks["protocol"], "socks")
        self.assertEqual(socks["settings"]["servers"][0]["users"][0], {"user": "user", "pass": "pass"})

        upgrade = uri_to_xray_outbound("vless://11111111-1111-4111-8111-111111111111@de.example.org:443?security=tls&type=httpupgrade&host=cdn.example.org&path=%2Fconnect&sni=de.example.org#Germany")
        self.assertEqual(upgrade["streamSettings"]["network"], "httpupgrade")
        self.assertEqual(upgrade["streamSettings"]["httpupgradeSettings"]["host"], "cdn.example.org")

    def test_unsupported_xray_protocols_are_rejected_instead_of_published_broken(self):
        for uri in [
            "tuic://11111111-1111-4111-8111-111111111111:password@de.example.org:443?sni=de.example.org#x",
            "anytls://password@de.example.org:443?sni=de.example.org#x",
            "hysteria://password@de.example.org:443?sni=de.example.org#x",
        ]:
            with self.subTest(scheme=uri.split(":", 1)[0]):
                with self.assertRaises(ValueError):
                    uri_to_xray_outbound(uri)

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
            previous.write_text('[{"existing":true}]', encoding="utf-8")
            config = Path(__file__).resolve().parents[1] / "config" / "settings.yaml"
            with self.assertRaisesRegex(ValueError, "Safety stop"):
                build_country_outputs(input_file, out, config)
            self.assertEqual(previous.read_text(encoding="utf-8"), '[{"existing":true}]')

    def test_failed_late_build_preserves_previous_complete_output(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, config = self._fixture(root)
            out = root / "publish"
            out.mkdir()
            previous = out / "AeryxVPN.json"
            previous.write_text('[{"previous":true}]', encoding="utf-8")
            original_writer = json_builder._write_json

            def fail_metadata(path, value):
                if Path(path).name == "AeryxVPN.metadata.json":
                    raise RuntimeError("simulated late write failure")
                return original_writer(path, value)

            with patch.object(json_builder, "_write_json", side_effect=fail_metadata):
                with self.assertRaisesRegex(RuntimeError, "simulated late write failure"):
                    build_country_outputs(source, out, config, "owner/repo", "main")
            self.assertEqual(previous.read_text(encoding="utf-8"), '[{"previous":true}]')
            self.assertFalse(any(p.name.startswith(".publish.staging-") for p in root.iterdir()))


if __name__ == "__main__":
    unittest.main()
