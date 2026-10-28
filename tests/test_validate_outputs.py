import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.validate_outputs import _find_unavailable_custom_geodata, _safe_xray_diagnostic


class CustomGeodataGuardTests(unittest.TestCase):
    def test_finds_custom_categories_anywhere_in_config(self):
        profile = {
            "dns": {
                "servers": [
                    "https://1.1.1.1/dns-query",
                    {"address": "https://dns.example/dns-query", "domains": ["geosite:WH-DIRECT"]},
                ]
            },
            "routing": {
                "rules": [
                    {"domain": ["geosite:STD-DIRECT"], "outboundTag": "direct"},
                    {"ip": ["geoip:WH-DIRECT"], "outboundTag": "direct"},
                ]
            },
        }
        found = _find_unavailable_custom_geodata(profile)
        self.assertEqual(len(found), 3)
        self.assertTrue(any("dns.servers[1].domains[0]" in item for item in found))
        self.assertTrue(any("routing.rules[0].domain[0]" in item for item in found))
        self.assertTrue(any("routing.rules[1].ip[0]" in item for item in found))

    def test_allows_standard_geo_selectors(self):
        profile = {
            "routing": {"rules": [
                {"domain": ["geosite:example"], "outboundTag": "direct"},
                {"ip": ["geoip:private"], "outboundTag": "direct"},
            ]}
        }
        self.assertEqual(_find_unavailable_custom_geodata(profile), [])

    def test_repository_template_and_published_profiles_have_no_custom_geo_dependencies(self):
        root = Path(__file__).resolve().parents[1]
        template = json.loads((root / "config" / "xray-profile-template.json").read_text(encoding="utf-8"))
        profiles = json.loads((root / "AeryxVPN.json").read_text(encoding="utf-8"))
        self.assertEqual(_find_unavailable_custom_geodata(template), [])
        self.assertTrue(profiles)
        for profile in profiles:
            self.assertEqual(_find_unavailable_custom_geodata(profile), [], profile.get("remarks"))

    def test_failure_diagnostic_is_useful_but_redacts_uuid_ip_and_temp_path(self):
        secret_uuid = "11111111-1111-4111-8111-111111111111"
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "profile.json"
            proc = subprocess.CompletedProcess(
                args=["xray"],
                returncode=23,
                stdout="",
                stderr=f"failed to load {config_path}: invalid target 192.0.2.5 id={secret_uuid}",
            )
            diagnostic = _safe_xray_diagnostic(proc, config_path)
        self.assertIsNotNone(diagnostic)
        self.assertIn("failed to load <config>", diagnostic)
        self.assertIn("<ip>", diagnostic)
        self.assertIn("<uuid>", diagnostic)
        self.assertNotIn(secret_uuid, diagnostic)
        self.assertNotIn(str(config_path), diagnostic)


if __name__ == "__main__":
    unittest.main()
