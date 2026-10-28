import copy
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.validate_outputs import _safe_xray_diagnostic, _without_happ_specific_geodata


class HappGeodataValidationCopyTests(unittest.TestCase):
    def test_removes_only_happ_specific_selectors_from_validation_copy(self):
        profile = {
            "dns": {
                "servers": [
                    "https://1.1.1.1/dns-query",
                    {
                        "address": "https://dns.example/dns-query",
                        "domains": ["geosite:WH-DIRECT", "geosite:STD-DIRECT"],
                        "skipFallback": True,
                    },
                    {
                        "address": "https://dns2.example/dns-query",
                        "domains": ["geosite:example", "domain:example.org"],
                    },
                ]
            },
            "routing": {
                "rules": [
                    {"domain": ["geosite:WH-DIRECT", "geosite:STD-DIRECT"], "outboundTag": "direct"},
                    {"ip": ["geoip:WH-DIRECT", "geoip:private"], "outboundTag": "direct"},
                    {"domain": ["domain:example.org"], "outboundTag": "proxy"},
                ]
            },
        }
        original = copy.deepcopy(profile)

        validated = _without_happ_specific_geodata(profile)

        self.assertEqual(profile, original, "published/source profile must not be mutated")
        self.assertEqual(len(validated["dns"]["servers"]), 2)
        self.assertEqual(
            validated["dns"]["servers"][1]["domains"],
            ["geosite:example", "domain:example.org"],
        )
        self.assertEqual(
            validated["routing"]["rules"],
            [
                {"ip": ["geoip:private"], "outboundTag": "direct"},
                {"domain": ["domain:example.org"], "outboundTag": "proxy"},
            ],
        )

    def test_drops_geodata_only_rule_instead_of_turning_it_into_catch_all(self):
        profile = {"routing": {"rules": [
            {"domain": ["geosite:WH-DIRECT"], "outboundTag": "direct"},
            {"ip": ["geoip:STD-DIRECT"], "outboundTag": "direct"},
        ]}}
        validated = _without_happ_specific_geodata(profile)
        self.assertEqual(validated["routing"]["rules"], [])

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
