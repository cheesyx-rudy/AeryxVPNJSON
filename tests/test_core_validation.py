from __future__ import annotations

import time
import unittest

from aeryx_core import Confidence, ValidationResult, ValidationStatus

from aeryx_json_parser.core_validation import validate_nodes_with_core
from aeryx_json_parser.models import ProxyNode


class _FakeEngine:
    async def validate(self, candidate, context):
        self.candidate = candidate
        self.context = context
        return ValidationResult(
            fingerprint=candidate.fingerprint,
            status=ValidationStatus.WORKING,
            confidence=Confidence.HIGH,
            score=96,
            elapsed_ms=125,
            reason_code="stability_threshold_met",
            reason="stable",
        )


class CoreValidationAdapterTests(unittest.TestCase):
    def test_core_validation_maps_result_without_mutating_share_uri(self):
        uri = (
            "vless://11111111-1111-4111-8111-111111111111@node.example:443"
            "?security=tls&sni=node.example&type=ws&host=cdn.example&path=%2Fedge#node"
        )
        node = ProxyNode(
            uri=uri,
            scheme="vless",
            host="node.example",
            port=443,
            name="node",
            source="test-source",
        )
        engines = []

        def engine_factory(**kwargs):
            engine = _FakeEngine()
            engines.append((engine, kwargs))
            return engine

        counts = validate_nodes_with_core(
            [node],
            {"xray": "/tools/xray", "sing-box": "/tools/sing-box"},
            workers=2,
            deadline=time.monotonic() + 20,
            per_node_timeout=5,
            targets=[("https://www.gstatic.com/generate_204", {204})],
            minimum_successes=1,
            require_independent_providers=False,
            retry_single_success=True,
            engine_factory=engine_factory,
        )

        self.assertEqual(counts, {"proxy_ok_high": 1})
        self.assertEqual(node.check_status, "proxy_ok_high")
        self.assertEqual(node.validation_confidence, "high")
        self.assertEqual(node.validation_score, 96)
        self.assertEqual(node.uri, uri)
        self.assertEqual(len(engines), 1)
        self.assertEqual(engines[0][1]["xray_binary"], "/tools/xray")
        self.assertEqual(engines[0][1]["sing_box_binary"], "/tools/sing-box")


if __name__ == "__main__":
    unittest.main()
