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


    def test_same_account_variants_are_collapsed_by_shared_core(self):
        first = ProxyNode(
            uri=(
                "vless://11111111-1111-4111-8111-111111111111@node.example:443"
                "?security=tls&type=ws&path=%2Fws#websocket"
            ),
            scheme="vless",
            host="node.example",
            port=443,
            name="websocket",
        )
        second = ProxyNode(
            uri=(
                "vless://11111111-1111-4111-8111-111111111111@node.example:443"
                "?security=reality&type=grpc&serviceName=edge#grpc"
            ),
            scheme="vless",
            host="node.example",
            port=443,
            name="grpc",
        )

        class CandidateAwareEngine:
            async def validate(self, candidate, context):
                del context
                score = 96 if candidate.protocol_settings.get("type") == "grpc" else 80
                return ValidationResult(
                    fingerprint=candidate.fingerprint,
                    status=ValidationStatus.WORKING,
                    confidence=Confidence.HIGH,
                    score=score,
                    elapsed_ms=100,
                )

        counts = validate_nodes_with_core(
            [first, second],
            {"xray": "/tools/xray", "sing-box": "/tools/sing-box"},
            workers=2,
            deadline=time.monotonic() + 20,
            per_node_timeout=5,
            targets=[("https://health.example/ready", {200})],
            minimum_successes=1,
            require_independent_providers=False,
            retry_single_success=True,
            engine_factory=lambda **kwargs: CandidateAwareEngine(),
        )

        self.assertEqual(counts, {"proxy_ok_high": 1, "proxy_duplicate_core": 1})
        self.assertEqual(second.check_status, "proxy_ok_high")
        self.assertEqual(first.check_status, "proxy_duplicate_core")
        self.assertIn("duplicate_account_variant:", first.check_reason)


if __name__ == "__main__":
    unittest.main()
