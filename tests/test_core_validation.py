from __future__ import annotations

import time
import unittest

from aeryx_core import (
    CheckResult,
    Confidence,
    ValidationResult,
    ValidationStatus,
    attach_validation_report,
)

from aeryx_json_parser.core_validation import _core_status, validate_nodes_with_core
from aeryx_json_parser.models import ProxyNode


class _FakeEngine:
    async def validate(self, candidate, context):
        self.candidate = candidate
        self.context = context
        return attach_validation_report(
            ValidationResult(
                fingerprint=candidate.fingerprint,
                status=ValidationStatus.WORKING,
                confidence=Confidence.HIGH,
                score=96,
                elapsed_ms=125,
                reason_code="stability_threshold_met",
                reason="stable",
                checks=(
                    CheckResult(
                        "http_health_stability",
                        True,
                        critical=True,
                        details={"successful_samples": 2, "success_rate": 1.0},
                    ),
                ),
            )
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
        self.assertEqual(node.validation_report["schema_version"], "2.0")
        self.assertEqual(len(node.validation_report["stages"]), 9)
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
                "?security=tls&type=grpc&serviceName=edge#grpc"
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


    def test_degraded_core_result_is_not_publishable(self):
        node = ProxyNode(
            uri="vless://11111111-1111-4111-8111-111111111111@degraded.example:443?security=tls#node",
            scheme="vless",
            host="degraded.example",
            port=443,
        )

        class DegradedEngine:
            async def validate(self, candidate, context):
                del context
                return ValidationResult(
                    fingerprint=candidate.fingerprint,
                    status=ValidationStatus.DEGRADED,
                    confidence=Confidence.MEDIUM,
                    score=64,
                    elapsed_ms=200,
                )

        counts = validate_nodes_with_core(
            [node],
            {"xray": "/tools/xray"},
            workers=1,
            deadline=time.monotonic() + 10,
            per_node_timeout=5,
            targets=[("https://health.example/ready", {200})],
            minimum_successes=2,
            require_independent_providers=True,
            retry_single_success=True,
            engine_factory=lambda **kwargs: DegradedEngine(),
        )

        self.assertEqual(counts, {"proxy_degraded": 1})
        self.assertEqual(node.check_status, "proxy_degraded")
        self.assertFalse(node.check_status.startswith("proxy_ok"))




    def test_indeterminate_unstable_and_invalid_are_not_collapsed_into_failed(self):
        expected = {
            ValidationStatus.INDETERMINATE: "proxy_indeterminate",
            ValidationStatus.UNSTABLE: "proxy_unstable",
            ValidationStatus.INVALID: "proxy_invalid",
            ValidationStatus.FAILED: "proxy_failed",
        }
        for core_status, parser_status in expected.items():
            with self.subTest(core_status=core_status):
                result = ValidationResult(
                    fingerprint="candidate",
                    status=core_status,
                    confidence=Confidence.LOW,
                    reason_code=f"test_{core_status.value}",
                )
                self.assertEqual(_core_status(result)[0], parser_status)

    def test_inconclusive_core_result_does_not_create_negative_vote(self):
        node = ProxyNode(
            uri="vless://11111111-1111-4111-8111-111111111111@unknown.example:443?security=tls#node",
            scheme="vless",
            host="unknown.example",
            port=443,
        )

        class IndeterminateEngine:
            async def validate(self, candidate, context):
                del context
                return ValidationResult(
                    fingerprint=candidate.fingerprint,
                    status=ValidationStatus.INDETERMINATE,
                    confidence=Confidence.LOW,
                    reason_code="network_environment_unavailable",
                )

        counts = validate_nodes_with_core(
            [node],
            {"xray": "/tools/xray"},
            workers=1,
            deadline=time.monotonic() + 10,
            per_node_timeout=5,
            targets=[("https://health.example/ready", {200})],
            minimum_successes=1,
            require_independent_providers=False,
            retry_single_success=False,
            engine_factory=lambda **kwargs: IndeterminateEngine(),
        )

        self.assertEqual(counts, {"proxy_indeterminate": 1})
        self.assertEqual(node.check_status, "proxy_indeterminate")
        self.assertIsNone(node.validation_votes["core_tunnel_validation"])


if __name__ == "__main__":
    unittest.main()
