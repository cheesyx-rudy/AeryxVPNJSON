from datetime import datetime, timezone

import pytest

from aeryx_core.domain.enums import Protocol, SourceFormat, ValidationStatus
from aeryx_core.domain.models import Endpoint, ProxyCandidate, SourcePayload, ValidationResult


def make_candidate() -> ProxyCandidate:
    return ProxyCandidate(
        fingerprint="sha256:example",
        protocol=Protocol.VLESS,
        endpoint=Endpoint(host="Example.COM.", port=443),
        source_payload=SourcePayload(
            format=SourceFormat.SHARE_URI,
            data="vless://example",
            source_name="unit-test",
        ),
    )


def test_endpoint_normalizes_host() -> None:
    endpoint = Endpoint(host="[EXAMPLE.COM.]", port=443)
    assert endpoint.host == "example.com"


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_endpoint_rejects_invalid_port(port: int) -> None:
    with pytest.raises(ValueError):
        Endpoint(host="example.com", port=port)


def test_candidate_keeps_source_payload() -> None:
    candidate = make_candidate()
    assert candidate.source_payload.data == "vless://example"
    assert candidate.endpoint.host == "example.com"


def test_validation_result_requires_timezone_aware_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ValidationResult(
            fingerprint="sha256:example",
            status=ValidationStatus.NOT_CHECKED,
            checked_at=datetime(2026, 1, 1),
        )


def test_validation_result_accepts_utc_datetime() -> None:
    result = ValidationResult(
        fingerprint="sha256:example",
        status=ValidationStatus.NOT_CHECKED,
        checked_at=datetime.now(timezone.utc),
    )
    assert result.status is ValidationStatus.NOT_CHECKED
