from dataclasses import dataclass

import pytest

from aeryx_core.domain.enums import Confidence, Protocol, SourceFormat, ValidationStatus
from aeryx_core.domain.models import Endpoint, ProxyCandidate, SourcePayload, ValidationResult
from aeryx_core.validation.contracts import ValidationContext
from aeryx_core.validation.engine import ValidationEngine


@dataclass
class FakeValidator:
    supported_protocols = frozenset({Protocol.VLESS})

    async def validate(self, candidate: ProxyCandidate, context: ValidationContext) -> ValidationResult:
        return ValidationResult(
            fingerprint=candidate.fingerprint,
            status=ValidationStatus.WORKING,
            confidence=Confidence.HIGH,
            score=100,
        )


def make_candidate(protocol: Protocol = Protocol.VLESS, fingerprint: str = "node-1") -> ProxyCandidate:
    return ProxyCandidate(
        fingerprint=fingerprint,
        protocol=protocol,
        endpoint=Endpoint(host="example.com", port=443),
        source_payload=SourcePayload(format=SourceFormat.SHARE_URI, data="original-data"),
    )


@pytest.mark.asyncio
async def test_engine_dispatches_to_matching_validator() -> None:
    engine = ValidationEngine([FakeValidator()])
    result = await engine.validate(make_candidate())
    assert result.status is ValidationStatus.WORKING
    assert result.score == 100


@pytest.mark.asyncio
async def test_engine_does_not_mark_unregistered_protocol_working() -> None:
    engine = ValidationEngine()
    result = await engine.validate(make_candidate(Protocol.TUIC))
    assert result.status is ValidationStatus.UNSUPPORTED
    assert result.reason_code == "validator_not_registered"


@pytest.mark.asyncio
async def test_validate_many_respects_public_contract() -> None:
    engine = ValidationEngine([FakeValidator()])
    candidates = [make_candidate(fingerprint=f"node-{index}") for index in range(3)]
    results = await engine.validate_many(candidates, concurrency=2)
    assert [result.fingerprint for result in results] == ["node-0", "node-1", "node-2"]


def test_engine_rejects_duplicate_protocol_registration() -> None:
    with pytest.raises(ValueError, match="already registered"):
        ValidationEngine([FakeValidator(), FakeValidator()])
