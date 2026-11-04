import base64
import json


from aeryx_core.adapters import ShareURIAdapter
from aeryx_core.domain.enums import Protocol, SourceFormat

UUID = "11111111-1111-4111-8111-111111111111"


def test_parses_vless_share_uri_and_keeps_source_parameters() -> None:
    uri = (
        f"vless://{UUID}@Example.org:443?security=reality&type=ws&host=cdn.example.org"
        "&path=%2Fsocket#Germany"
    )
    candidate = ShareURIAdapter().parse(uri, source_name="test-feed")[0]

    assert candidate.protocol is Protocol.VLESS
    assert candidate.endpoint.host == "example.org"
    assert candidate.endpoint.port == 443
    assert candidate.label == "Germany"
    assert candidate.source_payload.format is SourceFormat.SHARE_URI
    assert candidate.source_payload.data == uri
    assert dict(candidate.share_link.query)["security"] == "reality"
    assert candidate.protocol_settings["type"] == "ws"


def test_extracts_base64_subscription_and_deduplicates_fragments() -> None:
    first = f"vless://{UUID}@example.org:443?security=tls#one"
    second = f"vless://{UUID}@example.org:443?security=tls#two"
    wrapped = base64.b64encode(f"{first}\n{second}".encode()).decode()

    candidates = ShareURIAdapter().parse(wrapped)

    assert len(candidates) == 1
    assert candidates[0].label == "one"


def test_vmess_endpoint_and_original_payload_are_preserved() -> None:
    data = {"add": "vmess.example", "port": "8443", "id": UUID, "net": "ws", "path": "/x"}
    encoded = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    candidate = ShareURIAdapter().parse(f"vmess://{encoded}#vmess")[0]

    assert candidate.protocol is Protocol.VMESS
    assert candidate.endpoint.host == "vmess.example"
    assert candidate.endpoint.port == 8443
    assert candidate.protocol_settings["net"] == "ws"


def test_shadowsocks_sip002_and_legacy_endpoint() -> None:
    sip002 = "ss://YWVzLTI1Ni1nY206cGFzcw@example.org:8388#ss"
    legacy_payload = base64.urlsafe_b64encode(b"aes-256-gcm:pass@example.net:9443").decode().rstrip("=")
    legacy = f"ss://{legacy_payload}"

    candidates = ShareURIAdapter().parse(f"{sip002}\n{legacy}")

    assert [(item.endpoint.host, item.endpoint.port) for item in candidates] == [
        ("example.org", 8388),
        ("example.net", 9443),
    ]
    assert candidates[0].protocol is Protocol.SHADOWSOCKS
    assert candidates[0].protocol_settings == {"method": "aes-256-gcm", "password": "pass"}


def test_reports_invalid_port_without_discarding_other_candidates() -> None:
    result = ShareURIAdapter().parse_with_report(
        f"vless://{UUID}@bad.example:70000\n"
        f"trojan://secret@good.example:443#good"
    )

    assert len(result.candidates) == 1
    assert result.candidates[0].endpoint.host == "good.example"
    assert len(result.issues) == 1
    assert result.issues[0].reason_code == "invalid_share_uri"


def test_fragment_does_not_change_fingerprint_but_transport_does() -> None:
    adapter = ShareURIAdapter()
    first = adapter.parse(f"vless://{UUID}@example.org:443?security=tls#first")[0]
    second = adapter.parse(f"vless://{UUID}@example.org:443?security=tls#second")[0]
    third = adapter.parse(f"vless://{UUID}@example.org:443?security=reality#third")[0]

    assert first.fingerprint == second.fingerprint
    assert first.fingerprint != third.fingerprint
