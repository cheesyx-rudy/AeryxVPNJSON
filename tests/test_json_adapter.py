import json

from aeryx_core.adapters import ClashYAMLAdapter, StructuredJSONAdapter
from aeryx_core.domain.enums import Protocol, SourceFormat

UUID = "11111111-1111-4111-8111-111111111111"


def test_parses_xray_outbounds_and_ignores_non_proxy_outbounds() -> None:
    document = {
        "log": {"loglevel": "warning", "custom_unknown": True},
        "outbounds": [
            {
                "protocol": "vless",
                "tag": "edge-de",
                "settings": {
                    "vnext": [
                        {
                            "address": "de.example.org",
                            "port": 443,
                            "users": [{"id": UUID, "encryption": "none"}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "xhttpSettings": {"path": "/upload", "mode": "stream-one", "extra": {"vendor": "kept"}},
                },
                "private_unknown_field": {"keep": [1, 2, 3]},
            },
            {"protocol": "freedom", "tag": "direct", "settings": {}},
        ],
    }

    candidates = StructuredJSONAdapter().parse(json.dumps(document), source_name="xray-feed")

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.protocol is Protocol.VLESS
    assert candidate.endpoint.host == "de.example.org"
    assert candidate.source_payload.format is SourceFormat.XRAY_JSON
    saved = candidate.source_payload.data
    assert saved["document"]["log"]["custom_unknown"] is True
    assert saved["node"]["private_unknown_field"] == {"keep": [1, 2, 3]}
    assert saved["node"]["streamSettings"]["xhttpSettings"]["extra"] == {"vendor": "kept"}
    assert saved["index"] == 0


def test_parses_sing_box_hysteria2_outbound() -> None:
    document = {
        "outbounds": [
            {
                "type": "hysteria2",
                "tag": "h2",
                "server": "h2.example.org",
                "server_port": 443,
                "password": "secret",
                "tls": {"enabled": True, "server_name": "front.example.org"},
            },
            {"type": "direct", "tag": "direct"},
        ]
    }

    candidate = StructuredJSONAdapter().parse(document)[0]

    assert candidate.protocol is Protocol.HYSTERIA2
    assert candidate.endpoint.port == 443
    assert candidate.source_payload.format is SourceFormat.SING_BOX_JSON
    assert candidate.source_payload.data["node"]["tls"]["server_name"] == "front.example.org"


def test_parses_clash_json_proxy_list() -> None:
    document = {
        "proxies": [
            {
                "name": "clash-vless",
                "type": "vless",
                "server": "clash.example.org",
                "port": 443,
                "uuid": UUID,
                "tls": True,
                "network": "ws",
                "ws-opts": {"path": "/socket", "headers": {"Host": "cdn.example.org"}},
            }
        ],
        "proxy-groups": [{"name": "AUTO", "type": "select", "proxies": ["clash-vless"]}],
    }

    candidate = StructuredJSONAdapter().parse(document)[0]

    assert candidate.source_payload.format is SourceFormat.CLASH_JSON
    assert candidate.endpoint.host == "clash.example.org"
    assert candidate.source_payload.data["document"]["proxy-groups"][0]["name"] == "AUTO"
    assert candidate.source_payload.data["node"]["ws-opts"]["headers"]["Host"] == "cdn.example.org"


def test_parses_sip008_array_as_shadowsocks() -> None:
    document = [
        {
            "server": "ss.example.org",
            "server_port": 8388,
            "method": "aes-256-gcm",
            "password": "secret",
            "remarks": "sip008 node",
            "unknown": {"not": "discarded"},
        }
    ]

    candidate = StructuredJSONAdapter().parse(document)[0]

    assert candidate.protocol is Protocol.SHADOWSOCKS
    assert candidate.source_payload.format is SourceFormat.SIP008_JSON
    assert candidate.source_payload.data["node"]["unknown"] == {"not": "discarded"}


def test_fingerprint_ignores_label_but_keeps_transport_settings() -> None:
    adapter = StructuredJSONAdapter()
    common = {
        "outbounds": [
            {
                "type": "vless",
                "tag": "first",
                "server": "node.example.org",
                "server_port": 443,
                "uuid": UUID,
                "transport": {"type": "ws", "path": "/a"},
            }
        ]
    }
    renamed = {"outbounds": [{**common["outbounds"][0], "tag": "renamed"}]}
    changed_transport = {"outbounds": [{**common["outbounds"][0], "transport": {"type": "grpc", "service_name": "svc"}}]}

    first = adapter.parse(common)[0]
    second = adapter.parse(renamed)[0]
    third = adapter.parse(changed_transport)[0]

    assert first.fingerprint == second.fingerprint
    assert first.fingerprint != third.fingerprint


def test_invalid_proxy_node_is_reported_without_aborting_document() -> None:
    document = {
        "outbounds": [
            {"type": "vless", "tag": "bad", "server": "", "server_port": 443},
            {"type": "trojan", "tag": "good", "server": "good.example.org", "server_port": 443},
            {"type": "direct", "tag": "direct"},
        ]
    }

    result = StructuredJSONAdapter().parse_with_report(document)

    assert len(result.candidates) == 1
    assert result.candidates[0].label == "good"
    assert len(result.issues) == 1
    assert result.issues[0].item_index == 0
    assert result.issues[0].reason_code == "invalid_structured_endpoint"


def test_candidate_keeps_snapshot_when_caller_mutates_input_document() -> None:
    document = {
        "outbounds": [
            {
                "type": "vless",
                "server": "node.example.org",
                "server_port": 443,
                "uuid": UUID,
                "transport": {"type": "ws", "path": "/original"},
            }
        ]
    }

    candidate = StructuredJSONAdapter().parse(document)[0]
    document["outbounds"][0]["transport"]["path"] = "/mutated"

    assert (
        candidate.source_payload.data["node"]["transport"]["path"]
        == "/original"
    )


def test_clash_yaml_uses_shared_candidate_model_and_keeps_xhttp_settings() -> None:
    yaml_text = f"""proxies:
  - name: XHTTP node
    type: vless
    server: node.example.org
    port: 443
    uuid: {UUID}
    tls: true
    servername: cdn.example.org
    network: xhttp
    xhttp-opts:
      path: /upload
      host: cdn.example.org
      mode: stream-one
      x-padding-bytes: 100-1000
      reuse-settings:
        max-connections: 3
"""

    candidate = ClashYAMLAdapter().parse(yaml_text)[0]

    assert candidate.source_payload.format is SourceFormat.CLASH_YAML
    assert candidate.endpoint.host == "node.example.org"
    source_node = candidate.source_payload.data["node"]
    assert source_node["xhttp-opts"]["path"] == "/upload"
    assert source_node["xhttp-opts"]["reuse-settings"]["max-connections"] == 3
