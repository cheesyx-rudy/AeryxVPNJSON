"""Happ-compatible Xray JSON-array subscription builder.

Each JSON array item is one importable Happ entry. Country entries contain all
validated Xray-compatible nodes in that country and use Xray's observatory +
leastPing balancer. A global auto entry includes every supported node.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit, unquote

from .checks import build_singbox_outbound


def _first(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key, [])
    return str(values[0]) if values else default


def _vmess_network(uri: str, fallback: str) -> str:
    """The normalizer preserves VMess transport when it supports it; inspect net for unsupported variants."""
    if urlsplit(uri).scheme.lower() != "vmess":
        return fallback
    from .models import _decode_base64
    parsed = urlsplit(uri)
    payload = _decode_base64(unquote((parsed.netloc + parsed.path).strip()))
    data = json.loads(payload.decode("utf-8-sig"))
    return str(data.get("net") or fallback or "tcp").lower()


def _tls_parts(normalized: dict[str, Any], host: str) -> tuple[str, dict[str, Any]]:
    tls = normalized.get("tls") or {}
    reality = tls.get("reality") or {}
    if reality.get("enabled"):
        settings: dict[str, Any] = {
            "serverName": tls.get("server_name") or host,
            "fingerprint": (tls.get("utls") or {}).get("fingerprint") or "chrome",
            "publicKey": reality.get("public_key") or "",
            "shortId": reality.get("short_id") or "",
        }
        return "reality", settings
    if tls.get("enabled"):
        settings = {"serverName": tls.get("server_name") or host}
        if tls.get("insecure"):
            settings["allowInsecure"] = True
        fingerprint = (tls.get("utls") or {}).get("fingerprint")
        if fingerprint:
            settings["fingerprint"] = fingerprint
        alpn = tls.get("alpn")
        if isinstance(alpn, list) and alpn:
            settings["alpn"] = alpn
        return "tls", settings
    return "none", {}


def _stream_settings(normalized: dict[str, Any], uri: str, protocol: str) -> dict[str, Any]:
    host = str(normalized.get("server") or "")
    query = parse_qs(urlsplit(uri).query, keep_blank_values=True)
    if protocol == "hysteria":
        tls_kind, tls_settings = _tls_parts(normalized, host)
        if tls_kind == "reality":
            raise ValueError("xray_hysteria2_reality_not_supported")
        # Hysteria2 uses QUIC/TLS, not VLESS's ordinary TCP transport.
        stream: dict[str, Any] = {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": tls_settings or {"serverName": host, "alpn": ["h3"]},
            "hysteriaSettings": {"version": 2, "auth": str(normalized.get("password") or "")},
        }
        if "alpn" not in stream["tlsSettings"]:
            stream["tlsSettings"]["alpn"] = ["h3"]
        obfs = normalized.get("obfs") or {}
        if obfs:
            if str(obfs.get("type", "")).lower() != "salamander" or not obfs.get("password"):
                raise ValueError("xray_unsupported_hysteria2_obfs")
            stream["finalmask"] = {
                "udp": [{"type": "salamander", "settings": {"password": str(obfs["password"])}}]
            }
        return stream

    net = str((normalized.get("transport") or {}).get("type") or "tcp").lower()
    raw_net = _first(query, "type", "tcp").lower()
    if protocol == "vmess":
        net = _vmess_network(uri, net)
        raw_net = net
    if raw_net in {"httpupgrade", "http-upgrade"}:
        net = "httpupgrade"
    elif raw_net == "xhttp":
        net = "xhttp"
    elif net == "http" and raw_net != "xhttp":
        raise ValueError("xray_unsupported_http_transport")
    if net not in {"", "tcp", "ws", "grpc", "httpupgrade", "xhttp"}:
        raise ValueError(f"xray_unsupported_transport:{net}")

    security, security_settings = _tls_parts(normalized, host)
    stream: dict[str, Any] = {"network": net or "tcp", "security": security}
    if security == "tls":
        stream["tlsSettings"] = security_settings
    elif security == "reality":
        stream["realitySettings"] = security_settings
        spider_x = _first(query, "spx", "")
        if spider_x:
            stream["realitySettings"]["spiderX"] = unquote(spider_x)

    transport = normalized.get("transport") or {}
    if net == "ws":
        ws: dict[str, Any] = {"path": str(transport.get("path") or "/")}
        headers = transport.get("headers") or {}
        host_header = headers.get("Host") or headers.get("host") or _first(query, "host", "")
        if host_header:
            ws["headers"] = {"Host": str(host_header)}
        stream["wsSettings"] = ws
    elif net == "grpc":
        grpc: dict[str, Any] = {"serviceName": str(transport.get("service_name") or _first(query, "serviceName", _first(query, "path", "")))}
        authority = _first(query, "authority", "")
        if authority:
            grpc["authority"] = authority
        elif (transport.get("headers") or {}).get("Host"):
            grpc["authority"] = str(transport["headers"]["Host"])
        mode = _first(query, "mode", "")
        if mode:
            grpc["multiMode"] = mode.lower() in {"multi", "multi-mode", "true", "1"}
        stream["grpcSettings"] = grpc
    elif net == "httpupgrade":
        httpupgrade: dict[str, Any] = {"path": str(transport.get("path") or _first(query, "path", "/"))}
        host_header = transport.get("host") or _first(query, "host", "")
        if host_header:
            httpupgrade["host"] = str(host_header)
        stream["httpupgradeSettings"] = httpupgrade
    elif net == "xhttp":
        xhttp: dict[str, Any] = {
            "path": str(transport.get("path") or _first(query, "path", "/")),
            "mode": _first(query, "mode", "auto"),
        }
        host_header = transport.get("host") or _first(query, "host", "")
        if host_header:
            xhttp["host"] = str(host_header)
        extra = _first(query, "extra", "")
        if extra:
            try:
                parsed_extra = json.loads(unquote(extra))
            except Exception as exc:
                raise ValueError("xray_invalid_xhttp_extra") from exc
            if not isinstance(parsed_extra, dict):
                raise ValueError("xray_invalid_xhttp_extra")
            xhttp["extra"] = parsed_extra
        stream["xhttpSettings"] = xhttp
    # A VLESS/VMess/Trojan transport without TLS/REALITY must not carry empty fake fields.
    if stream.get("security") == "none":
        stream.pop("security")
    return stream


def uri_to_xray_outbound(uri: str) -> dict[str, Any]:
    """Convert a supported URI to an Xray outbound, rejecting non-equivalent mappings."""
    parsed = urlsplit(uri)
    scheme = parsed.scheme.lower()
    normalized = build_singbox_outbound(uri)
    host = str(normalized.get("server") or "")
    port = int(normalized.get("server_port") or 0)
    if not host or not (1 <= port <= 65535):
        raise ValueError("xray_missing_host_or_port")

    if scheme == "vless":
        user: dict[str, Any] = {"id": str(normalized.get("uuid") or ""), "encryption": "none"}
        if not user["id"]:
            raise ValueError("xray_vless_uuid_missing")
        if normalized.get("flow"):
            user["flow"] = str(normalized["flow"])
        payload: dict[str, Any] = {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": _stream_settings(normalized, uri, "vless"),
        }
        return payload

    if scheme == "vmess":
        user = {
            "id": str(normalized.get("uuid") or ""),
            "alterId": int(normalized.get("alter_id") or 0),
            "security": str(normalized.get("security") or "auto"),
        }
        if not user["id"]:
            raise ValueError("xray_vmess_uuid_missing")
        return {
            "tag": "proxy", "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": _stream_settings(normalized, uri, "vmess"),
        }

    if scheme == "trojan":
        password = str(normalized.get("password") or "")
        if not password:
            raise ValueError("xray_trojan_password_missing")
        return {
            "tag": "proxy", "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": _stream_settings(normalized, uri, "trojan"),
        }

    if scheme == "ss":
        return {
            "tag": "proxy", "protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": port,
                                         "method": str(normalized.get("method") or ""),
                                         "password": str(normalized.get("password") or "")}]},
        }

    if scheme in {"socks", "socks5", "http", "https"}:
        protocol = "socks" if scheme in {"socks", "socks5"} else "http"
        server: dict[str, Any] = {"address": host, "port": port}
        if normalized.get("username") is not None:
            server["users"] = [{"user": str(normalized.get("username") or ""), "pass": str(normalized.get("password") or "") }]
        result = {"tag": "proxy", "protocol": protocol, "settings": {"servers": [server]}}
        if scheme == "https":
            result["streamSettings"] = {"security": "tls", "tlsSettings": {"serverName": host}}
        return result

    if scheme in {"hysteria2", "hy2"}:
        return {
            "tag": "proxy", "protocol": "hysteria",
            "settings": {"version": 2, "address": host, "port": port},
            "streamSettings": _stream_settings(normalized, uri, "hysteria"),
        }

    # Xray-core does not implement these URI protocols as native outbounds.
    # It is safer to report explicit omission than to publish a different protocol.
    if scheme == "hysteria":
        raise ValueError("xray_protocol_unsupported:hysteria_v1")
    if scheme == "tuic":
        raise ValueError("xray_protocol_unsupported:tuic")
    if scheme == "anytls":
        raise ValueError("xray_protocol_unsupported:anytls")
    if scheme == "ssr":
        raise ValueError("xray_protocol_unsupported:ssr")
    raise ValueError(f"xray_protocol_unsupported:{scheme or 'unknown'}")


def _unique_outbounds(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assign tags unique to this profile; the first tag remains `proxy` for Happ summaries."""
    result = []
    for index, record in enumerate(records, start=1):
        item = json.loads(json.dumps(record["xray"], ensure_ascii=False))
        item["tag"] = "proxy" if index == 1 else f"aeryx-node-{index:03d}"
        result.append(item)
    return result


def build_xray_json_profile(
    remarks: str,
    description: str,
    records: list[dict[str, Any]],
    probe_url: str,
    probe_interval: str,
    socks_port: int = 10808,
    balancer_tag: str = "aeryx-least-ping",
) -> dict[str, Any]:
    """Build one complete Xray JSON subscription item compatible with Happ's JSON array."""
    if not records:
        raise ValueError("cannot build a country profile without proxy nodes")
    outbounds = _unique_outbounds(records)
    node_tags = [item["tag"] for item in outbounds]
    prefix = "aeryx-node-"
    selector = ["proxy", prefix]
    outbounds.extend([
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"},
    ])
    profile = {
        "remarks": remarks,
        "meta": {"serverDescription": description},
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"], "queryStrategy": "UseIP"},
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": int(socks_port),
            "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False},
        }],
        "outbounds": outbounds,
        "observatory": {
            "subjectSelector": selector,
            "probeUrl": probe_url,
            "probeInterval": probe_interval,
            "enableConcurrency": True,
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "inboundTag": ["socks-in"], "balancerTag": balancer_tag}],
            "balancers": [{
                "tag": balancer_tag,
                "selector": selector,
                "fallbackTag": "proxy",
                "strategy": {"type": "leastPing"},
            }],
        },
    }
    return profile
