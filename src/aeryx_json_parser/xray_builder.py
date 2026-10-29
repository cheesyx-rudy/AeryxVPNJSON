"""Happ-compatible Xray JSON-array subscription builder.

Each JSON array item is one importable Happ entry. Country entries contain all
validated Xray-compatible nodes in that country and use Xray's burstObservatory +
leastPing balancer. A global auto entry includes every supported node.
"""
from __future__ import annotations

import copy
import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit, unquote

from .checks import build_singbox_outbound

ROOT = Path(__file__).resolve().parents[2]
PROFILE_TEMPLATE_PATH = ROOT / "config" / "xray-profile-template.json"
DEFAULT_SOCKOPT = {
    "domainStrategy": "UseIPv4",
    "tcpKeepAliveIdle": 60,
    "tcpKeepAliveInterval": 15,
    "tcpNoDelay": True,
}


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
            "allowInsecure": False,
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
            "method": "hysteria",
            "tlsSettings": tls_settings or {"serverName": host},
            "hysteriaSettings": {"version": 2, "auth": str(normalized.get("password") or "")},
        }
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
            stream["realitySettings"]["spiderX"] = spider_x

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
        }
        mode = _first(query, "mode", "")
        if mode:
            xhttp["mode"] = mode
        host_header = transport.get("host") or _first(query, "host", "")
        if host_header:
            xhttp["host"] = str(host_header)
        # parse_qs has already percent-decoded query values. Unquoting again can
        # corrupt JSON values that intentionally contain percent-escaped text.
        extra = _first(query, "extra", "")
        if extra:
            try:
                parsed_extra = json.loads(extra)
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


def _reject_public_ip_without_transport_security(host: str, protocol: str, stream: dict[str, Any]) -> None:
    """Reject VLESS-family nodes that current Xray-core refuses for public IP endpoints.

    Xray permits an unencrypted VLESS/VMess/Trojan endpoint on a domain name or a
    private IP, but rejects this configuration when the endpoint is a public IP.
    Doing this at conversion time prevents one malformed source node from breaking
    every country/Auto profile that contains it.
    """
    if protocol not in {"vless", "vmess", "trojan"}:
        return
    security = str(stream.get("security") or "none").lower()
    if security not in {"", "none"}:
        return
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return  # Hostname endpoints are not rejected by this specific Xray rule.
    if address.is_global:
        raise ValueError("xray_public_ip_requires_tls_or_reality")


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
        user: dict[str, Any] = {"id": str(normalized.get("uuid") or ""), "encryption": "none", "level": 8}
        if not user["id"]:
            raise ValueError("xray_vless_uuid_missing")
        if normalized.get("flow"):
            user["flow"] = str(normalized["flow"])
        stream = _stream_settings(normalized, uri, "vless")
        _reject_public_ip_without_transport_security(host, "vless", stream)
        payload: dict[str, Any] = {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": stream,
        }
        return payload

    if scheme == "vmess":
        user = {
            "id": str(normalized.get("uuid") or ""),
            "alterId": int(normalized.get("alter_id") or 0),
            "security": str(normalized.get("security") or "auto"),
            "level": 8,
        }
        if not user["id"]:
            raise ValueError("xray_vmess_uuid_missing")
        stream = _stream_settings(normalized, uri, "vmess")
        _reject_public_ip_without_transport_security(host, "vmess", stream)
        return {
            "tag": "proxy", "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": stream,
        }

    if scheme == "trojan":
        password = str(normalized.get("password") or "")
        if not password:
            raise ValueError("xray_trojan_password_missing")
        stream = _stream_settings(normalized, uri, "trojan")
        _reject_public_ip_without_transport_security(host, "trojan", stream)
        return {
            "tag": "proxy", "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": stream,
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
            _, tls_settings = _tls_parts(normalized, host)
            result["streamSettings"] = {"security": "tls", "tlsSettings": tls_settings}
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


def _load_profile_template() -> dict[str, Any]:
    """Load the shared profile shell copied from the supplied working Happ example."""
    try:
        template = json.loads(PROFILE_TEMPLATE_PATH.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ValueError(f"Happ/Xray profile template is missing: {PROFILE_TEMPLATE_PATH}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Happ/Xray profile template is invalid JSON: {PROFILE_TEMPLATE_PATH}") from exc
    if not isinstance(template, dict):
        raise ValueError("Happ/Xray profile template must be a JSON object")
    if not isinstance(template.get("outbounds"), list):
        raise ValueError("Happ/Xray profile template must contain an outbounds array")
    return template


def _unique_outbounds(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assign proxy-N tags exactly like the sample profiles; `proxy` matches the prefix."""
    result: list[dict[str, Any]] = []
    for index, record in enumerate(records, start=1):
        item = copy.deepcopy(record["xray"])
        item["tag"] = f"proxy-{index}"
        if item.get("protocol") in {"vless", "vmess"}:
            for server in (item.get("settings") or {}).get("vnext", []):
                for user in server.get("users", []):
                    user.setdefault("level", 8)
        stream = item.get("streamSettings")
        if isinstance(stream, dict):
            sockopt = dict(DEFAULT_SOCKOPT)
            sockopt.update(stream.get("sockopt") or {})
            stream["sockopt"] = sockopt
        result.append(item)
    return result


def build_xray_json_profile(
    remarks: str,
    records: list[dict[str, Any]],
    burst_observatory: dict[str, Any] | None = None,
    socks_port: int = 10808,
) -> dict[str, Any]:
    """Build one Happ Xray profile using the supplied shared JSON template."""
    if not records:
        raise ValueError("cannot build a country profile without proxy nodes")

    profile = copy.deepcopy(_load_profile_template())
    profile["remarks"] = remarks
    profile["outbounds"] = _unique_outbounds(records) + copy.deepcopy(profile["outbounds"])

    inbounds = profile.get("inbounds") or []
    socks = next((item for item in inbounds if item.get("tag") == "socks"), None)
    if socks is None:
        raise ValueError("profile template must contain a SOCKS inbound tagged 'socks'")
    socks["port"] = int(socks_port)

    # Keep the template's selectors/routing in sync with its proxy-N tag convention.
    profile["burstObservatory"]["subjectSelector"] = ["proxy"]
    balancers = profile["routing"].get("balancers") or []
    if len(balancers) != 1:
        raise ValueError("profile template must contain exactly one balancer")
    balancer = balancers[0]
    balancer["tag"] = "balancer"
    balancer["selector"] = ["proxy"]
    balancer.pop("fallbackTag", None)

    if burst_observatory:
        config = burst_observatory
        ping = profile["burstObservatory"]["pingConfig"]
        mapping = {
            "connectivity": "connectivity",
            "destination": "destination",
            "http_method": "httpMethod",
            "interval": "interval",
            "sampling": "sampling",
            "timeout": "timeout",
        }
        for source_key, target_key in mapping.items():
            if source_key in config and config[source_key] not in (None, ""):
                ping[target_key] = config[source_key]

    return profile
