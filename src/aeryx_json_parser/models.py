from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any
from urllib.parse import urlsplit, parse_qs, parse_qsl, urlencode, unquote, urlunsplit
import base64, json, ipaddress

SUPPORTED_SCHEMES = {
    "vless", "vmess", "trojan", "ss", "ssr", "hysteria", "hysteria2", "hy2",
    "tuic", "anytls", "socks", "socks5", "http", "https"
}

@dataclass(slots=True)
class ProxyNode:
    uri: str
    scheme: str
    host: str
    port: int
    name: str = ""
    source: str = ""
    endpoint_ip: str | None = None
    structural_ok: bool = True
    structural_reason: str = "ok"
    check_status: str = "not_checked"
    check_reason: str = ""
    elapsed_ms: int | None = None
    tcp_precheck: str = "not_checked"
    validation_confidence: str = "unknown"
    successful_probe_count: int = 0
    probe_target_count: int = 0
    validation_votes: dict[str, int | None] = field(default_factory=dict)
    validation_score: int = 0

    @property
    def identity(self) -> str:
        # Drop only the human-readable fragment. Keep auth, query and transport options:
        # two differently configured links to one endpoint are not necessarily duplicates.
        raw=self.uri.strip()
        try:
            parsed=urlsplit(raw)
            # Query ordering has no semantic effect for these share links. Sort pairs
            # to deduplicate equivalent links without discarding auth/transport data.
            query=urlencode(sorted(parse_qsl(parsed.query,keep_blank_values=True)),doseq=True)
            return urlunsplit((parsed.scheme.lower(),parsed.netloc,parsed.path,query,""))
        except Exception:
            return raw.partition("#")[0]

    def to_dict(self, include_uri: bool = True) -> dict[str, Any]:
        value = asdict(self)
        if not include_uri:
            value.pop("uri", None)
        return value

@dataclass(slots=True)
class FetchResult:
    url: str
    final_url: str = ""
    status: str = "error"
    status_code: int | None = None
    content_type: str = ""
    bytes_downloaded: int = 0
    elapsed_ms: int = 0
    content: str = ""
    error: str = ""
    discovered_urls: list[dict[str, Any]] = field(default_factory=list)
    source_name: str = ""
    client_profile: str = "default"
    compatibility_note: str = ""


def parse_endpoint(uri: str) -> tuple[str, int, str]:
    raw = uri.strip()
    p = urlsplit(raw)
    scheme = p.scheme.lower()
    host = (p.hostname or "").strip("[]").rstrip(".").lower()
    port = p.port or 0
    if scheme == "vmess":
        payload = unquote((p.netloc + p.path).strip())
        decoded = _decode_base64(payload)
        obj = json.loads(decoded.decode("utf-8-sig"))
        host = str(obj.get("add") or obj.get("address") or obj.get("server") or "").strip().strip("[]").lower()
        port = int(obj.get("port") or 0)
        if not host or not port:
            raise ValueError("VMess: missing server or port")
    elif scheme == "ss":
        host, port = _ss_endpoint(p)
    elif scheme == "ssr":
        text = _decode_base64(p.netloc + p.path).decode("utf-8", "replace")
        main = text.split("/?", 1)[0]
        parts = main.split(":")
        if len(parts) < 6:
            raise ValueError("SSR: malformed payload")
        host, port = parts[0].strip("[]").lower(), int(parts[1])
    elif scheme in {"socks", "socks5", "http", "https", "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "anytls"}:
        if not host or not port:
            raise ValueError(f"{scheme}: missing server or port")
    else:
        raise ValueError(f"unsupported scheme: {scheme or '(none)'}")

    if not host:
        raise ValueError("server hostname/IP is empty")
    if not (1 <= int(port) <= 65535):
        raise ValueError(f"port is outside 1..65535: {port}")
    if any(c.isspace() for c in host):
        raise ValueError("server hostname contains whitespace")
    # Fail fast on malformed numeric address literals; hostnames remain allowed.
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        if ":" in host and not host.startswith("["):
            # A colon in a non-IP hostname usually means an unescaped port/invalid URI.
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if host.count(":") > 0:
                    raise ValueError("invalid IPv6 address literal")
    return host, int(port), scheme


def _decode_base64(s: str) -> bytes:
    s = s.strip()
    # Both URL-safe and classic Base64 occur in share links.
    compact = "".join(s.split())
    compact += "=" * (-len(compact) % 4)
    try:
        return base64.urlsafe_b64decode(compact.encode("ascii"))
    except Exception as exc:
        raise ValueError("invalid Base64 payload") from exc


def _ss_endpoint(p) -> tuple[str, int]:
    netloc = p.netloc
    if "@" in netloc:
        _, hostport = netloc.rsplit("@", 1)
    else:
        decoded = _decode_base64(netloc + p.path).decode("utf-8", "replace")
        _, hostport = decoded.rsplit("@", 1)
    hp = urlsplit("//" + hostport)
    if not hp.hostname or not hp.port:
        raise ValueError("Shadowsocks: malformed server/port")
    return hp.hostname.strip("[]").lower(), hp.port
