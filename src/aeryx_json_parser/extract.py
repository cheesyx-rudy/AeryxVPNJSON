from __future__ import annotations
import base64, binascii, html, json, re, urllib.parse
from html.parser import HTMLParser
from typing import Any

URI_RE = re.compile(r"(?i)(?:vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|anytls|socks5?|https?)://[^\s<>\"'`]+")
URL_RE = re.compile(r"(?i)https?://[^\s<>\"'`]+")
B64_RE = re.compile(r"^[A-Za-z0-9_+/=-]{24,}$")
TRAILING = ".,;:!?)]}>\"'`"

class _HTMLLinks(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.text_parts: list[str] = []
    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if value and (key.lower() in {"href", "src", "data-url", "data-href", "data-subscription", "content", "value"}):
                self.links.append(html.unescape(value.strip()))
            elif value and key.lower().startswith("data-") and ("sub" in key.lower() or "config" in key.lower()):
                self.links.append(html.unescape(value.strip()))
    def handle_data(self, data):
        if data.strip(): self.text_parts.append(data)


def clean_token(value: str) -> str:
    value = html.unescape(value.strip())
    value = value.replace("\\u0026", "&").replace("\\/", "/").replace("\\u003d", "=")
    value = value.replace("\\x3A", ":").replace("\\x2F", "/")
    return value.rstrip(TRAILING)


def decode_layers(text: str, max_depth: int = 4, max_bytes: int = 12 * 1024 * 1024) -> list[str]:
    """Decode common Base64 subscription wrappers without assuming all text is Base64."""
    seen = set(); layers = [text]
    current = text
    for _ in range(max_depth):
        compact = "".join(current.strip().split())
        if len(compact) < 24 or not B64_RE.fullmatch(compact) or compact in seen:
            break
        seen.add(compact)
        try:
            raw = base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4))
            if not raw or len(raw) > max_bytes:
                break
            decoded = raw.decode("utf-8-sig")
            if decoded == current or not any(token in decoded.lower() for token in ("://", "proxies:", "outbounds", "server:", "proxy-providers")):
                # Keep decoding for nested Base64 even if it doesn't yet show URI tokens.
                inner = "".join(decoded.strip().split())
                if len(inner) < 24 or not B64_RE.fullmatch(inner):
                    break
            current = decoded
            layers.append(current)
        except (ValueError, UnicodeDecodeError, binascii.Error):
            break
    # URL-encoded wrappers are common in panel redirect links.
    for layer in list(layers):
        unquoted = urllib.parse.unquote(layer)
        if unquoted != layer and unquoted not in layers:
            layers.append(unquoted)
    return layers


def extract_uri_strings(text: str) -> list[str]:
    found: list[str] = []
    for layer in decode_layers(text):
        for match in URI_RE.finditer(layer):
            candidate=clean_token(match.group(0))
            # HTTP(S) web pages are much more common in HTML/panel responses than
            # raw HTTP-proxy URIs. Do not mistake /api/subscription URLs for nodes.
            try:
                parsed=urllib.parse.urlsplit(candidate)
                if parsed.scheme.lower() in {"http","https"}:
                    if not parsed.port or parsed.path not in {"", "/"} or parsed.query:
                        continue
            except ValueError:
                continue
            found.append(candidate)
        # Some panels embed escaped JSON or base64 payloads in JS strings.
        try:
            obj = json.loads(layer)
            found.extend(_strings_from_object(obj))
        except Exception:
            pass
        if "<html" in layer.lower() or "<!doctype html" in layer.lower():
            parser = _HTMLLinks();
            try:
                parser.feed(layer)
                for value in parser.links:
                    found.extend(clean_token(m.group(0)) for m in URI_RE.finditer(value))
            except Exception:
                pass
                
    # Normalize URL escaping but not the opaque credentials/query values themselves.
    out, seen = [], set()
    for value in found:
        value = clean_token(value)
        if value and value not in seen:
            out.append(value); seen.add(value)
    return out


def _strings_from_object(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, str):
        out.extend(clean_token(m.group(0)) for m in URI_RE.finditer(obj))
    elif isinstance(obj, dict):
        for value in obj.values(): out.extend(_strings_from_object(value))
    elif isinstance(obj, list):
        for value in obj: out.extend(_strings_from_object(value))
    return out


def extract_html_links(text: str, base_url: str) -> list[str]:
    parser = _HTMLLinks()
    try: parser.feed(text)
    except Exception: pass
    candidates = list(parser.links)
    # Include absolute API/config paths embedded in inline scripts.
    candidates += [clean_token(m.group(0)) for m in URL_RE.finditer(text)]
    result, seen = [], set()
    for value in candidates:
        value = value.strip()
        if not value or value.startswith(("javascript:", "data:", "mailto:", "#")):
            continue
        try: full = urllib.parse.urljoin(base_url, value)
        except Exception: continue
        p = urllib.parse.urlsplit(full)
        if p.scheme not in {"http", "https"} or not p.hostname:
            continue
        # A generic interface can contain hundreds of navigation links. Follow only likely
        # subscription/export/config endpoints and only same-host URLs in the caller.
        path = p.path.lower()
        hint = any(k in path for k in ("sub", "config", "proxy", "export", "download", "raw", "api", "profile", "clash", "v2ray", "link"))
        if hint and full not in seen:
            result.append(full); seen.add(full)
    return result
