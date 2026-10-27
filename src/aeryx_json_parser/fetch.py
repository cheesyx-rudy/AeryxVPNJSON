from __future__ import annotations
import os, re, time, threading, mimetypes, hashlib
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from typing import Any
from pathlib import Path
import requests
from .models import FetchResult
from .extract import extract_html_links, extract_uri_strings, decode_layers
from .adapters import extract_structured_nodes
from .models import SUPPORTED_SCHEMES

DEFAULT_UA = "AeryxParser/2.2 (+subscription import; Python requests)"
_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

CLIENT_LANDING_MARKERS = (
    "вставлять в клиент", "вставить в клиент", "а не по ней переходить",
    "вставить в приложение", "откройте ссылку в приложении", "используйте ссылку в клиенте",
    "insert this link into the client", "paste this link into the client",
    "open this link in the app", "use this link in the app", "client is not supported",
    "app not supported", "use happ", "unsupported client",
)


def has_supported_payload(content: str) -> bool:
    """True only when content contains proxy share links or convertible structured nodes."""
    if not content or not content.strip():
        return False
    try:
        layers = decode_layers(content)
    except Exception:
        layers = [content]
    for layer in layers:
        try:
            for link in extract_uri_strings(layer):
                scheme = urlsplit(link).scheme.lower()
                if scheme in SUPPORTED_SCHEMES:
                    return True
        except Exception:
            pass
        try:
            links, _ = extract_structured_nodes(layer)
            if links:
                return True
        except Exception:
            pass
    return False


def _safe_set_header(headers: dict[str, Any], name: str, value: str) -> None:
    """Set an HTTP header without keeping duplicate keys with different casing."""
    for existing in list(headers):
        if str(existing).lower() == name.lower():
            del headers[existing]
    headers[name] = value


def _happ_headers(url: str, existing: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    """Build a Happ-compatible request profile without inventing a device identity.

    If a panel requires device registration, callers must provide their own permitted
    HWID using the HAPP_HWID secret or an explicit per-source X-HWID header.
    """
    headers = dict(existing)
    profile = settings.get("happ_profile", {}) or {}
    _safe_set_header(headers, "User-Agent", str(profile.get("user_agent", "Happ/3.23.0")))
    _safe_set_header(headers, "Accept", str(profile.get("accept", "text/plain, application/json, */*")))
    defaults = {
        "X-Device-OS": str(profile.get("device_os", "Android")),
        "X-Device-Model": str(profile.get("device_model", "AeryxJSON-Parser")),
        "X-Ver-OS": str(profile.get("os_version", "14")),
        "X-Device-Locale": str(profile.get("locale", "ru_RU")),
    }
    configured_hwid = os.environ.get("HAPP_HWID", "").strip()
    source_header_names = {str(k).lower() for k in existing}
    # Do not synthesize/spoof an HWID. Use the authorized device identifier explicitly
    # configured by the operator, or preserve the per-source X-HWID header as supplied.
    if configured_hwid and "x-hwid" not in source_header_names:
        defaults["X-HWID"] = configured_hwid
    core_version = str(profile.get("xray_core_version", "")).strip()
    if core_version:
        defaults["X-Xray-Core"] = core_version
    for name, value in defaults.items():
        if name.lower() not in source_header_names:
            _safe_set_header(headers, name, value)
    return headers


def _needs_happ_compatibility(url: str, result: FetchResult) -> bool:
    """Recognize provider wrappers that return a browser instruction instead of data."""
    path = urlsplit(url).path.lower()
    if "bypass-hwid-lock" in path or "happ" in path:
        return not has_supported_payload(result.content)
    body = (result.content or "").lower()
    if any(marker in body for marker in CLIENT_LANDING_MARKERS):
        return not has_supported_payload(result.content)
    return False


def resolve_env(value: Any) -> Any:
    if isinstance(value,str):
        def sub(m):
            key=m.group(1)
            if key not in os.environ or not os.environ[key]:
                raise ValueError(f"required environment variable {key} referenced by the source list is not set")
            return os.environ[key]
        return _ENV_RE.sub(sub,value)
    if isinstance(value,dict): return {str(k):resolve_env(v) for k,v in value.items()}
    if isinstance(value,list): return [resolve_env(v) for v in value]
    return value


def redact_url(url: str) -> str:
    try:
        p=urlsplit(url)
        # Query strings often contain opaque panel tokens or signatures whose names
        # are unknown. Preserve keys for diagnostics, redact every value.
        query=[(k, "***") for k,v in parse_qsl(p.query,keep_blank_values=True)]
        netloc=p.netloc
        if "@" in netloc: netloc="***@"+netloc.rsplit("@",1)[1]
        # Opaque path segments are also commonly used as bearer tokens by panels.
        # Preserve ordinary filenames, but mask long token-like path components.
        path_parts=[]
        for segment in p.path.split("/"):
            if len(segment) >= 24 and re.fullmatch(r"[A-Za-z0-9._~-]+", segment):
                path_parts.append("***")
            else:
                path_parts.append(segment)
        safe_path="/".join(path_parts)
        return urlunsplit((p.scheme,netloc,safe_path,urlencode(query),""))
    except Exception: return "<redacted-url>"

class Fetcher:
    def __init__(self, settings: dict[str,Any]):
        self.settings = dict(settings or {})
        settings = self.settings
        self.timeout_connect=float(settings.get("connect_timeout_seconds",4))
        self.timeout_read=float(settings.get("read_timeout_seconds",8))
        self.max_bytes=int(settings.get("max_source_bytes",20*1024*1024))
        self.retries=max(0,int(settings.get("retries",1)))
        self.follow_pages=bool(settings.get("follow_web_pages",True))
        self._local=threading.local()

    def _session(self):
        if not hasattr(self._local,"session"):
            s=requests.Session(); s.trust_env=False
            s.headers.update({"User-Agent":DEFAULT_UA,"Accept":"text/plain, text/html, application/yaml, application/json, */*"})
            self._local.session=s
        return self._local.session

    def fetch(self, source: dict[str, Any], deadline: float | None = None) -> FetchResult:
        """Fetch normally; retry special client-only provider links as a Happ-compatible client."""
        initial = self._fetch_once(source, deadline)
        if not bool(self.settings.get("client_compatibility_fallback", True)):
            return initial
        raw_url = str(source.get("url") or "").strip()
        try:
            url = str(resolve_env(raw_url)).strip() if raw_url else ""
        except Exception:
            return initial
        if not url or not _needs_happ_compatibility(url, initial):
            return initial
        if deadline is not None and time.monotonic() >= deadline:
            initial.compatibility_note = "Happ-compatible retry skipped: runtime deadline reached."
            return initial

        original_headers = source.get("headers") or {}
        if not isinstance(original_headers, dict):
            original_headers = {}
        compatible_source = dict(source)
        compatible_source["headers"] = _happ_headers(url, original_headers, self.settings)
        compatible = self._fetch_once(compatible_source, deadline)
        compatible.client_profile = "happ-compat"
        used_hwid = any(str(k).lower() == "x-hwid" for k in compatible_source["headers"])
        compatible.compatibility_note = (
            "Retried with a Happ-compatible request profile because the endpoint returned a client-only page "
            "or no parseable proxy data. "
            + ("An explicitly configured device ID was sent." if used_hwid else "No HWID was fabricated or sent; set HAPP_HWID only if this is an authorized device ID and the panel requires it.")
        )
        if not has_supported_payload(compatible.content):
            # Keep the final response for diagnostics, but make the failed adapter attempt explicit.
            failure = f"HTTP {compatible.status_code}" if compatible.status_code else (compatible.error or "no response")
            compatible.error = (
                f"Happ-compatible retry returned no recognized proxy data ({failure}); "
                "the source may require its registered device ID or a different documented client profile."
            )
        return compatible

    def _fetch_once(self, source: dict[str,Any], deadline: float | None = None) -> FetchResult:
        raw_url=str(source.get("url") or "").strip()
        try: url=str(resolve_env(raw_url)).strip() if raw_url else ""
        except Exception as exc:
            return FetchResult(url=redact_url(raw_url) if raw_url else "<local-file>",source_name=str(source.get("name") or "source"),error=f"{type(exc).__name__}: {exc}"[:220])
        name=str(source.get("name") or (urlsplit(url).netloc if url else "local-file"))
        start=time.monotonic(); result=FetchResult(url=redact_url(url) if url else "<local-file>",source_name=name)
        local_value=source.get("file") or source.get("path")
        if local_value:
            path=Path(str(local_value)).expanduser()
            if not path.is_absolute(): path=Path.cwd()/path
            try:
                if not path.is_file(): raise FileNotFoundError(path)
                if path.stat().st_size>self.max_bytes: raise ValueError(f"local file exceeds max_source_bytes ({self.max_bytes})")
                raw=path.read_bytes(); result.content=raw.decode("utf-8-sig",errors="replace")
                result.status="ok"; result.bytes_downloaded=len(raw); result.final_url=f"file://{path.resolve()}"
                result.content_type=mimetypes.guess_type(path.name)[0] or "text/plain"
                result.elapsed_ms=round((time.monotonic()-start)*1000)
                return result
            except Exception as exc:
                result.error=f"{type(exc).__name__}: {exc}"[:500]; result.elapsed_ms=round((time.monotonic()-start)*1000); return result
        p=urlsplit(url)
        if p.scheme not in {"http","https"} or not p.hostname:
            result.error="source URL must be an absolute HTTP(S) URL, or provide file/path"; return result
        if deadline is not None and start>=deadline:
            result.error="global runtime budget exceeded before fetch"; return result
        try:
            headers=resolve_env(source.get("headers") or {})
        except Exception as exc:
            result.error=f"{type(exc).__name__}: {exc}"[:220]
            result.elapsed_ms=round((time.monotonic()-start)*1000)
            return result
        if not isinstance(headers,dict):
            result.error="source headers must be a mapping"; return result
        headers={str(k):str(v[0] if isinstance(v,(list,tuple)) and v else "" if isinstance(v,(list,tuple)) else v) for k,v in headers.items()}
        if not any(k.lower()=="user-agent" for k in headers): headers["User-Agent"]=DEFAULT_UA
        last_error=""
        for attempt in range(self.retries+1):
            if deadline is not None and time.monotonic()>=deadline:
                last_error="global runtime budget exceeded"; break
            try:
                remaining = deadline - time.monotonic() if deadline is not None else max(self.timeout_connect,self.timeout_read)
                if remaining <= 0.1:
                    last_error="global runtime budget exceeded"; break
                # requests applies these per socket phase. Cap both by the remaining
                # whole-run budget before opening the connection, then re-check while streaming.
                timeout_connect=max(0.1,min(self.timeout_connect,remaining))
                timeout_read=max(0.1,min(self.timeout_read,remaining))
                response=self._session().get(url,headers=headers,timeout=(timeout_connect,timeout_read),stream=True,allow_redirects=True)
                with response:
                    result.status_code=response.status_code
                    result.final_url=redact_url(response.url)
                    result.content_type=str(response.headers.get("Content-Type",""))[:160]
                    response.raise_for_status()
                    chunks=[]; size=0
                    for chunk in response.iter_content(64*1024):
                        if not chunk: continue
                        size+=len(chunk)
                        if size>self.max_bytes: raise ValueError(f"source exceeded max_source_bytes ({self.max_bytes})")
                        chunks.append(chunk)
                        if deadline is not None and time.monotonic()>=deadline: raise TimeoutError("global runtime budget exceeded while downloading")
                    raw=b"".join(chunks)
                    # BOM/Windows text and subscription responses are common.
                    content=raw.decode("utf-8-sig",errors="replace")
                    result.status="ok"; result.bytes_downloaded=size; result.content=content
                    if self.follow_pages and ("html" in result.content_type.lower() or "<html" in content[:4096].lower() or "<!doctype html" in content[:4096].lower()):
                        original_host=(urlsplit(response.url).hostname or "").lower()
                        for candidate in extract_html_links(content,response.url):
                            cp=urlsplit(candidate)
                            if (cp.hostname or "").lower()==original_host and candidate!=response.url:
                                result.discovered_urls.append({"url":candidate,"name":f"web-link:{name}","headers":headers,"parent":redact_url(url)})
                    result.elapsed_ms=round((time.monotonic()-start)*1000)
                    return result
            except Exception as exc:
                # Requests exceptions often echo the full URL (including signed query
                # parameters). Never save exception messages that could leak credentials.
                last_error=f"{type(exc).__name__}"
                # Keep retries bounded and never sleep if overall budget is almost gone.
                if attempt<self.retries and (deadline is None or time.monotonic()+0.2<deadline): time.sleep(0.15*(attempt+1))
        result.error=last_error[:500]; result.elapsed_ms=round((time.monotonic()-start)*1000)
        return result
