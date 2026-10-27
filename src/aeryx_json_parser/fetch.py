from __future__ import annotations
import os, re, time, threading, mimetypes
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from typing import Any
from pathlib import Path
import requests
from .models import FetchResult
from .extract import extract_html_links

DEFAULT_UA = "AeryxJSON-Parser/1.0 (subscription fetch)"
_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


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

    def fetch(self, source: dict[str,Any], deadline: float | None = None) -> FetchResult:
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
