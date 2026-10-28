from __future__ import annotations
import json, time, hashlib, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from urllib.parse import urlsplit
from typing import Any
import yaml
from .models import ProxyNode, FetchResult, parse_endpoint, SUPPORTED_SCHEMES
from .fetch import Fetcher, redact_url
from .extract import extract_uri_strings, decode_layers
from .adapters import extract_structured_nodes
from .filtering import load_blocklists, NetworkIndex, evaluate_endpoint, parse_networks
from .checks import (detect_cores, validate_nodes, precheck_endpoints, PROBE_URLS, DEFAULT_MIN_SUCCESSFUL_PROBES, DEFAULT_REQUIRE_INDEPENDENT_PROVIDERS)
from .progress import ProgressReporter
from .routing import refresh_happ_routing
from .geolocation import CountryResolver, set_node_name

ROOT=Path(__file__).resolve().parents[2]
DEFAULT_CONFIG=ROOT/"config"/"settings.yaml"
DEFAULT_SOURCES=ROOT/"sources.txt"


def _load_yaml(path: Path) -> dict[str,Any]:
    obj=yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(obj,dict): raise ValueError(f"{path} must contain a YAML mapping")
    return obj


def _source_name(url: str, index: int) -> str:
    """Create a useful, credential-free label for a source-list entry."""
    try:
        parsed = urlsplit(url)
        # Paths can themselves contain opaque access tokens; keep reports credential-safe.
        host = parsed.hostname or "source"
        return str(host)[:100]
    except Exception:
        return f"source-{index}"


def _parse_txt_source(line: str, index: int) -> dict[str, Any]:
    """TXT line format: URL [| Header: value | Header: value]."""
    parts = [part.strip() for part in line.split("|")]
    url = parts[0]
    # A complete URL may live in an Actions secret so a public sources.txt never exposes tokens.
    is_env_url = bool(re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", url))
    if not url.lower().startswith(("http://", "https://")) and not is_env_url:
        raise ValueError(f"sources.txt line {index}: expected an absolute HTTP(S) URL or a full ${{SECRET_NAME}} URL reference")
    headers: dict[str, str] = {}
    for raw_header in parts[1:]:
        if not raw_header:
            continue
        if ":" not in raw_header:
            raise ValueError(f"sources.txt line {index}: header must use 'Name: value' format")
        key, value = raw_header.split(":", 1)
        key, value = key.strip(), value.strip()
        if not key or not value:
            raise ValueError(f"sources.txt line {index}: header name and value must not be empty")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in key + value):
            raise ValueError(f"sources.txt line {index}: control characters are not allowed in headers")
        headers[key] = value
    item: dict[str, Any] = {"url": url, "name": (f"secret-source-{index}" if is_env_url else _source_name(url, index)), "enabled": True}
    if headers:
        item["headers"] = headers
    return item


def load_sources(path: Path) -> list[dict[str,Any]]:
    if not path.exists(): raise FileNotFoundError(f"Source list not found: {path}")
    if path.suffix.lower()==".txt":
        out=[]; seen=set()
        for line_no, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            line=raw_line.strip()
            if not line or line.startswith(("#",";")): continue
            entry=_parse_txt_source(line, line_no)
            key=(entry["url"], tuple(sorted((entry.get("headers") or {}).items())))
            if key not in seen:
                seen.add(key); out.append(entry)
        return out
    # YAML remains supported for tests and migrations, but the project default is sources.txt.
    cfg=_load_yaml(path); raw=cfg.get("sources",[])
    if not isinstance(raw,list): raise ValueError("source YAML: 'sources' must be a list")
    out=[]
    for i,item in enumerate(raw):
        if isinstance(item,str): item={"url":item}
        if not isinstance(item,dict) or not (item.get("url") or item.get("file") or item.get("path")) or not item.get("enabled",True): continue
        entry=dict(item); entry.setdefault("name",f"source-{i+1}"); entry["url"]=str(entry.get("url") or "").strip()
        if (entry["url"] or entry.get("file") or entry.get("path")) and entry not in out: out.append(entry)
    return out


def _source_key(source: dict[str,Any]) -> str:
    raw=json.dumps({"url":str(source.get("url","")),"file":str(source.get("file",source.get("path",""))),"headers":source.get("headers",{})},sort_keys=True,default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def _embedded_proxy_name(uri: str, scheme: str) -> str:
    """Read names from protocols where the client label is inside Base64 payload."""
    from urllib.parse import parse_qs, urlsplit, unquote
    from .models import _decode_base64
    parsed = urlsplit(uri)
    if parsed.fragment:
        return unquote(parsed.fragment)
    try:
        payload = (parsed.netloc + parsed.path).strip()
        if scheme == "vmess":
            value = json.loads(_decode_base64(payload).decode("utf-8-sig"))
            return str(value.get("ps") or value.get("name") or "") if isinstance(value, dict) else ""
        if scheme == "ssr":
            decoded = _decode_base64(payload).decode("utf-8", "replace")
            query = decoded.partition("/?")[2]
            params = parse_qs(query, keep_blank_values=True)
            remarks = (params.get("remarks") or [""])[0]
            if not remarks:
                return ""
            try:
                raw = _decode_base64(remarks).decode("utf-8", "replace")
                return unquote(raw)
            except Exception:
                return unquote(remarks)
    except Exception:
        return ""
    return ""


def _parse_link(uri: str, source: str) -> ProxyNode:
    host,port,scheme=parse_endpoint(uri)
    name = _embedded_proxy_name(uri, scheme)
    return ProxyNode(uri=uri.strip(),scheme=scheme,host=host,port=port,name=name,source=source)


def _parse_document(content: str) -> tuple[list[str],list[dict[str,Any]]]:
    """Parse plain/Base64 share links and structured Xray/sing-box JSON layers."""
    links = extract_uri_strings(content)
    providers: list[dict[str, Any]] = []
    # Some panels Base64-wrap a complete Xray/sing-box JSON object, not a URI list.
    # Decode each bounded layer and run the structured adapters on it as well.
    for layer in decode_layers(content):
        structured, discovered = extract_structured_nodes(layer)
        links.extend(structured)
        providers.extend(discovered)
    unique: list[str] = []
    seen: set[str] = set()
    for link in links:
        if link not in seen:
            unique.append(link); seen.add(link)
    unique_providers: list[dict[str, Any]] = []
    seen_providers: set[str] = set()
    for provider in providers:
        key = json.dumps(provider, sort_keys=True, ensure_ascii=False, default=str)
        if key not in seen_providers:
            unique_providers.append(provider); seen_providers.add(key)
    return unique, unique_providers


def _static_networks(config: dict[str,Any]) -> list:
    out=[]
    for value in config.get("manual_cidrs",[]) or []: out.extend(parse_networks(str(value)))
    value=config.get("manual_cidrs_file")
    if value:
        p=Path(value)
        if not p.is_absolute(): p=ROOT/p
        if p.exists(): out.extend(parse_networks(p.read_text(encoding="utf-8",errors="replace")))
    return sorted(set(out),key=lambda n:(n.version,int(n.network_address),n.prefixlen))


def _subscription_metadata(config: dict[str, Any], node_count: int, generated_at: datetime | None = None) -> list[str]:
    """Create Happ-compatible subscription metadata with a live timestamp/count."""
    settings = config.get("subscription", {}) or {}
    tz_name = str(settings.get("timezone", "Europe/Moscow"))
    try:
        tz = ZoneInfo(tz_name)
    except ZoneInfoNotFoundError:
        tz = timezone.utc
    moment = generated_at or datetime.now(tz)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=tz)
    moment = moment.astimezone(tz)
    timestamp = moment.strftime("%d.%m.%Y %H:%M")
    title = str(settings.get("profile_title", "AeryxVPN"))[:25]
    support_url = str(settings.get("support_url", "https://t.me/cheesyx"))
    web_page_url = str(settings.get("profile_web_page_url", "https://t.me/AeryxVPN"))
    interval = max(1, int(settings.get("profile_update_interval_hours", 1)))
    announce = (
        f"AeryxVPN · Новости: @AeryxVPN · Разработчики: @cheesyx · "
        f"обновлено: {timestamp} | конфигов: {node_count}"
    )
    # Happ documents a maximum of 200 visible characters for announce.
    announce = announce[:200]
    return [
        f"#profile-title: {title}",
        f"#support-url: {support_url}",
        f"#profile-web-page-url: {web_page_url}",
        f"#profile-update-interval: {interval}",
        f"#announce: {announce}",
    ]


def _write_subscription(
    path: Path,
    nodes: list[ProxyNode],
    routing_link: str = "",
    metadata_lines: list[str] | None = None,
):
    """Write metadata, then the Happ routing profile, then proxy URIs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    lines = list(metadata_lines or [])
    # Happ supports routing links embedded in the subscription body. Keep it before
    # proxy records to ensure clients encounter it during subscription parsing.
    if routing_link:
        lines.append(routing_link.strip())
    lines.extend(n.uri for n in nodes)
    tmp.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    tmp.replace(path)


def _count_proxy_lines(text: str) -> int:
    prefixes = tuple(f"{scheme}://" for scheme in SUPPORTED_SCHEMES)
    return sum(1 for line in text.splitlines() if line.strip().lower().startswith(prefixes))


def _write_report(out_dir: Path, report: dict[str,Any], invalid: dict[str,Any], rejected: list[dict[str,Any]]):
    report["invalid_links"]=[{"source":v.get("source"),"reason":v.get("error")} for v in list(invalid.values())[:2000]]
    safe=[]
    for entry in rejected:
        node=entry.get("node")
        safe.append({"node":node.to_dict(include_uri=False) if node else {},"stage":entry.get("stage"),"reason":entry.get("reason")})
    report["rejections"]=safe[:5000]
    report["finished_at"]=datetime.now(timezone.utc).isoformat(timespec="seconds")
    (out_dir/"validation_report.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")


def run_pipeline(config_path: Path=DEFAULT_CONFIG,sources_path: Path=DEFAULT_SOURCES,check_mode: str|None=None,
                 workers: int|None=None,max_runtime: int|None=None,skip_blocklist: bool=False,
                 force_publish: bool=False,refresh_routing: bool=True) -> dict[str,Any]:
    started=time.monotonic(); cfg=_load_yaml(config_path)
    pcfg=cfg.get("pipeline",{}) or {}; fcfg=cfg.get("fetch",{}) or {}; ccfg=cfg.get("check",{}) or {}; bcfg=cfg.get("blocklists",{}) or {}; ocfg=cfg.get("outputs",{}) or {}
    mode=check_mode or str(ccfg.get("mode","proxy"))
    if mode not in {"none","tcp","proxy"}: raise ValueError("check mode must be none, tcp, or proxy")
    worker_count=max(1,min(int(workers or ccfg.get("workers",32)),96)); runtime=max(20,int(max_runtime or pcfg.get("max_runtime_seconds",240)))
    deadline=started+runtime; out_dir=Path(ocfg.get("directory","output")); out_dir=out_dir if out_dir.is_absolute() else ROOT/out_dir; out_dir.mkdir(parents=True,exist_ok=True)
    cache=Path(bcfg.get("cache_path","output/blocklist_cache.json")); cache=cache if cache.is_absolute() else ROOT/cache
    progress=ProgressReporter(out_dir/"progress.jsonl")
    report={"schema_version":1,"parser":"AeryxJSON-Parser","version":"1.4.3","started_at":datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "check_mode":mode,"runtime_budget_seconds":runtime,"sources":[],"stages":[],"counts":{},"warnings":[]}
    fetcher=Fetcher(fcfg); initial=load_sources(sources_path)
    progress.emit("start", "Запуск обработки подписки", {"sources":len(initial),"budget_seconds":runtime,"mode":mode})

    # Stage 1: parallel source download and bounded expansion of web panels/provider URLs.
    max_sources=max(1,min(int(fcfg.get("max_total_sources",50)),300)); max_depth=max(0,min(int(fcfg.get("follow_depth",2)),4))
    pending=[(s,0) for s in initial]; submitted=set(); source_results=[]; raw_links=[]; invalid={}; fetch_errors=0
    while pending and len(submitted)<max_sources and time.monotonic()<deadline:
        batch=[]
        for source,depth in pending:
            key=_source_key(source)
            if key in submitted: continue
            submitted.add(key); batch.append((source,depth))
            if len(submitted)>=max_sources: break
        pending=[]
        if not batch: break
        with ThreadPoolExecutor(max_workers=max(4,min(16,int(fcfg.get("workers",12))))) as pool:
            futures={pool.submit(fetcher.fetch,s,deadline):(s,d) for s,d in batch}
            for future in as_completed(futures):
                source,depth=futures[future]
                try: fr=future.result()
                except Exception as exc: fr=FetchResult(url=redact_url(str(source.get("url",""))),source_name=str(source.get("name","")),error=f"{type(exc).__name__}: source processing failed")
                record={"name":fr.source_name,"url":fr.url,"final_url":fr.final_url,"status":fr.status,"status_code":fr.status_code,
                        "content_type":fr.content_type,"bytes_downloaded":fr.bytes_downloaded,"elapsed_ms":fr.elapsed_ms}
                if getattr(fr, "client_profile", "default") != "default":
                    record["client_profile"] = fr.client_profile
                if getattr(fr, "compatibility_note", ""):
                    record["compatibility_note"] = fr.compatibility_note[:240]
                if fr.error: record["error"]=fr.error[:300]; fetch_errors+=1
                links,providers=_parse_document(fr.content) if fr.status=="ok" and fr.content else ([],[])
                record["links_extracted"]=len(links); record["providers_discovered"]=len(providers)
                source_results.append(record)
                for link in links:
                    try: raw_links.append(_parse_link(link,fr.source_name))
                    except Exception as exc: invalid.setdefault(link,{"source":fr.source_name,"error":str(exc)[:180]})
                if depth<max_depth and time.monotonic()<deadline:
                    for child in fr.discovered_urls+providers:
                        child_url=str(child.get("url","")).strip()
                        if child_url: pending.append((dict(child),depth+1))
        progress.emit("fetch_batch", "Завершён пакет источников", {"sources_done":len(source_results),"unique_nodes_so_far":len(raw_links),"fetch_errors":fetch_errors})
        if len(submitted)>=max_sources and pending: report["warnings"].append(f"Nested source discovery capped at {max_sources} URLs")
    report["sources"]=source_results
    report["stages"].append({"name":"fetch_and_parse","configured_sources":len(initial),"fetched_sources":len(source_results),"fetch_errors":fetch_errors,
                             "raw_links":len(raw_links),"invalid_links":len(invalid),"elapsed_seconds":round(time.monotonic()-started,2)})
    progress.emit("fetch_and_parse", "Источники разобраны", {"fetched":len(source_results),"links":len(raw_links),"invalid":len(invalid),"errors":fetch_errors})
    # Exact dedupe (only remove remarks); auth and transport options remain part of identity.
    nodes=[]; seen=set()
    for node in raw_links:
        if node.identity not in seen: seen.add(node.identity); nodes.append(node)
    report["stages"].append({"name":"deduplicate","input":len(raw_links),"output":len(nodes),"removed":len(raw_links)-len(nodes),"elapsed_seconds":round(time.monotonic()-started,2)})
    progress.emit("deduplicate", "Дубликаты удалены", {"input":len(raw_links),"unique":len(nodes),"duplicates":len(raw_links)-len(nodes)})
    if not nodes:
        report["counts"]={"configured_sources":len(initial),"fetched_sources":len(source_results),"unique_nodes":0,"accepted":0}
        report["warnings"].append("No valid proxy nodes were extracted; the previous final subscription was left unchanged.")
        progress.emit("stop", "Остановка: не найдено ни одной валидной конфигурации", {"accepted":0})
        _write_report(out_dir,report,invalid,[]); return report

    # Stage 2: IP/CIDR filtering. Feed failures are fail-open for external lists; private/non-global IPs stay blocked.
    bstart=time.monotonic(); networks=[]; bdetails={"status":"skipped","network_count":0,"sources":[]}
    if not skip_blocklist and bcfg.get("enabled",True):
        try: networks,bdetails=load_blocklists(bcfg,cache,workers=int(bcfg.get("workers",6)),deadline=deadline)
        except Exception as exc: bdetails={"status":"unavailable_fail_open","network_count":0,"error":f"{type(exc).__name__}: {exc}"}
    networks.extend(_static_networks(bcfg)); index=NetworkIndex(networks)
    hosts=sorted({n.host for n in nodes}); endpoint_info={}
    with ThreadPoolExecutor(max_workers=min(48,max(4,worker_count))) as pool:
        futures={pool.submit(evaluate_endpoint,host,index,bcfg,deadline):host for host in hosts}
        for future in as_completed(futures):
            host=futures[future]
            try: endpoint_info[host]=future.result()
            except Exception as exc: endpoint_info[host]={"host":host,"resolved_ips":[],"resolve_status":f"error:{type(exc).__name__}","blocked_matches":[],"non_global_ips":[],"blocked":False}
    kept=[]; rejected=[]; unresolved=0
    for node in nodes:
        info=endpoint_info.get(node.host,{"resolved_ips":[],"resolve_status":"not_checked","blocked":False})
        node.endpoint_ip=(info.get("allowed_ips") or info.get("resolved_ips") or [None])[0]
        if info.get("resolve_status") not in {"resolved","literal"}: unresolved+=1
        if info.get("blocked"):
            node.check_status="blocked_ip"; reason=[]
            if info.get("blocked_matches"): reason.append("CIDR denylist match")
            if info.get("non_global_ips"): reason.append("non-global address")
            rejected.append({"uri":node.uri,"stage":"blocklist","reason":", ".join(reason),"node":node})
        else: kept.append(node)
    report["blocklist"]={**bdetails,"network_count":len(networks),"filtered":len(nodes)-len(kept),"unresolved_hosts":unresolved}
    report["stages"].append({"name":"ip_cidr_filter","input":len(nodes),"output":len(kept),"removed":len(nodes)-len(kept),"unresolved_hosts":unresolved,"elapsed_seconds":round(time.monotonic()-bstart,2)})
    progress.emit("ip_cidr_filter", "Проверены DNS и IP/CIDR-блок-листы", {"input":len(nodes),"eligible":len(kept),"blocked":len(nodes)-len(kept),"unresolved_hosts":unresolved})

    # Stage 3: quick endpoint reachability. This only prioritizes work; it never by itself rejects a node.
    check_start=time.monotonic(); cores=detect_cores(ROOT); report["cores"]={k:Path(v).name for k,v in cores.items()}
    tcp_counts={}
    if mode == "proxy" and kept:
        tcp_stride=max(1,len(kept)//10)
        def tcp_progress(done,total,counts):
            if done == 1 or done == total or done % tcp_stride == 0:
                progress.emit("endpoint_precheck", f"Проверка TCP-адресов: {done}/{total}", counts)
        tcp_counts=precheck_endpoints(kept, workers=int(ccfg.get("tcp_precheck_workers",64)),
                                      timeout=float(ccfg.get("tcp_precheck_timeout_seconds",0.9)), progress_callback=tcp_progress)
        # Positive endpoint checks first, UDP schemes next, failures last. Never drop a node here.
        priority={"open":0,"not_applicable_udp":1}
        kept.sort(key=lambda n:(priority.get(n.tcp_precheck,2),n.host,n.port))
    report["endpoint_precheck"]={"counts":tcp_counts,"total":len(kept)}
    progress.emit("endpoint_precheck", "Этап доступности конечных адресов завершён", tcp_counts or {"status":"skipped"})
    if mode=="proxy" and not cores:
        report["warnings"].append("No Xray/sing-box binary detected. Proxy mode fell back to TCP-only; no node is labelled as tunnel-validated. Run python tools/install_cores.py.")
    before=len(kept); probe_targets=[]
    for url in ccfg.get("test_urls",[]) or []:
        url=str(url).strip()
        if url.startswith(("https://", "http://")):
            parsed_url=urlsplit(url)
            if parsed_url.path.rstrip("/").endswith("/generate_204") or parsed_url.path.rstrip("/")=="/generate_204":
                expected={204}
            else:
                expected={200}
            probe_targets.append((url,expected))
    if not probe_targets:
        probe_targets=PROBE_URLS
    minimum_successes=max(1,int(ccfg.get("minimum_successful_probes",DEFAULT_MIN_SUCCESSFUL_PROBES)))
    require_independent=bool(ccfg.get("require_independent_probe_domains",DEFAULT_REQUIRE_INDEPENDENT_PROVIDERS))
    if len(probe_targets) < minimum_successes:
        report["warnings"].append(
            f"Only {len(probe_targets)} health target(s) configured. High-confidence quorum is {minimum_successes}; a single exact response will be retried and assigned lower confidence instead of being discarded."
        )
    check_workers=max(1,min(worker_count,int(ccfg.get("max_concurrent_core_probes",ccfg.get("workers",12))),32))
    validation_stride=max(1,len(kept)//10)
    def validation_progress(done,total,counts):
        if done == 1 or done == total or done % validation_stride == 0:
            successful=sum(v for k,v in counts.items() if k.startswith("proxy_ok"))
            progress.emit("tunnel_validation", f"Туннельная проверка: {done}/{total}", {"passed":successful,"completed":done,"total":total,"statuses":counts}, summary=True)
    progress.emit("tunnel_validation", "Запущена проверка через sing-box/Xray", {"nodes":len(kept),"workers":check_workers,"targets":len(probe_targets),"timeout_per_node":float(ccfg.get("per_node_timeout_seconds",10))})
    status_counts=validate_nodes(
        kept, cores, mode, check_workers, deadline,
        float(ccfg.get("per_node_timeout_seconds",10)), probe_targets,
        minimum_successes, require_independent,
        progress_callback=validation_progress,
        retry_single_success=bool(ccfg.get("retry_single_success", True)),
    )
    effective_mode = "proxy" if mode=="proxy" and cores else ("tcp" if mode=="proxy" else mode)
    # Aggregate probe observations so the next scheduled report explains why nodes passed/failed.
    from collections import Counter
    probe_observations=Counter()
    failure_reasons=Counter()
    for node in kept:
        if not node.check_status.startswith("proxy_ok"):
            failure_reasons[(node.check_reason or node.check_status).split(";")[0][:120]] += 1
        for fragment in (node.check_reason or "").split(";"):
            if "=" not in fragment:
                continue
            host,result=fragment.split("=",1)
            host=host.strip().lower()
            if "." in host and len(host)<255:
                probe_observations[f"{host} {result.strip()[:70]}"] += 1
    confidence_counts={}
    for node in kept:
        if node.check_status.startswith("proxy_ok"):
            confidence_counts[node.validation_confidence]=confidence_counts.get(node.validation_confidence,0)+1
    vote_positive = sum(1 for n in kept for v in n.validation_votes.values() if v is not None and v > 0)
    vote_negative = sum(1 for n in kept for v in n.validation_votes.values() if v is not None and v < 0)
    node_results = [
        {
            "scheme": n.scheme, "host": n.host, "port": n.port, "name": n.name,
            "status": n.check_status, "confidence": n.validation_confidence,
            "tcp_precheck": n.tcp_precheck, "elapsed_ms": n.elapsed_ms,
            "validation_score": n.validation_score, "validation_votes": n.validation_votes,
            "successful_probes": n.successful_probe_count, "probe_targets": n.probe_target_count,
            "reason_code": ((n.check_reason or n.check_status).split(";")[0])[:120],
        }
        for n in kept
    ]
    report["validation"]={"requested_mode":mode,"effective_mode":effective_mode,"status_counts":status_counts,
                          "confidence_counts":confidence_counts,"endpoint_precheck_counts":tcp_counts,
                          "elapsed_seconds":round(time.monotonic()-check_start,2),"workers":check_workers,
                          "stage_vote_totals":{"positive":vote_positive,"negative":vote_negative,"net":vote_positive-vote_negative},
                          "node_results":node_results,
                          "health_policy":{"preferred_successful_probes":minimum_successes,
                                            "require_independent_probe_domains_for_high_confidence":require_independent,
                                            "single_exact_probe_retry":bool(ccfg.get("retry_single_success",True)),
                                            "targets":[{"host":urlsplit(url).hostname,"accepted_statuses":sorted(accepted)} for url,accepted in probe_targets]},
                          "probe_observations":[{"result":k,"count":v} for k,v in probe_observations.most_common(100)],
                          "common_failure_reasons":[{"reason":k,"count":v} for k,v in failure_reasons.most_common(30)]}
    report["stages"].append({"name":"parallel_validation","input":before,"status_counts":status_counts,"elapsed_seconds":round(time.monotonic()-check_start,2)})
    progress.emit("tunnel_validation", "Туннельная проверка завершена", {"input":before,"passed":sum(v for k,v in status_counts.items() if k.startswith("proxy_ok")),"confidence":confidence_counts,"statuses":status_counts,"elapsed_seconds":round(time.monotonic()-check_start,2)})
    if mode=="proxy" and cores:
        # The scheduled publisher is deliberately strict: only a positive tunnel test
        # can enter the public subscription. Unchecked or adapter-incompatible nodes
        # remain visible in diagnostics but are never silently advertised as working.
        candidate=[n for n in kept if n.check_status.startswith("proxy_ok")]
        candidate_ids={id(n) for n in candidate}
        rejected.extend(
            {"uri":n.uri,"stage":"probe","reason":n.check_reason or n.check_status,"node":n}
            for n in kept if id(n) not in candidate_ids
        )
    else:
        # TCP is diagnostic only. Don't destroy a valid node solely because TCP was briefly refused.
        candidate=kept
        if mode=="tcp": report["warnings"].append("TCP mode is diagnostic, not a proxy-handshake test; structurally valid nodes are retained.")

    # Resolve a country per candidate and replace all old/noisy labels with a stable name.
    # IP geolocation is preferred; existing config/source labels and ccTLDs are fallbacks.
    lcfg = cfg.get("location", {}) or {}
    db_value = str(lcfg.get("database_path", "output/dbip-country-lite.mmdb"))
    db_path = Path(db_value)
    if not db_path.is_absolute():
        db_path = ROOT / db_path
    require_country = bool(lcfg.get("require_country", False))
    resolver = None
    location_counts: dict[str, int] = {}
    located_candidate: list[ProxyNode] = []
    try:
        resolver = CountryResolver(db_path)
        if require_country and not resolver.available:
            report["warnings"].append(f"Country database not found at {db_path}; candidates will need a country from the source/config label or hostname TLD.")
        for node in candidate:
            info = endpoint_info.get(node.host, {})
            ip_candidates = []
            for ip in [node.endpoint_ip, *(info.get("allowed_ips") or []), *(info.get("resolved_ips") or [])]:
                if ip and ip not in ip_candidates:
                    ip_candidates.append(str(ip))
            labels = [node.name, node.source]
            country = resolver.resolve(ip_candidates, labels, node.host)
            if country is None:
                if require_country:
                    rejected.append({"uri": node.uri, "stage": "location", "reason": "country could not be determined from IP, source/config label, or host country suffix", "node": node})
                    continue
                # In non-production diagnostic configurations, make uncertainty explicit
                # rather than leaving the URI with no generated label. Production sets
                # require_country=true, where this fallback is prohibited.
                from .geolocation import Country
                country = Country("EU", "Europe", "fallback_unknown")
            set_node_name(node, country)
            located_candidate.append(node)
            location_counts[country.code] = location_counts.get(country.code, 0) + 1
        old_candidate_count = len(candidate)
        candidate = located_candidate
        report["locations"] = {"database_available": resolver.available, "database_path": str(db_path),
                               "named": len(candidate), "rejected_unresolved": old_candidate_count-len(candidate),
                               "country_counts": location_counts,
                               "methods": "IP geolocation first; config/source label and country-code TLD fallback"}
    except Exception as exc:
        report["warnings"].append(f"Country labeling failed: {type(exc).__name__}: {str(exc)[:180]}")
        report["locations"] = {"database_available": False, "named": 0, "error": type(exc).__name__}
        if require_country:
            for node in candidate:
                rejected.append({"uri": node.uri, "stage": "location", "reason": "country geolocation unavailable; fail-closed", "node": node})
            candidate = []
        else:
            # Diagnostic/test configurations without a GeoIP database still never
            # emit nameless records. Mark the uncertainty explicitly instead.
            for node in candidate:
                from .geolocation import Country
                set_node_name(node, Country("EU", "Europe", "fallback"))

    if resolver is not None:
        resolver.close()

    # The Happ routing profile is part of the delivered subscription body, not just a
    # sidecar artifact. Refresh it, or use the last known-good deep link if refresh is
    # explicitly disabled/failed. Never publish without it when routing is configured.
    rcfg = cfg.get("routing", {}) or {}
    routing_enabled = bool(rcfg.get("happ_enabled", True))
    include_routing = bool(rcfg.get("include_in_subscription", True))
    routing_link = ""
    routing_ready = not (routing_enabled and include_routing)
    profile_path = ROOT / str(rcfg.get("profile_path", "routing/HAPP-ROUTING.JSON"))
    deeplink_path = ROOT / str(rcfg.get("deeplink_path", "routing/HAPP-ROUTING.DEEPLINK"))

    def load_existing_routing_link() -> str:
        try:
            value = deeplink_path.read_text(encoding="utf-8-sig").strip()
            # Validate shape and payload before reusing it from a previous run.
            import base64
            marker = "happ://routing/onadd/"
            if not value.startswith(marker):
                return ""
            encoded = value[len(marker):].strip()
            decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
            profile = json.loads(decoded.decode("utf-8"))
            if not isinstance(profile, dict) or not {"Name", "GlobalProxy", "RouteOrder"}.issubset(profile):
                return ""
            return value
        except Exception:
            return ""

    if routing_enabled and include_routing:
        if refresh_routing:
            try:
                routing_link = refresh_happ_routing(profile_path, deeplink_path)
                routing_ready = bool(routing_link)
            except Exception as exc:
                report["warnings"].append(f"Happ routing refresh failed: {type(exc).__name__}: {str(exc)[:180]}")
        if not routing_link:
            routing_link = load_existing_routing_link()
            routing_ready = bool(routing_link)
            if routing_ready:
                report["warnings"].append("Using the last known-good Happ routing deep link because refresh did not produce a new link.")
        if not routing_ready:
            report["warnings"].append("Happ routing profile is required but unavailable; publication is blocked to avoid emitting a subscription without routing.")
    elif not include_routing:
        routing_ready = True
    report["routing"] = {"enabled": routing_enabled, "included_in_subscription": include_routing,
                          "ready": routing_ready, "profile_name": str(rcfg.get("profile_path", "routing/HAPP-ROUTING.JSON"))}

    min_count=max(1,int(pcfg.get("min_output_configs",5))); min_ratio=max(0.0,min(1.0,float(pcfg.get("min_output_ratio",0.02))))
    ratio=len(candidate)/max(1,len(nodes)); final_path=out_dir/str(ocfg.get("subscription_file","AeryxVPN"))
    candidate_path=out_dir/str(ocfg.get("candidate_file","proxies.candidate.txt"))
    previous_count = _count_proxy_lines(final_path.read_text(encoding="utf-8", errors="replace")) if final_path.exists() else 0
    metadata_lines = _subscription_metadata(cfg, len(candidate))
    effective_routing_link = routing_link if include_routing and routing_enabled else ""
    _write_subscription(candidate_path, candidate, effective_routing_link, metadata_lines)
    # Automatic publication in proxy mode requires a usable validation core and at
    # least one positive real tunnel check. Otherwise retain the previous final file;
    # the candidate/report remain available for diagnostics or an explicit override.
    validation_ready = True
    if mode == "proxy":
        validation_ready = bool(cores) and any(n.check_status.startswith("proxy_ok") for n in candidate)
    safe=(validation_ready and routing_ready and len(candidate)>=min_count and ratio>=min_ratio) or force_publish
    if safe:
        _write_subscription(final_path, candidate, effective_routing_link, metadata_lines)
        publish={"status":"published","subscription_file":str(final_path),"candidate_file":str(candidate_path)}
    else:
        publish={"status":"safety_stop_existing_kept" if final_path.exists() else "safety_stop_candidate_only","subscription_file":str(final_path),"candidate_file":str(candidate_path)}
        details=[]
        if not validation_ready: details.append("proxy validation unavailable or no successful tunnel check")
        if not routing_ready: details.append("required Happ routing profile is missing or invalid")
        if len(candidate)<min_count: details.append(f"only {len(candidate)} candidates (minimum {min_count})")
        if ratio<min_ratio: details.append(f"candidate ratio {ratio:.1%} below {min_ratio:.1%}")
        report["warnings"].append("Safety stop: " + "; ".join(details) + ". Final subscription unchanged.")
    (out_dir/str(ocfg.get("structured_file","parsed_proxies.json"))).write_text(json.dumps([n.to_dict() for n in candidate],ensure_ascii=False,indent=2),encoding="utf-8")
    (out_dir/str(ocfg.get("rejected_file","rejected_proxies.txt"))).write_text("\n".join(str(x["uri"]) for x in rejected)+("\n" if rejected else ""),encoding="utf-8")
    report["counts"]={"configured_sources":len(initial),"fetched_sources":len(source_results),"source_errors":fetch_errors,"raw_links":len(raw_links),"unique_nodes":len(nodes),
                       "blocked":sum(1 for x in rejected if x["stage"]=="blocklist"),"probe_rejected":sum(1 for x in rejected if x["stage"]=="probe"),
                       "location_rejected":sum(1 for x in rejected if x["stage"]=="location"),
                       "candidate_nodes":len(candidate),"previous_subscription_nodes":previous_count,"total_elapsed_seconds":round(time.monotonic()-started,2)}
    publish.update({"previous_count":previous_count,"candidate_count":len(candidate),"ratio":round(ratio,4),"force_publish":force_publish})
    report["publish"]=publish
    progress.emit("publication", "Решение по публикации", {"status":publish.get("status"),"candidate_count":len(candidate),"previous_count":previous_count,"confidence":confidence_counts})
    report["progress_file"]="output/progress.jsonl (runner artifact; not committed to the public subscription repository)"
    _write_report(out_dir,report,invalid,rejected)
    return report
