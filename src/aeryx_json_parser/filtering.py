from __future__ import annotations
import ipaddress, json, re, socket, time, threading, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
import requests

NETWORK_RE = re.compile(r"(?<![\w:.])(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?|[0-9a-fA-F:]{2,}(?:/[0-9]{1,3})?)(?![\w:.])")
FEEDS = [
  {"name":"AntiFilter aggregated list","url":"https://antifilter.download/list/allyouneed.lst","format":"text"},
  {"name":"Russia blocked IPs aggregate","url":"https://raw.githubusercontent.com/eduard256/russia-blocked-ips/main/ip.txt","format":"text"},
]


def parse_networks(text: str) -> list[ipaddress.IPv4Network|ipaddress.IPv6Network]:
    out=set()
    for raw in text.splitlines():
        line=raw.strip()
        if not line or line.startswith(("#",";","//")): continue
        line=line.split("#",1)[0].strip()
        for token in NETWORK_RE.findall(line):
            token=token.strip("'\";,[]{}()")
            try:
                network=ipaddress.ip_network(token,strict=False)
                # A broad route accidentally pasted into a feed must never blackhole
                # every candidate. /0 is not a useful host blocklist entry here.
                if network.prefixlen != 0: out.add(network)
            except ValueError: pass
        # Supports simple JSON/YAML key/value records too.
        for match in re.finditer(r"(?i)(?:ip|cidr|network|subnet|address)\s*[:=]\s*[\"']?([^\s,\"'}]+)",line):
            try:
                network=ipaddress.ip_network(match.group(1),strict=False)
                if network.prefixlen != 0: out.add(network)
            except ValueError: pass
    return sorted(out,key=lambda n:(n.version,int(n.network_address),n.prefixlen))


def _feed_get(feed: dict[str,Any], timeout: tuple[float,float], max_bytes: int, deadline: float|None=None) -> tuple[list,dict]:
    start=time.monotonic(); url=str(feed["url"]); s=requests.Session(); s.trust_env=False
    try:
        remaining = deadline - time.monotonic() if deadline is not None else max(timeout)
        if remaining <= 0.1: raise TimeoutError("global runtime budget exceeded")
        bounded_timeout=(max(0.1,min(timeout[0],remaining)),max(0.1,min(timeout[1],remaining)))
        r=s.get(url,timeout=bounded_timeout,headers={"User-Agent":"AeryxJSON-Parser/1.0 blocklist-update","Accept":"text/plain, application/json, */*"},stream=True)
        with r:
            r.raise_for_status(); chunks=[]; size=0
            for c in r.iter_content(65536):
                if deadline is not None and time.monotonic() >= deadline: raise TimeoutError("global runtime budget exceeded during feed download")
                if c:
                    size+=len(c)
                    if size>max_bytes: raise ValueError(f"feed over {max_bytes} bytes")
                    chunks.append(c)
            body=b"".join(chunks)
        text=body.decode("utf-8-sig",errors="replace")
        if str(feed.get("format","text"))=="json":
            data=json.loads(text); vals=[]
            def walk(v):
                if isinstance(v,str):
                    try: ipaddress.ip_network(v.strip(),strict=False); vals.append(v)
                    except ValueError: pass
                elif isinstance(v,dict):
                    for k,x in v.items():
                        if str(k).lower() in {"ip","ips","cidr","network","subnet","address","value"} or isinstance(x,(dict,list)): walk(x)
                elif isinstance(v,list):
                    for x in v: walk(x)
            walk(data); nets=parse_networks("\n".join(vals))
        else: nets=parse_networks(text)
        if not nets: raise ValueError("no valid IP/CIDR entries in feed")
        return nets,{"name":feed.get("name",url),"url":_redact(url),"status":"ok","network_count":len(nets),"bytes":size,"elapsed_ms":round((time.monotonic()-start)*1000),"sha256":hashlib.sha256(body).hexdigest()}
    finally: s.close()


def _redact(url):
    from .fetch import redact_url
    return redact_url(url)


class NetworkIndex:
    """CIDR lookup indexed by prefix length; avoids scanning every CIDR per proxy."""
    def __init__(self, networks):
        self.prefixes={4:[],6:[]}; self.values={4:{},6:{}}
        for net in networks:
            v=net.version; prefix=net.prefixlen; self.values[v].setdefault(prefix,set()).add(int(net.network_address))
        for v in (4,6): self.prefixes[v]=sorted(self.values[v].keys(),reverse=True)
    def match(self, ip):
        addr=ipaddress.ip_address(str(ip).split("%",1)[0]); width=32 if addr.version==4 else 128; n=int(addr)
        for prefix in self.prefixes[addr.version]:
            mask=((1<<prefix)-1) << (width-prefix) if prefix else 0
            if (n & mask) in self.values[addr.version][prefix]: return f"{ipaddress.ip_network((addr, prefix),strict=False)}"
        return None


def load_blocklists(config: dict[str,Any], cache_path: Path, workers: int = 6, deadline: float|None=None) -> tuple[list,dict]:
    """Fetch feeds concurrently, use fresh per-feed cache, fail open for external feeds."""
    if not config.get("enabled",True): return [],{"status":"disabled","network_count":0,"sources":[]}
    feeds=config.get("feeds",FEEDS); cache_hours=float(config.get("cache_hours",72)); max_bytes=int(config.get("max_feed_bytes",12*1024*1024))
    cache_path.parent.mkdir(parents=True,exist_ok=True)
    try: cache=json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception: cache={"feeds":{}}
    cached=cache.get("feeds",{}) if isinstance(cache,dict) else {}; next_cache={"updated_at":int(time.time()),"feeds":{}}
    merged=set(); reports=[]
    with ThreadPoolExecutor(max_workers=max(1,min(workers,12))) as pool:
        fmap={pool.submit(_feed_get,feed,(2.5,float(config.get("timeout_seconds",5))),max_bytes,deadline):feed for feed in feeds}
        for future in as_completed(fmap):
            feed=fmap[future]; raw_key=str(feed.get("url","")); key=hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
            try:
                nets,info=future.result(); items=[n.with_prefixlen for n in nets]; merged.update(nets)
                next_cache["feeds"][key]={"fetched_at":int(time.time()),"networks":items,"sha256":info["sha256"]}
                reports.append(info)
            except Exception as exc:
                old=(cached.get(key) or cached.get(raw_key) or {}) if isinstance(cached,dict) else {}
                age=time.time()-float(old.get("fetched_at",0) or 0)
                if old.get("networks") and age<=cache_hours*3600:
                    nets=parse_networks("\n".join(str(x) for x in old["networks"])); merged.update(nets)
                    next_cache["feeds"][key]=old
                    reports.append({"name":feed.get("name",key),"url":_redact(key),"status":"cache","network_count":len(nets),"age_hours":round(age/3600,1),"error":type(exc).__name__})
                else:
                    reports.append({"name":feed.get("name",key),"url":_redact(key),"status":"error","error":type(exc).__name__})
    if next_cache["feeds"]:
        tmp=cache_path.with_suffix(cache_path.suffix+".tmp")
        tmp.write_text(json.dumps(next_cache,ensure_ascii=False,separators=(",",":")),encoding="utf-8"); tmp.replace(cache_path)
    raw_nets=sorted(merged,key=lambda n:(n.version,int(n.network_address),n.prefixlen))
    # Feeds often contain broad CDN/cloud prefixes in addition to precise blocked IPs.
    # Only enforce reasonably specific external ranges by default; manual CIDRs remain
    # operator-enforced separately. This is a guard against accidentally filtering large
    # legitimate hosting networks because a third-party aggregate includes one broad ASN.
    min_v4=max(1,min(32,int(config.get("minimum_external_prefix_v4",24))))
    min_v6=max(1,min(128,int(config.get("minimum_external_prefix_v6",48))))
    nets=[net for net in raw_nets if net.prefixlen >= (min_v4 if net.version==4 else min_v6)]
    ignored_broad=len(raw_nets)-len(nets)
    return nets,{"status":"fresh_or_cached" if nets else "unavailable_fail_open","network_count":len(nets),"raw_network_count":len(raw_nets),"ignored_broad_prefix_count":ignored_broad,"minimum_external_prefix_v4":min_v4,"minimum_external_prefix_v6":min_v6,"successful_sources":sum(1 for x in reports if x["status"]=="ok"),"cached_sources":sum(1 for x in reports if x["status"]=="cache"),"failed_sources":sum(1 for x in reports if x["status"]=="error"),"sources":reports}


def resolve_ips(host: str, timeout: float=1.5) -> tuple[list[str],str]:
    try:
        ip=ipaddress.ip_address(host.strip("[]").split("%",1)[0]); return [ip.compressed],"literal"
    except ValueError: pass
    # getaddrinfo has no timeout parameter; execute in a daemon thread so a slow system
    # resolver cannot hold the entire pipeline open indefinitely.
    answer=[]; error=[]; done=threading.Event()
    def worker():
        try: answer.extend(sorted({item[4][0].split("%",1)[0] for item in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)}))
        except Exception as exc: error.append(f"{type(exc).__name__}: {exc}")
        finally: done.set()
    t=threading.Thread(target=worker,daemon=True); t.start(); done.wait(timeout)
    if not done.is_set(): return [],"dns-timeout"
    return answer,("resolved" if answer else (error[0] if error else "dns-no-address"))


def evaluate_endpoint(host: str, index: NetworkIndex, config: dict[str,Any], deadline: float|None=None) -> dict[str,Any]:
    if deadline is not None and time.monotonic() >= deadline:
        return {"host":host,"resolved_ips":[],"resolve_status":"global-runtime-budget","blocked_matches":[],"non_global_ips":[],"blocked":False}
    ips,resolve_status=resolve_ips(host,float(config.get("dns_timeout_seconds",1.5)))
    matches=[]; nonglobal=[]
    for value in ips:
        try: addr=ipaddress.ip_address(value)
        except ValueError: continue
        if not addr.is_global:
            nonglobal.append(value)
        matched=index.match(value)
        if matched: matches.append({"ip":value,"network":matched})
    reject_private=bool(config.get("reject_non_global_addresses",True))
    # Hostnames can have multiple A/AAAA records. Do not reject the entire node if
    # only one address is listed while another resolved address remains usable.
    matched_ips={str(item["ip"]) for item in matches}
    non_global_set=set(nonglobal)
    effectively_blocked=[ip for ip in ips if ip in matched_ips or (reject_private and ip in non_global_set)]
    all_addresses_blocked=bool(ips) and len(effectively_blocked)==len(ips)
    allowed_ips=[ip for ip in ips if ip not in effectively_blocked]
    return {"host":host,"resolved_ips":ips,"allowed_ips":allowed_ips,"resolve_status":resolve_status,"blocked_matches":matches,"non_global_ips":nonglobal,
            "blocked":all_addresses_blocked}
