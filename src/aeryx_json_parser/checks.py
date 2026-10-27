from __future__ import annotations
import base64, json, os, socket, subprocess, tempfile, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
import requests
from .models import ProxyNode, parse_endpoint, _decode_base64

# A quorum of two independent providers gives high confidence, but is not an absolute
# gate: some networks block individual health destinations. Any accepted node still needs
# an exact end-to-end response through the running proxy; one such response is rechecked
# and classified with lower confidence if the repeat or multi-provider quorum is absent.
# Arbitrary error pages, redirects, and generic 4xx responses are never accepted as health.
PROBE_URLS = [
    ("https://www.gstatic.com/generate_204", {204}),
    ("https://cp.cloudflare.com/generate_204", {204}),
    ("http://www.msftconnecttest.com/connecttest.txt", {200}),
    ("https://api.ipify.org", {200}),
    ("https://checkip.amazonaws.com", {200}),
]
DEFAULT_MIN_SUCCESSFUL_PROBES = 2  # preferred strong quorum; a strict single success gets a second-stage retry
DEFAULT_REQUIRE_INDEPENDENT_PROVIDERS = True
UDP_SCHEMES = {"hysteria", "hysteria2", "hy2", "tuic"}


def _first(q: dict[str,list[str]], key: str, default="") -> str:
    vals=q.get(key,[]); return str(vals[0]) if vals else default

def _truthy(v: Any) -> bool: return str(v).strip().lower() in {"1","true","yes","on"}

def _vmess(uri: str) -> dict[str,Any]:
    p=urllib.parse.urlsplit(uri)
    raw=_decode_base64(urllib.parse.unquote(p.netloc+p.path)).decode("utf-8-sig")
    obj=json.loads(raw)
    if not isinstance(obj,dict): raise ValueError("VMess payload is not a JSON object")
    return obj

def _ss(uri: str) -> tuple[str,str,str,int]:
    p=urllib.parse.urlsplit(uri); netloc=p.netloc
    if "@" in netloc:
        auth,hp=netloc.rsplit("@",1)
        if ":" not in auth: auth=_decode_base64(auth).decode()
        method,password=auth.split(":",1)
    else:
        payload=_decode_base64(netloc+p.path).decode()
        auth,hp=payload.rsplit("@",1); method,password=auth.split(":",1)
    p2=urllib.parse.urlsplit("//"+hp)
    return method,password,p2.hostname or "",p2.port or 0


def build_singbox_outbound(uri: str) -> dict[str,Any]:
    p=urllib.parse.urlsplit(uri); scheme=p.scheme.lower(); q=urllib.parse.parse_qs(p.query,keep_blank_values=True)
    host,port,_=parse_endpoint(uri); name=urllib.parse.unquote(p.fragment) or scheme
    if scheme=="vmess":
        x=_vmess(uri); host=str(x.get("add") or x.get("address") or host); port=int(x.get("port") or port)
        outbound={"type":"vmess","tag":name,"server":host,"server_port":port,"uuid":str(x.get("id") or x.get("uuid") or ""),"alter_id":int(x.get("aid") or 0),"security":str(x.get("scy") or "auto")}
        net=str(x.get("net") or "tcp").lower(); security=str(x.get("tls") or "").lower()
        if security in {"tls","true","1"}:
            outbound["tls"]={"enabled":True,"server_name":str(x.get("sni") or host),"insecure":False}
            if x.get("fp"): outbound["tls"]["utls"]={"enabled":True,"fingerprint":x["fp"]}
        if net=="ws": outbound["transport"]={"type":"ws","path":str(x.get("path") or "/"),"headers":{"Host":str(x.get("host") or host)}}
        elif net=="grpc": outbound["transport"]={"type":"grpc","service_name":str(x.get("path") or "")}
        elif net in {"httpupgrade","http-upgrade"}: outbound["transport"]={"type":"httpupgrade","path":str(x.get("path") or "/"),"host":str(x.get("host") or host)}
        elif net=="xhttp": outbound["transport"]={"type":"http","path":str(x.get("path") or "/"),"host":str(x.get("host") or host)}
        if not outbound["uuid"]: raise ValueError("VMess UUID missing")
        return outbound
    if scheme in {"ss"}:
        if _first(q,"plugin",""):
            # The Xray outbound adapter does not reproduce arbitrary SIP002 plugin options.
            raise ValueError("Shadowsocks plugin requires a plugin-aware validator")
        method,password,host,port=_ss(uri)
        if not method or not password: raise ValueError("Shadowsocks method/password missing")
        return {"type":"shadowsocks","tag":name,"server":host,"server_port":port,"method":method,"password":password}

    tls_q=(_first(q,"security", "") or "").lower()
    tls={"enabled":tls_q in {"tls","reality"} or scheme in {"trojan","hysteria","hysteria2","hy2","tuic","anytls","https"},
         "server_name":_first(q,"sni",host)}
    if _truthy(_first(q,"allowInsecure", _first(q,"insecure","false"))): tls["insecure"]=True
    fp=_first(q,"fp","")
    if fp: tls["utls"]={"enabled":True,"fingerprint":fp}
    alpn=_first(q,"alpn","")
    if alpn: tls["alpn"]=[x for x in alpn.split(",") if x]
    if tls_q=="reality":
        pbk=_first(q,"pbk","")
        if not pbk: raise ValueError("REALITY public key (pbk) missing")
        tls["reality"]={"enabled":True,"public_key":pbk,"short_id":_first(q,"sid","")}
    if scheme=="vless":
        uid=urllib.parse.unquote(p.username or "")
        if not uid: raise ValueError("VLESS UUID missing")
        out={"type":"vless","tag":name,"server":host,"server_port":port,"uuid":uid,"tls":tls}
        flow=_first(q,"flow","")
        if flow: out["flow"]=flow
    elif scheme=="trojan":
        password=urllib.parse.unquote(p.username or "")
        if not password: raise ValueError("Trojan password missing")
        out={"type":"trojan","tag":name,"server":host,"server_port":port,"password":password,"tls":tls}
    elif scheme in {"socks","socks5"}:
        out={"type":"socks","tag":name,"server":host,"server_port":port}
        if p.username is not None: out.update({"username":urllib.parse.unquote(p.username),"password":urllib.parse.unquote(p.password or "")})
    elif scheme in {"http","https"}:
        out={"type":"http","tag":name,"server":host,"server_port":port}
        if p.username is not None: out.update({"username":urllib.parse.unquote(p.username),"password":urllib.parse.unquote(p.password or "")})
        if scheme=="https": out["tls"]={"enabled":True,"server_name":host}
    elif scheme in {"hysteria2","hy2","hysteria"}:
        password=urllib.parse.unquote(p.username or "")
        if not password: raise ValueError("Hysteria password missing")
        if scheme in {"hysteria2", "hy2"}:
            out={"type":"hysteria2","tag":name,"server":host,"server_port":port,"password":password,"tls":tls}
        else:
            # Hysteria v1's sing-box outbound uses auth_str; v2 uses password.
            out={"type":"hysteria","tag":name,"server":host,"server_port":port,"auth_str":password,"tls":tls}
        obfs=_first(q,"obfs",""); obfsp=_first(q,"obfs-password","")
        if obfs and obfsp: out["obfs"]={"type":obfs,"password":obfsp}
    elif scheme=="tuic":
        uid=urllib.parse.unquote(p.username or ""); password=urllib.parse.unquote(p.password or "")
        if not uid or not password: raise ValueError("TUIC UUID/password missing")
        out={"type":"tuic","tag":name,"server":host,"server_port":port,"uuid":uid,"password":password,"tls":tls}
        cc=_first(q,"congestion_control",_first(q,"congestion-controller",""))
        if cc: out["congestion_control"]=cc
        mode=_first(q,"udp_relay_mode",_first(q,"udp-relay-mode",""))
        if mode: out["udp_relay_mode"]=mode
    elif scheme=="anytls":
        password=urllib.parse.unquote(p.username or "")
        if not password: raise ValueError("AnyTLS password missing")
        out={"type":"anytls","tag":name,"server":host,"server_port":port,"password":password,"tls":tls}
    else:
        raise ValueError(f"sing-box adapter does not support {scheme}")

    network=_first(q,"type","tcp").lower()
    if scheme in {"vless","trojan","vmess"}:
        if network=="ws":
            headers={}; value=_first(q,"host","")
            if value: headers["Host"]=value
            out["transport"]={"type":"ws","path":_first(q,"path","/"),"headers":headers}
        elif network=="grpc":
            out["transport"]={"type":"grpc","service_name":_first(q,"serviceName",_first(q,"path",""))}
            authority=_first(q,"authority",_first(q,"host",""))
            if authority: out["transport"]["headers"]={"Host":authority}
        elif network in {"httpupgrade","http-upgrade"}:
            out["transport"]={"type":"httpupgrade","path":_first(q,"path","/"),"host":_first(q,"host",host)}
        elif network=="xhttp":
            # sing-box's HTTP transport covers compatible XHTTP deployments, but not every
            # mode/flow. Keep exact XHTTP configs flagged in diagnostics if the core rejects them.
            out["transport"]={"type":"http","path":_first(q,"path","/"),"host":_first(q,"host",host)}
        elif network not in {"tcp"}:
            # HTTP/2 and mKCP settings differ between Xray and sing-box versions;
            # let the Xray fallback try them instead of silently testing raw TCP.
            raise ValueError(f"unsupported transport for sing-box probe: {network}")
    return out


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1",0)); return int(sock.getsockname()[1])


def _probe_provider(url: str) -> str:
    """Group probe hosts by operator so two URLs on one CDN do not count twice."""
    host=(urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
    if host == "gstatic.com" or host.endswith(".gstatic.com") or host == "google.com" or host.endswith(".google.com") or host.endswith(".googleapis.com"):
        return "google"
    if host == "cloudflare.com" or host.endswith(".cloudflare.com"):
        return "cloudflare"
    if host == "msftconnecttest.com" or host.endswith(".msftconnecttest.com") or host == "msftncsi.com" or host.endswith(".msftncsi.com"):
        return "microsoft"
    if host == "ipify.org" or host.endswith(".ipify.org"):
        return "ipify"
    if host == "amazonaws.com" or host.endswith(".amazonaws.com"):
        return "amazon"
    labels=host.split(".")
    # Good enough for custom health-check hosts; built-in targets use explicit groups above.
    if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "gov", "ac"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else (host or "unknown")


def _read_probe_body(response, limit: int=4096) -> bytes:
    """Read only a small bounded response body (needed to reject captive portals)."""
    collected=bytearray()
    try:
        for chunk in response.iter_content(chunk_size=256):
            if not chunk:
                continue
            collected.extend(chunk[:max(0, limit-len(collected))])
            if len(collected) >= limit:
                break
    except Exception:
        pass
    return bytes(collected)


def _probe_response_ok(url: str, status: int, body: bytes, accepted: set[int]) -> tuple[bool,str]:
    """Validate exact status and known endpoint payload; never equate arbitrary 4xx with health."""
    parsed=urllib.parse.urlsplit(url)
    host=(parsed.hostname or "").lower()
    # HTTP error pages and redirects are not healthy tunnel checks, even if a
    # stale/custom config accidentally broadens the accepted status set.
    if status < 200 or status >= 300:
        return False, f"status_{status}"
    if status not in accepted:
        return False, f"unexpected_status_{status}"
    if parsed.path.rstrip("/") == "/generate_204":
        return (status == 204 and not body, "expected_204" if status == 204 and not body else "invalid_generate_204_response")
    if host == "www.msftconnecttest.com" and parsed.path.rstrip("/") == "/connecttest.txt":
        valid=status == 200 and body.decode("utf-8", "replace").strip() == "Microsoft Connect Test"
        return valid, "expected_msft_payload" if valid else "unexpected_msft_payload"
    if host == "api.ipify.org" or host == "checkip.amazonaws.com":
        try:
            import ipaddress
            ip = ipaddress.ip_address(body.decode("ascii", "replace").strip())
            valid = status == 200 and ip.is_global
        except ValueError:
            valid = False
        return valid, "expected_public_ip" if valid else "invalid_public_ip_payload"
    if host == "www.cloudflare.com" and parsed.path.rstrip("/") == "/cdn-cgi/trace":
        values={}
        for line in body.decode("utf-8", "replace").splitlines():
            if "=" in line:
                key,value=line.split("=",1); values[key.strip()]=value.strip()
        try:
            ip_ok=bool(values.get("ip")) and __import__("ipaddress").ip_address(values["ip"]).is_global
        except ValueError:
            ip_ok=False
        valid=status == 200 and ip_ok and values.get("http") in {"on","off"}
        return valid, "valid_cloudflare_trace" if valid else "invalid_cloudflare_trace"
    # User-configured targets may be used, but their status must match the exact
    # accepted set configured for that target; redirects and 4xx are not success.
    return True, f"expected_status_{status}"


def _probe_one_through_socks(port: int, url: str, accepted: set[int], deadline: float|None=None) -> tuple[str,str,bool]:
    proxy=f"socks5h://127.0.0.1:{port}"
    host=urllib.parse.urlsplit(url).hostname or "unknown"
    remaining=(deadline-time.monotonic()) if deadline is not None else 3.6
    # Requests has separate connect/read timeouts, so each must fit in roughly half
    # the remaining per-node budget; otherwise a late probe could overrun the budget.
    if remaining <= 0.3:
        return host, "budget_exhausted", False
    timeout=max(0.15,min(1.8,remaining/2.0))
    try:
        # One isolated session per target avoids sharing requests.Session across threads.
        with requests.Session() as session:
            session.trust_env=False
            session.proxies.update({"http":proxy,"https":proxy})
            with session.get(url,timeout=(timeout,timeout),allow_redirects=False,stream=True,
                             headers={"User-Agent":"AeryxJSON-Parser/1.0","Connection":"close"}) as response:
                status=int(response.status_code)
                # Read a small bounded body even for generate_204 targets so an invalid
                # response that claims 204 but sends content cannot be treated as empty.
                body=_read_probe_body(response)
                response.close()
        valid,why=_probe_response_ok(url,status,body,set(accepted))
        return host, f"{status}:{'ok' if valid else why}", valid
    except Exception as exc:
        return host, type(exc).__name__, False


def _request_through_socks(port: int, targets=PROBE_URLS, deadline: float|None=None,
                           minimum_successes: int=DEFAULT_MIN_SUCCESSFUL_PROBES,
                           require_independent_providers: bool=DEFAULT_REQUIRE_INDEPENDENT_PROVIDERS,
                           retry_single_success: bool=True) -> tuple[bool,str]:
    """Run a provider quorum first, then recheck borderline single-provider successes.

    A tunnel is not marked working from TCP-open or core syntax alone. At least one
    exact end-to-end probe response is required. Two independent providers are high
    confidence; one exact response is retried through the same live tunnel to avoid
    rejecting nodes merely because the other probe sites are filtered.
    """
    minimum_successes=max(1,int(minimum_successes))
    if not targets:
        return False, "health_policy_impossible:no_targets"
    attempts: list[str]=[]
    successes: list[tuple[str,str,str,set[int]]]=[]
    providers=set()
    with ThreadPoolExecutor(max_workers=max(1,min(5,len(targets)))) as pool:
        futures={pool.submit(_probe_one_through_socks,port,url,accepted,deadline):(url,accepted) for url,accepted in targets}
        for future in as_completed(futures):
            url,accepted=futures[future]
            try:
                host,result,valid=future.result()
            except Exception as exc:
                host=urllib.parse.urlsplit(url).hostname or "unknown"
                result=type(exc).__name__; valid=False
            provider=_probe_provider(url)
            attempts.append(f"{host}={result}")
            if valid:
                successes.append((url,provider,host,set(accepted)))
                providers.add(provider)

    independent_count=len(providers)
    if len(successes)>=minimum_successes and (not require_independent_providers or independent_count>=minimum_successes):
        details=";".join(sorted(attempts))
        return True,(f"verified_multi:successes={len(successes)}/{len(targets)}; providers={','.join(sorted(providers))}; "+details)[:900]

    # One operator may be the only destination reachable from this network, even if
    # two configured target URLs share that provider. Treat the provider-limited case
    # as a retry tier, rather than a hard failure, but never call it high confidence.
    if successes and (len(successes) < minimum_successes or
                      (require_independent_providers and independent_count < minimum_successes)):
        url,provider,host,accepted=successes[0]
        if retry_single_success and (deadline is None or deadline-time.monotonic() > 0.2):
            retry_host,retry_result,retry_ok=_probe_one_through_socks(port,url,accepted,deadline)
            attempts.append(f"{retry_host}_repeat={retry_result}")
            details=";".join(sorted(attempts))
            if retry_ok:
                return True,(f"verified_repeat:successes={len(successes)}/{len(targets)}; repeat=ok; provider={provider}; "
                             f"independent_providers={independent_count}; quorum=not_met; "+details)[:900]
            label="verified_single" if len(successes)==1 else "verified_low_confidence"
            return True,(f"{label}:successes={len(successes)}/{len(targets)}; repeat=failed; provider={provider}; "
                         f"independent_providers={independent_count}; low_confidence_but_tunnel_proven; {details}")[:900]
        details=";".join(sorted(attempts))
        label="verified_single" if len(successes)==1 else "verified_low_confidence"
        return True,(f"{label}:successes={len(successes)}/{len(targets)}; repeat=disabled_or_no_budget; provider={provider}; "
                     f"independent_providers={independent_count}; low_confidence_but_tunnel_proven; {details}")[:900]

    details=";".join(sorted(attempts))
    requirement=f"need_{minimum_successes}_successful_probe(s)"
    if require_independent_providers:
        requirement += f"_from_independent_providers; got_{len(successes)}_success(es)_from_{independent_count}_provider(s)"
    return False,(requirement+";"+details)[:900] or "probe_budget_exceeded"


def _uses_tcp_transport(node: ProxyNode) -> bool:
    """Return False for transports that fundamentally use UDP on their server port."""
    if node.scheme in UDP_SCHEMES:
        return False
    try:
        p=urllib.parse.urlsplit(node.uri)
        q=urllib.parse.parse_qs(p.query, keep_blank_values=True)
        transport=(q.get("type") or ["tcp"])[0].strip().lower()
        if transport in {"udp", "quic", "kcp", "http3", "h3"}:
            return False
    except Exception:
        pass
    return True


def _tcp_reachability(node: ProxyNode, timeout: float=1.0) -> tuple[str,int]:
    started=time.monotonic()
    if not _uses_tcp_transport(node):
        return "not_applicable_udp", round((time.monotonic()-started)*1000)
    # IPs were resolved in the previous DNS/IP stage. Use the resolved address here
    # so a second system DNS lookup cannot stall the whole timed validation run.
    target=node.endpoint_ip
    if not target:
        try:
            import ipaddress
            ipaddress.ip_address(node.host)
            target=node.host
        except ValueError:
            return "dns_unresolved", round((time.monotonic()-started)*1000)
    try:
        with socket.create_connection((target,node.port),timeout=max(0.15,float(timeout))):
            return "open", round((time.monotonic()-started)*1000)
    except ConnectionRefusedError:
        return "refused", round((time.monotonic()-started)*1000)
    except socket.timeout:
        return "timeout", round((time.monotonic()-started)*1000)
    except OSError as exc:
        return f"error_{type(exc).__name__}", round((time.monotonic()-started)*1000)


def precheck_endpoints(nodes: list[ProxyNode], workers: int=64, timeout: float=1.0,
                       progress_callback=None) -> dict[str,int]:
    """Cheap reachability stage; diagnostic/prioritization signal, never a sole rejection."""
    counts: dict[str,int]={}
    if not nodes:
        return counts
    max_workers=max(1,min(int(workers),96))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures={pool.submit(_tcp_reachability,node,timeout):node for node in nodes}
        for done,future in enumerate(as_completed(futures),1):
            node=futures[future]
            try:
                status,elapsed=future.result()
            except Exception as exc:
                status,elapsed=f"error_{type(exc).__name__}",None
            node.tcp_precheck=status
            counts[status]=counts.get(status,0)+1
            if progress_callback:
                progress_callback(done,len(nodes),dict(counts))
    return counts


def test_with_singbox(uri: str, binary: str, per_node_timeout: float=9.0, deadline: float|None=None, targets=PROBE_URLS,
                      minimum_successes: int=DEFAULT_MIN_SUCCESSFUL_PROBES,
                      require_independent_providers: bool=DEFAULT_REQUIRE_INDEPENDENT_PROVIDERS,
                      retry_single_success: bool=True) -> tuple[bool,str,int]:
    start=time.monotonic(); proc=None; tmp=None
    local_deadline=min(start+per_node_timeout,deadline or float("inf"))
    try:
        outbound=build_singbox_outbound(uri)
        port=_reserve_port()
        cfg={"log":{"level":"error"},"inbounds":[{"type":"socks","tag":"local-socks","listen":"127.0.0.1","listen_port":port}],
             "outbounds":[{**outbound,"tag":"proxy"},{"type":"direct","tag":"direct"}],
             "route":{"final":"proxy","auto_detect_interface":True}}
        tmp=tempfile.NamedTemporaryFile("w",encoding="utf-8",suffix=".json",delete=False)
        json.dump(cfg,tmp,ensure_ascii=False); tmp.close()
        remaining=local_deadline-time.monotonic()
        if remaining<=0.1: return False,"probe_budget_exceeded",round((time.monotonic()-start)*1000)
        check=subprocess.run([binary,"check","-c",tmp.name],capture_output=True,text=True,timeout=min(2.5,remaining))
        if check.returncode!=0: return False,"sing-box-config-invalid:"+(check.stderr or check.stdout)[-220:],round((time.monotonic()-start)*1000)
        proc=subprocess.Popen([binary,"run","-c",tmp.name],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        ready=False
        while time.monotonic()<local_deadline:
            if proc.poll() is not None:
                err=""
                try: err=(proc.stderr.read() or "")[-180:]
                except Exception: pass
                return False,"sing-box-exit:"+err,round((time.monotonic()-start)*1000)
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=0.15): ready=True; break
            except OSError: time.sleep(0.05)
        if not ready: return False,"sing-box-start-timeout",round((time.monotonic()-start)*1000)
        ok,reason=_request_through_socks(port,targets=targets,deadline=local_deadline,minimum_successes=minimum_successes,
                                         require_independent_providers=require_independent_providers,
                                         retry_single_success=retry_single_success)
        return ok,reason,round((time.monotonic()-start)*1000)
    except subprocess.TimeoutExpired: return False,"validator-timeout",round((time.monotonic()-start)*1000)
    except Exception as exc: return False,f"{type(exc).__name__}:{exc}"[:260],round((time.monotonic()-start)*1000)
    finally:
        if proc is not None:
            try: proc.terminate(); proc.wait(timeout=0.7)
            except Exception:
                try: proc.kill()
                except Exception: pass
        if tmp:
            try: os.unlink(tmp.name)
            except OSError: pass


def _tls_xray(q: dict[str,list[str]], host: str, security: str, vmess: dict[str,Any]|None=None) -> dict[str,Any]:
    vmess=vmess or {}; value={"network":"tcp","security":security or "none"}
    if security=="tls":
        tls={"serverName":_first(q,"sni",str(vmess.get("sni") or host))}
        fp=_first(q,"fp",str(vmess.get("fp") or "")); alpn=_first(q,"alpn",str(vmess.get("alpn") or ""))
        if fp: tls["fingerprint"]=fp
        if alpn: tls["alpn"]=[x for x in alpn.split(",") if x]
        if _truthy(_first(q,"allowInsecure","false")): tls["allowInsecure"]=True
        value["tlsSettings"]=tls
    elif security=="reality":
        pbk=_first(q,"pbk","");
        if not pbk: raise ValueError("REALITY public key missing")
        value["realitySettings"]={"serverName":_first(q,"sni",host),"fingerprint":_first(q,"fp","chrome"),"publicKey":pbk,"shortId":_first(q,"sid","")}
    network=_first(q,"type",str(vmess.get("net") or "tcp")).lower(); value["network"]=network
    if network=="ws":
        headers={}; h=_first(q,"host",str(vmess.get("host") or ""))
        if h: headers["Host"]=h
        value["wsSettings"]={"path":_first(q,"path",str(vmess.get("path") or "/")),"headers":headers}
    elif network=="grpc":
        grpc={"serviceName":_first(q,"serviceName",_first(q,"path",str(vmess.get("path") or "")))}
        authority=_first(q,"authority",_first(q,"host",str(vmess.get("host") or "")))
        if authority: grpc["authority"]=authority
        value["grpcSettings"]=grpc
    elif network=="http":
        host_value=_first(q,"host",str(vmess.get("host") or ""))
        hosts=[x for x in host_value.split(",") if x]
        http_settings={"path":_first(q,"path",str(vmess.get("path") or "/"))}
        if hosts: http_settings["host"]=hosts
        value["httpSettings"]=http_settings
    elif network in {"httpupgrade","http-upgrade"}:
        value["network"]="httpupgrade"; value["httpupgradeSettings"]={"path":_first(q,"path","/"),"host":_first(q,"host",host)}
    elif network=="xhttp":
        value["xhttpSettings"]={"path":_first(q,"path","/"),"host":_first(q,"host",host),"mode":_first(q,"mode","")}
    elif network not in {"tcp","http","kcp"}:
        raise ValueError(f"unsupported Xray transport {network}")
    return value


def build_xray_config(uri: str, port: int) -> dict[str,Any]:
    p=urllib.parse.urlsplit(uri); scheme=p.scheme.lower(); q=urllib.parse.parse_qs(p.query,keep_blank_values=True)
    host,remote_port,_=parse_endpoint(uri); tag=urllib.parse.unquote(p.fragment) or scheme; stream=None
    if scheme=="vmess":
        x=_vmess(uri); host=str(x.get("add") or x.get("address") or host); remote_port=int(x.get("port") or remote_port)
        uid=str(x.get("id") or x.get("uuid") or "")
        if not uid: raise ValueError("VMess UUID missing")
        outbound={"protocol":"vmess","settings":{"vnext":[{"address":host,"port":remote_port,"users":[{"id":uid,"alterId":int(x.get("aid") or 0),"security":str(x.get("scy") or "auto")}]}]}}
        sec="tls" if str(x.get("tls") or "").lower() in {"tls","true","1"} else "none"
        stream=_tls_xray(q,host,sec,x)
    elif scheme=="vless":
        uid=urllib.parse.unquote(p.username or "");
        if not uid: raise ValueError("VLESS UUID missing")
        user={"id":uid,"encryption":_first(q,"encryption","none")}; flow=_first(q,"flow","")
        if flow: user["flow"]=flow
        outbound={"protocol":"vless","settings":{"vnext":[{"address":host,"port":remote_port,"users":[user]}]}}
        stream=_tls_xray(q,host,_first(q,"security","none"))
    elif scheme=="trojan":
        password=urllib.parse.unquote(p.username or "");
        if not password: raise ValueError("Trojan password missing")
        outbound={"protocol":"trojan","settings":{"servers":[{"address":host,"port":remote_port,"password":password}]}}
        stream=_tls_xray(q,host,_first(q,"security","tls"))
    elif scheme=="ss":
        method,password,host,remote_port=_ss(uri)
        outbound={"protocol":"shadowsocks","settings":{"servers":[{"address":host,"port":remote_port,"method":method,"password":password}]}}
        stream=None
    elif scheme in {"socks","socks5"}:
        server={"address":host,"port":remote_port}
        if p.username is not None: server["users"]=[{"user":urllib.parse.unquote(p.username),"pass":urllib.parse.unquote(p.password or "")}]
        outbound={"protocol":"socks","settings":{"servers":[server]}}; stream=None
    elif scheme in {"http","https"}:
        server={"address":host,"port":remote_port}
        if p.username is not None: server["users"]=[{"user":urllib.parse.unquote(p.username),"pass":urllib.parse.unquote(p.password or "")}]
        outbound={"protocol":"http","settings":{"servers":[server]}}
        stream={"network":"tcp","security":"tls","tlsSettings":{"serverName":host}} if scheme=="https" else None
    else: raise ValueError(f"Xray adapter does not support {scheme}")
    if stream: outbound["streamSettings"]=stream
    return {"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"auth":"noauth","udp":False}}],
            "outbounds":[outbound,{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[]}}


def test_with_xray(uri: str,binary: str,per_node_timeout=9.0,deadline: float|None=None,targets=PROBE_URLS,
                   minimum_successes: int=DEFAULT_MIN_SUCCESSFUL_PROBES,
                   require_independent_providers: bool=DEFAULT_REQUIRE_INDEPENDENT_PROVIDERS,
                   retry_single_success: bool=True) -> tuple[bool,str,int]:
    start=time.monotonic(); proc=None; tmp=None
    limit=min(start+per_node_timeout,deadline or float("inf"))
    try:
        port=_reserve_port(); cfg=build_xray_config(uri,port)
        tmp=tempfile.NamedTemporaryFile("w",encoding="utf-8",suffix=".json",delete=False); json.dump(cfg,tmp); tmp.close()
        remaining=limit-time.monotonic()
        if remaining<=0.1: return False,"probe_budget_exceeded",round((time.monotonic()-start)*1000)
        test=subprocess.run([binary,"run","-test","-config",tmp.name],capture_output=True,text=True,timeout=min(2.5,remaining))
        if test.returncode!=0: return False,"xray-config-invalid:"+(test.stderr or test.stdout)[-220:],round((time.monotonic()-start)*1000)
        proc=subprocess.Popen([binary,"run","-config",tmp.name],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        ready=False
        while time.monotonic()<limit:
            if proc.poll() is not None:
                err=""
                try: err=(proc.stderr.read() or "")[-180:]
                except Exception: pass
                return False,"xray-exit:"+err,round((time.monotonic()-start)*1000)
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.15): ready=True; break
            except OSError: time.sleep(.05)
        if not ready: return False,"xray-start-timeout",round((time.monotonic()-start)*1000)
        ok,reason=_request_through_socks(port,deadline=limit,targets=targets,minimum_successes=minimum_successes,
                                         require_independent_providers=require_independent_providers,
                                         retry_single_success=retry_single_success)
        return ok,reason,round((time.monotonic()-start)*1000)
    except subprocess.TimeoutExpired: return False,"validator-timeout",round((time.monotonic()-start)*1000)
    except Exception as exc: return False,f"{type(exc).__name__}:{exc}"[:260],round((time.monotonic()-start)*1000)
    finally:
        if proc is not None:
            try: proc.terminate(); proc.wait(timeout=.7)
            except Exception:
                try: proc.kill()
                except Exception: pass
        if tmp:
            try: os.unlink(tmp.name)
            except OSError: pass


def _reported_success_count(reason: str) -> int:
    import re
    match=re.search(r"successes=(\d+)/(\d+)", reason)
    return int(match.group(1)) if match else 0


def _record_validation_votes(node: ProxyNode, reason: str, targets) -> int:
    """Score independent stages; no amount of metadata/TCP evidence can replace a tunnel probe."""
    successes=_reported_success_count(reason)
    multi=reason.startswith("verified_multi:")
    repeat=reason.startswith("verified_repeat:")
    stability_vote=1 if (multi or repeat) else -1
    tcp_vote = 1 if node.tcp_precheck == "open" else (-1 if node.tcp_precheck in {"refused", "timeout"} or node.tcp_precheck.startswith("error_") else None)
    votes={
        "structure": 1 if node.structural_ok else -1,
        "core_config_accepted": 1,
        "core_runtime_and_socks": 1,
        "exact_end_to_end_response": 1 if successes >= 1 else -1,
        "endpoint_tcp_reachability": tcp_vote,
        "independent_provider_or_repeat": stability_vote,
    }
    node.validation_votes=votes
    # Each independent stage gets one vote; the exact end-to-end response remains mandatory.
    # The score is a literal majority, not a weighted rule where one target can count twice.
    positive=sum(1 for value in votes.values() if value is not None and value > 0)
    negative=sum(1 for value in votes.values() if value is not None and value < 0)
    node.validation_score=positive-negative
    node.successful_probe_count=successes
    node.probe_target_count=len(targets)
    node.validation_confidence="high" if multi else ("medium" if repeat else "low")
    return node.validation_score


def probe_node(node: ProxyNode, cores: dict[str,str], mode: str, deadline: float|None=None, per_node_timeout: float=9.0, targets=PROBE_URLS,
               minimum_successes: int=DEFAULT_MIN_SUCCESSFUL_PROBES,
               require_independent_providers: bool=DEFAULT_REQUIRE_INDEPENDENT_PROVIDERS,
               retry_single_success: bool=True) -> tuple[str,str,int|None]:
    start=time.monotonic()
    node_deadline=min(deadline if deadline is not None else float("inf"), start+max(0.1,float(per_node_timeout)))
    if deadline is not None and start >= deadline: return "not_checked","global runtime budget reached before validation",0
    if node.scheme == "ss" and urllib.parse.parse_qs(urllib.parse.urlsplit(node.uri).query).get("plugin"):
        if mode == "proxy": return "not_checkable","Shadowsocks plugin options need exact plugin-aware core mapping",0
    if mode=="none": return "not_checked","checking disabled",0
    if mode=="tcp":
        try:
            with socket.create_connection((node.host,node.port),timeout=1.6): return "tcp_open","TCP endpoint accepts connections; tunnel not verified",round((time.monotonic()-start)*1000)
        except Exception as exc: return "tcp_closed",f"{type(exc).__name__}: {exc}",round((time.monotonic()-start)*1000)
    # Prefer sing-box for protocol breadth. Xray is a fallback for common Xray protocols.
    sb=cores.get("sing-box"); xr=cores.get("xray")
    xray_supported={"vless","vmess","trojan","ss","socks","socks5","http","https"}
    if mode=="proxy" and not sb and xr and node.scheme not in xray_supported:
        return "not_checkable","No installed core adapter for this scheme; endpoint retained unverified",0
    if sb:
        ok,reason,elapsed=test_with_singbox(node.uri,sb,per_node_timeout=per_node_timeout,deadline=node_deadline,targets=targets,minimum_successes=minimum_successes,require_independent_providers=require_independent_providers,
                                   retry_single_success=retry_single_success)
        if ok:
            score=_record_validation_votes(node,reason,targets)
            if score > 0:
                return f"proxy_ok_{node.validation_confidence}",reason+f"; votes={score}; tcp={node.tcp_precheck}",elapsed
            return "proxy_suspect",reason+f"; vote_tie_or_negative={score}",elapsed
        # A core/config mismatch shouldn't auto-delete a potentially functional node if Xray can test it.
        if xr and node.scheme in {"vless","vmess","trojan","ss","socks","socks5","http","https"}:
            ok2,reason2,elapsed2=test_with_xray(node.uri,xr,per_node_timeout=per_node_timeout,deadline=node_deadline,targets=targets,minimum_successes=minimum_successes,require_independent_providers=require_independent_providers,
                                   retry_single_success=retry_single_success)
            if ok2:
                score=_record_validation_votes(node,reason2,targets)
                if score > 0:
                    return f"proxy_ok_xray_fallback_{node.validation_confidence}",reason2+f"; votes={score}; tcp={node.tcp_precheck}",elapsed2
                return "proxy_suspect",reason2+f"; vote_tie_or_negative={score}",elapsed2
        # If deadline was reached, don't make a destructive decision from an incomplete check.
        if deadline is not None and time.monotonic()>=deadline: return "not_checked","global runtime budget reached",round((time.monotonic()-start)*1000)
        # If an adapter/core cannot represent this particular feature, it has not
        # proved the remote node is dead. Keep it unverified rather than deleting it.
        diagnostic=(reason or "").lower()
        if any(marker in diagnostic for marker in ("adapter does not support", "unsupported transport", "unsupported xray transport", "config-invalid", "valueerror:")):
            return "not_checkable",reason,elapsed
        return "proxy_failed",reason,elapsed
    if xr and node.scheme in {"vless","vmess","trojan","ss","socks","socks5","http","https"}:
        ok,reason,elapsed=test_with_xray(node.uri,xr,per_node_timeout=per_node_timeout,deadline=node_deadline,targets=targets,minimum_successes=minimum_successes,require_independent_providers=require_independent_providers,
                                   retry_single_success=retry_single_success)
        if ok:
            score=_record_validation_votes(node,reason,targets)
            if score > 0:
                return f"proxy_ok_xray_{node.validation_confidence}",reason+f"; votes={score}; tcp={node.tcp_precheck}",elapsed
            return "proxy_suspect",reason+f"; vote_tie_or_negative={score}",elapsed
        diagnostic=(reason or "").lower()
        if any(marker in diagnostic for marker in ("unsupported", "config-invalid", "valueerror:")):
            return "not_checkable",reason,elapsed
        if deadline is not None and time.monotonic()>=deadline:
            return "not_checked","global runtime budget reached",elapsed
        return "proxy_failed",reason,elapsed
    # Structural validity and TCP reachability remain useful for protocols without a validator.
    try:
        with socket.create_connection((node.host,node.port),timeout=1.6): return "tcp_only","No compatible core available; TCP endpoint reachable but proxy tunnel is unverified",round((time.monotonic()-start)*1000)
    except Exception as exc: return "tcp_closed",f"No compatible core; TCP check failed: {type(exc).__name__}",round((time.monotonic()-start)*1000)


def detect_cores(root: Path) -> dict[str,str]:
    result={}
    candidates={
        "sing-box":[os.getenv("SINGBOX_BINARY"),str(root/"tools"/"sing-box.exe"),str(root/"tools"/"sing-box"),"sing-box"],
        "xray":[os.getenv("XRAY_BINARY"),str(root/"tools"/"xray.exe"),str(root/"tools"/"xray"),"xray"],
    }
    import shutil
    for key,values in candidates.items():
        for value in values:
            if not value: continue
            if Path(value).is_file(): result[key]=str(Path(value).resolve()); break
            found=shutil.which(value)
            if found: result[key]=found; break
    return result


def validate_nodes(nodes: list[ProxyNode], cores: dict[str,str], mode: str, workers: int, deadline: float|None=None, per_node_timeout: float=9.0, targets=PROBE_URLS,
                   minimum_successes: int=DEFAULT_MIN_SUCCESSFUL_PROBES,
                   require_independent_providers: bool=DEFAULT_REQUIRE_INDEPENDENT_PROVIDERS,
                   progress_callback=None, retry_single_success: bool=True) -> dict[str,int]:
    counts={}
    # Validate likely reachable endpoints first. Failed prechecks are diagnostic only;
    # UDP transports and host-specific filtering must not be rejected on TCP evidence alone.
    priority={"open":0,"not_applicable_udp":1}
    nodes=sorted(nodes,key=lambda n:(priority.get(n.tcp_precheck,2), n.port, n.host))
    if mode=="proxy" and not cores:
        # Don't label a TCP check as a tunnel validation, and don't drop configs just because a core isn't installed.
        mode="tcp"
    max_workers=max(1,min(int(workers),96))
    completed=0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures={pool.submit(probe_node,node,cores,mode,deadline,per_node_timeout,targets,minimum_successes,require_independent_providers,retry_single_success):node for node in nodes}
        for future in as_completed(futures):
            node=futures[future]
            try: status,reason,elapsed=future.result()
            except Exception as exc: status,reason,elapsed="not_checked",f"validator-exception:{type(exc).__name__}",None
            node.check_status=status; node.check_reason=reason; node.elapsed_ms=elapsed
            counts[status]=counts.get(status,0)+1
            completed += 1
            if progress_callback:
                progress_callback(completed,len(futures),dict(counts))
    return counts
