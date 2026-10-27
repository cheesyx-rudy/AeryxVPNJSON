from __future__ import annotations
import base64, json, urllib.parse, ipaddress
from typing import Any


def _b64(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def _q(value: Any) -> str:
    return urllib.parse.quote(str(value), safe="")


def _query(values: dict[str, Any]) -> str:
    pairs=[]
    for k,v in values.items():
        if v is None or v == "" or v is False: continue
        if isinstance(v, (list, tuple)): v=",".join(map(str,v))
        if isinstance(v, bool): v="true" if v else "false"
        pairs.append((k, str(v)))
    return urllib.parse.urlencode(pairs, doseq=True, quote_via=urllib.parse.quote)


def _hostport(server: str, port: Any) -> str:
    host = str(server or "").strip()
    try: ipaddress.IPv6Address(host.strip("[]")); host=f"[{host.strip('[]')}]"
    except ValueError: pass
    return f"{host}:{int(port)}"


def _tls_params(proxy: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    tls=proxy.get("tls", {})
    if tls is True: tls={"enabled": True}
    if not isinstance(tls, dict): tls={}
    params={}
    sni=tls.get("servername") or tls.get("server_name") or proxy.get("servername") or proxy.get("sni")
    if sni: params["sni"]=sni
    fp=(tls.get("utls") or {}).get("fingerprint") if isinstance(tls.get("utls"),dict) else tls.get("fingerprint")
    fp=fp or proxy.get("client-fingerprint") or proxy.get("fingerprint")
    if fp: params["fp"]=fp
    alpn=tls.get("alpn") or proxy.get("alpn")
    if alpn: params["alpn"]=alpn
    insecure=tls.get("skip-cert-verify", tls.get("insecure", proxy.get("skip-cert-verify", False)))
    if insecure: params["allowInsecure"]="1"
    reality=tls.get("reality-opts") or tls.get("reality") or proxy.get("reality-opts") or proxy.get("reality") or {}
    if isinstance(reality,dict):
        pbk=reality.get("public-key") or reality.get("public_key") or reality.get("publicKey")
        sid=reality.get("short-id") or reality.get("short_id") or reality.get("shortId")
        if pbk: params["pbk"]=pbk
        if sid: params["sid"]=sid
    return params


def clash_proxy_to_uri(proxy: dict[str, Any]) -> str | None:
    """Convert common Mihomo/Clash proxy mappings to URI share links."""
    if not isinstance(proxy, dict): return None
    kind=str(proxy.get("type", "")).lower()
    server=proxy.get("server") or proxy.get("address") or ""
    port=proxy.get("port") or proxy.get("server_port") or 0
    name=str(proxy.get("name") or proxy.get("tag") or f"{kind}-{server}:{port}")
    if kind in {"direct", "reject", "reject-drop", "dns", "selector", "select", "url-test", "fallback", "load-balance", "relay", "pass", "compatible", "wireguard"}:
        return None
    if not server or not str(port).isdigit() or not 1 <= int(port) <= 65535: return None
    hp=_hostport(str(server),int(port)); query={}; scheme=kind; user=""
    if kind in {"ss", "shadowsocks"}:
        method=str(proxy.get("cipher") or proxy.get("method") or "")
        password=str(proxy.get("password") or "")
        if not method or not password: return None
        token=base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        plugin=proxy.get("plugin") or ""
        opts=proxy.get("plugin-opts") or proxy.get("plugin_opts") or {}
        if isinstance(opts,dict) and opts:
            parts=[]
            for key,value in opts.items():
                if value is True: parts.append(str(key))
                elif value is not False and value is not None and value != "": parts.append(f"{key}={value}")
            if parts: plugin=str(plugin)+(";" if plugin else "")+";".join(parts)
        q="?"+_query({"plugin":plugin}) if plugin else ""
        return f"ss://{token}@{hp}{q}#{_q(name)}"
    if kind == "vmess":
        tls=proxy.get("tls",False)
        network=str(proxy.get("network") or "tcp").lower()
        ws=proxy.get("ws-opts") or proxy.get("ws_opts") or {}
        grpc=proxy.get("grpc-opts") or proxy.get("grpc_opts") or {}
        obfs=ws.get("headers",{}) if isinstance(ws,dict) else {}
        host=obfs.get("Host") or obfs.get("host") or ""
        v={"v":"2","ps":name,"add":str(server),"port":str(port),"id":str(proxy.get("uuid") or ""),
           "aid":str(proxy.get("alterId") or proxy.get("alter-id") or 0),"scy":str(proxy.get("cipher") or "auto"),
           "net":network,"type":"none","host":str(host),"path":str(ws.get("path") or grpc.get("grpc-service-name") or "/"),
           "tls":"tls" if tls else "","sni":str((proxy.get("servername") or (tls.get("servername") if isinstance(tls,dict) else "") or "")),
           "alpn":",".join(tls.get("alpn",[])) if isinstance(tls,dict) and isinstance(tls.get("alpn"),list) else "",
           "fp":str(proxy.get("client-fingerprint") or "")}
        if not v["id"]: return None
        return "vmess://"+base64.b64encode(json.dumps(v,separators=(",",":"),ensure_ascii=False).encode()).decode().rstrip("=")
    if kind == "vless":
        uid=str(proxy.get("uuid") or "")
        if not uid: return None
        tls=proxy.get("tls",False)
        if isinstance(tls,dict):
            if tls.get("enabled",True): query.update(_tls_params({**proxy,"tls":tls}))
        elif tls: query.update(_tls_params(proxy))
        if (isinstance(tls,dict) and isinstance(tls.get("reality-opts"),dict)) or isinstance(proxy.get("reality-opts"),dict): query["security"]="reality"
        elif tls: query["security"]="tls"
        else: query["security"]="none"
        query["encryption"]="none"
        flow=proxy.get("flow")
        if flow: query["flow"]=flow
        network=str(proxy.get("network") or (proxy.get("network-type") or "tcp")).lower()
        query["type"]="xhttp" if network in {"xhttp","splithttp"} else network
        if network in {"ws","httpupgrade","xhttp","splithttp"}:
            key="ws-opts" if network=="ws" else "ws-opts"
            opts=proxy.get(key,{}) or {}
            if opts.get("path"): query["path"]=opts["path"]
            headers=opts.get("headers",{}) or {}
            if headers.get("Host") or headers.get("host"): query["host"]=headers.get("Host") or headers.get("host")
        if network=="grpc":
            opts=proxy.get("grpc-opts",{}) or {}
            query["serviceName"]=opts.get("grpc-service-name") or opts.get("serviceName") or ""
            query["mode"]=opts.get("mode") or ""
        return f"vless://{_q(uid)}@{hp}?{_query(query)}#{_q(name)}"
    if kind == "trojan":
        password=str(proxy.get("password") or "")
        if not password: return None
        tls=proxy.get("tls",True)
        query.update(_tls_params({**proxy,"tls":tls}))
        query["security"]="tls" if tls else "none"
        query["type"]=str(proxy.get("network") or "tcp")
        network=proxy.get("network")
        if network=="ws":
            opts=proxy.get("ws-opts",{}) or {}; query["path"]=opts.get("path","")
            headers=opts.get("headers",{}) or {}; query["host"]=headers.get("Host") or headers.get("host") or ""
        elif network=="grpc":
            opts=proxy.get("grpc-opts",{}) or {}; query["serviceName"]=opts.get("grpc-service-name") or ""
        return f"trojan://{_q(password)}@{hp}?{_query(query)}#{_q(name)}"
    if kind in {"hysteria2","hy2","hysteria"}:
        password=str(proxy.get("password") or proxy.get("auth") or proxy.get("auth-str") or "")
        if not password: return None
        query.update(_tls_params(proxy))
        obfs=proxy.get("obfs") or proxy.get("obfs-password")
        if isinstance(obfs,dict):
            if obfs.get("type"): query["obfs"]=obfs["type"]
            if obfs.get("password"): query["obfs-password"]=obfs["password"]
        elif obfs: query["obfs-password"]=obfs
        scheme="hysteria2" if kind in {"hysteria2","hy2"} else "hysteria"
        return f"{scheme}://{_q(password)}@{hp}?{_query(query)}#{_q(name)}"
    if kind == "tuic":
        uid=str(proxy.get("uuid") or proxy.get("token") or ""); password=str(proxy.get("password") or "")
        if not uid or not password: return None
        query.update(_tls_params(proxy))
        for key in ("congestion-controller","congestion_control","udp-relay-mode","udp_relay_mode","zero-rtt-handshake","heartbeat-interval"):
            if key in proxy: query[key.replace("-","_")]=proxy[key]
        return f"tuic://{_q(uid)}:{_q(password)}@{hp}?{_query(query)}#{_q(name)}"
    if kind == "anytls":
        password=str(proxy.get("password") or "")
        if not password: return None
        query.update(_tls_params(proxy))
        return f"anytls://{_q(password)}@{hp}?{_query(query)}#{_q(name)}"
    if kind in {"socks5","socks"}:
        username=str(proxy.get("username") or ""); password=str(proxy.get("password") or "")
        auth=f"{_q(username)}:{_q(password)}@" if username else ""
        return f"socks5://{auth}{hp}#{_q(name)}"
    if kind == "http":
        username=str(proxy.get("username") or ""); password=str(proxy.get("password") or "")
        auth=f"{_q(username)}:{_q(password)}@" if username else ""
        scheme="https" if proxy.get("tls") else "http"
        return f"{scheme}://{auth}{hp}#{_q(name)}"
    return None


def _singbox_outbound_to_uri(out: dict[str, Any]) -> str | None:
    if not isinstance(out,dict): return None
    typ=str(out.get("type") or "").lower()
    if typ not in {"vless","vmess","trojan","shadowsocks","ss","hysteria","hysteria2","tuic","anytls","socks","http"}: return None
    tls=out.get("tls") or {}
    if not isinstance(tls,dict): tls={"enabled":bool(tls)}
    reality=tls.get("reality") or {}
    utls=tls.get("utls") or {}
    transport=out.get("transport") or {}
    proxy={"type":typ,"server":out.get("server"),"port":out.get("server_port"),"name":out.get("tag") or typ,
           "tls":{"enabled":tls.get("enabled",typ in {"trojan","hysteria","hysteria2","tuic","anytls"}),
                  "servername":tls.get("server_name") or tls.get("serverName"),"insecure":tls.get("insecure",False),
                  "alpn":tls.get("alpn"),"utls":utls,"reality-opts":{"public-key":reality.get("public_key"),"short-id":reality.get("short_id")}},
           "client-fingerprint":utls.get("fingerprint"),"network":transport.get("type") or "tcp",
           "ws-opts":{"path":transport.get("path"),"headers":transport.get("headers") or {}},
           "grpc-opts":{"grpc-service-name":transport.get("service_name")},
           "uuid":out.get("uuid"),"password":out.get("password"),"cipher":out.get("method"),
           "alterId":out.get("alter_id",0),"flow":out.get("flow"),"username":out.get("username"),
           "congestion-controller":out.get("congestion_control"),"udp-relay-mode":out.get("udp_relay_mode"),
           "obfs":out.get("obfs"),"auth":out.get("auth"),"token":out.get("token"),
           "plugin":out.get("plugin"),"plugin_opts":out.get("plugin_opts")}
    if typ=="shadowsocks": proxy["type"]="ss"
    if typ=="hysteria2": proxy["type"]="hysteria2"
    if typ=="hysteria": proxy["type"]="hysteria"
    return clash_proxy_to_uri(proxy)


def _xray_outbound_to_uri(out: dict[str, Any]) -> str | None:
    """Convert common Xray JSON outbound objects to share links without panel-specific assumptions."""
    if not isinstance(out,dict): return None
    protocol=str(out.get("protocol") or "").lower()
    if protocol not in {"vless","vmess","trojan","shadowsocks","socks","http"}: return None
    settings=out.get("settings") or {}; stream=out.get("streamSettings") or {}
    if not isinstance(settings,dict) or not isinstance(stream,dict): return None
    name=str(out.get("tag") or protocol)
    host=""; port=0; user={}
    if protocol in {"vless","vmess"}:
        vnext=settings.get("vnext") or []
        if not vnext or not isinstance(vnext[0],dict): return None
        host=str(vnext[0].get("address") or ""); port=int(vnext[0].get("port") or 0)
        users=vnext[0].get("users") or []
        if not users or not isinstance(users[0],dict): return None
        user=users[0]
    else:
        servers=settings.get("servers") or []
        if not servers or not isinstance(servers[0],dict): return None
        server=servers[0]; host=str(server.get("address") or ""); port=int(server.get("port") or 0)
        nested_users=server.get("users") or []
        user=nested_users[0] if protocol in {"socks","http"} and nested_users and isinstance(nested_users[0],dict) else server
    if not host or not (1<=port<=65535): return None
    tls_settings=stream.get("tlsSettings") or {}; reality=stream.get("realitySettings") or {}
    security=str(stream.get("security") or "none").lower()
    network=str(stream.get("network") or "tcp").lower()
    query={"type":network}
    if security in {"tls","reality"}:
        query["security"]=security
        if security=="tls":
            if tls_settings.get("serverName"): query["sni"]=tls_settings["serverName"]
            if tls_settings.get("fingerprint"): query["fp"]=tls_settings["fingerprint"]
            if tls_settings.get("alpn"): query["alpn"]=tls_settings["alpn"]
            if tls_settings.get("allowInsecure"): query["allowInsecure"]="1"
        if security=="reality":
            if reality.get("serverName"): query["sni"]=reality["serverName"]
            if reality.get("fingerprint"): query["fp"]=reality["fingerprint"]
            if reality.get("publicKey"): query["pbk"]=reality["publicKey"]
            if reality.get("shortId"): query["sid"]=reality["shortId"]
    else: query["security"]="none"
    if network=="ws":
        ws=stream.get("wsSettings") or {}; headers=ws.get("headers") or {}
        query["path"]=ws.get("path") or "/"
        if headers.get("Host"): query["host"]=headers["Host"]
    elif network=="grpc":
        grpc=stream.get("grpcSettings") or {}
        query["serviceName"]=grpc.get("serviceName") or ""
        if grpc.get("authority"): query["authority"]=grpc["authority"]
    elif network=="http":
        opts=stream.get("httpSettings") or {}; query["path"]=opts.get("path") or "/"
        hosts=opts.get("host") or []
        if hosts: query["host"]=hosts[0] if isinstance(hosts,list) else hosts
    elif network in {"httpupgrade","xhttp"}:
        opts=stream.get("httpupgradeSettings" if network=="httpupgrade" else "xhttpSettings") or {}
        query["path"]=opts.get("path") or "/"
        if opts.get("host"): query["host"]=opts["host"]
        if network=="xhttp" and opts.get("mode"): query["mode"]=opts["mode"]
    elif network not in {"tcp","http","kcp"}:
        # A transport with no share-link mapping must not silently turn into TCP.
        return None
    hp=_hostport(host,port)
    if protocol=="vless":
        uid=str(user.get("id") or "")
        if not uid: return None
        if user.get("flow"): query["flow"]=user["flow"]
        query["encryption"]=str(user.get("encryption") or "none")
        return f"vless://{_q(uid)}@{hp}?{_query(query)}#{_q(name)}"
    if protocol=="vmess":
        payload={"v":"2","ps":name,"add":host,"port":str(port),"id":str(user.get("id") or ""),
                 "aid":str(user.get("alterId") or 0),"scy":str(user.get("security") or "auto"),"net":network,"type":"none",
                 "host":str((stream.get("wsSettings") or {}).get("headers",{}).get("Host") or ""),
                 "path":str((stream.get("wsSettings") or {}).get("path") or (stream.get("grpcSettings") or {}).get("serviceName") or "/"),
                 "tls":"tls" if security=="tls" else "","sni":str(query.get("sni") or ""),"fp":str(query.get("fp") or ""),
                 "type":str((stream.get("kcpSettings") or {}).get("header",{}).get("type") or "none"),
                 "seed":str((stream.get("kcpSettings") or {}).get("seed") or "")}
        if not payload["id"]: return None
        return "vmess://"+base64.b64encode(json.dumps(payload,separators=(",",":"),ensure_ascii=False).encode()).decode().rstrip("=")
    if protocol=="trojan":
        password=str(user.get("password") or "")
        if not password: return None
        query["security"]=security if security in {"tls","reality"} else "tls"
        return f"trojan://{_q(password)}@{hp}?{_query(query)}#{_q(name)}"
    if protocol=="shadowsocks":
        method=str(user.get("method") or ""); password=str(user.get("password") or "")
        if not method or not password: return None
        token=base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return f"ss://{token}@{hp}#{_q(name)}"
    if protocol in {"socks","http"}:
        username=str(user.get("user") or user.get("username") or ""); password=str(user.get("pass") or user.get("password") or "")
        auth=f"{_q(username)}:{_q(password)}@" if username else ""
        scheme="socks5" if protocol=="socks" else "https" if security=="tls" else "http"
        return f"{scheme}://{auth}{hp}#{_q(name)}"
    return None


def _sip008_to_uri(item: dict[str, Any]) -> str | None:
    server=str(item.get("server") or item.get("address") or "")
    port=item.get("server_port") or item.get("server-port") or item.get("port")
    method=str(item.get("method") or item.get("cipher") or "")
    password=str(item.get("password") or "")
    name=str(item.get("remarks") or item.get("name") or item.get("tag") or f"ss-{server}:{port}")
    if not server or not method or not password: return None
    try: p=int(port)
    except (TypeError,ValueError): return None
    if not 1<=p<=65535: return None
    return clash_proxy_to_uri({"type":"ss","server":server,"port":p,"cipher":method,"password":password,
                               "name":name,"plugin":item.get("plugin"),"plugin-opts":item.get("plugin_opts") or item.get("plugin-opts")})


def extract_structured_nodes(text: str) -> tuple[list[str], list[dict[str, Any]]]:
    """Parse supported structured formats. Returns (share-links, discovered provider URLs)."""
    try:
        import yaml
        obj=yaml.safe_load(text)
    except Exception:
        obj=None
    links: list[str]=[]; discovered=[]
    def walk(value):
        if isinstance(value,dict):
            if isinstance(value.get("proxies"),list):
                for item in value["proxies"]:
                    uri=clash_proxy_to_uri(item)
                    if uri: links.append(uri)
            providers=value.get("proxy-providers") or value.get("proxy_providers")
            if isinstance(providers,dict):
                for name,spec in providers.items():
                    if isinstance(spec,dict) and str(spec.get("type","http")).lower()=="http" and spec.get("url"):
                        discovered.append({"url":str(spec["url"]),"name":f"provider:{name}","headers":spec.get("header") or spec.get("headers") or {}})
            outs=value.get("outbounds")
            if isinstance(outs,list):
                for out in outs:
                    uri=_singbox_outbound_to_uri(out) or _xray_outbound_to_uri(out)
                    if uri: links.append(uri)
            # SIP008/ShadowsocksD exports commonly store an array of server records.
            sip_uri=None if ("type" in value or "protocol" in value or "outbounds" in value) else _sip008_to_uri(value)
            if sip_uri: links.append(sip_uri)
            for v in value.values():
                if isinstance(v,(dict,list)): walk(v)
        elif isinstance(value,list):
            for v in value: walk(v)
    if obj is not None: walk(obj)
    return links,discovered
