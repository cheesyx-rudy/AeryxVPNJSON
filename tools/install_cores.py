from __future__ import annotations
import argparse, json, os, platform, re, shutil, stat, sys, tarfile, tempfile, time, urllib.error, urllib.request, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
API_HEADERS={"Accept":"application/vnd.github+json","User-Agent":"AeryxParser-core-installer/2.0","X-GitHub-Api-Version":"2022-11-28"}


def get_json(url: str):
    req=urllib.request.Request(url,headers=API_HEADERS)
    with urllib.request.urlopen(req,timeout=20) as r: return json.loads(r.read().decode("utf-8"))


def download(url: str, dest: Path, max_bytes: int=250*1024*1024, attempts: int=4):
    """Download a release asset atomically, retrying transient GitHub/CDN failures."""
    partial=dest.with_name(dest.name+".part")
    headers={"User-Agent":"AeryxParser-core-installer/2.1","Accept":"application/octet-stream"}
    for attempt in range(1, attempts+1):
        req=urllib.request.Request(url,headers=headers)
        try:
            total=0
            with urllib.request.urlopen(req,timeout=45) as r, partial.open("wb") as f:
                while True:
                    chunk=r.read(1024*1024)
                    if not chunk: break
                    total+=len(chunk)
                    if total>max_bytes: raise ValueError(f"download exceeds safety limit ({max_bytes} bytes)")
                    f.write(chunk)
            if total == 0:
                raise ValueError("downloaded release asset is empty")
            os.replace(partial,dest)
            return
        except urllib.error.HTTPError as exc:
            try: partial.unlink()
            except OSError: pass
            retryable=exc.code in {403,408,425,429,500,502,503,504}
            if not retryable or attempt>=attempts:
                raise
            retry_after=exc.headers.get("Retry-After") if exc.headers else None
            try: delay=max(1,min(20,int(retry_after))) if retry_after else min(2**(attempt-1),8)
            except (TypeError,ValueError): delay=min(2**(attempt-1),8)
            print(f"[WARN] HTTP {exc.code} while downloading release asset; retry {attempt}/{attempts} in {delay}s",file=sys.stderr)
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError) as exc:
            try: partial.unlink()
            except OSError: pass
            if attempt>=attempts:
                raise
            delay=min(2**(attempt-1),8)
            print(f"[WARN] Network error while downloading release asset ({type(exc).__name__}); retry {attempt}/{attempts} in {delay}s",file=sys.stderr)
            time.sleep(delay)


def detect_target():
    sysname=platform.system().lower()
    machine=platform.machine().lower()
    osname={"windows":"windows","linux":"linux","darwin":"darwin"}.get(sysname)
    arch="arm64" if machine in {"arm64","aarch64"} else "amd64" if machine in {"x86_64","amd64","x64"} else "386" if machine in {"i386","i686","x86"} else ""
    if not osname or not arch: raise SystemExit(f"Unsupported platform/architecture: {sysname}/{machine}")
    return osname,arch


def asset_by_patterns(assets, patterns):
    names=[(a.get("name",""),a.get("browser_download_url","")) for a in assets]
    for pattern in patterns:
        for name,url in names:
            if re.search(pattern,name,re.I): return name,url
    return None,None


def install_archive(owner_repo: str, tool: str, osname: str, arch: str, tools_dir: Path):
    release=get_json(f"https://api.github.com/repos/{owner_repo}/releases/latest")
    tag=release.get("tag_name","unknown"); assets=release.get("assets",[])
    if tool=="xray":
        if osname=="windows": patterns=[r"^Xray-windows-64\.zip$" if arch=="amd64" else rf"^Xray-windows-{arch}\.zip$"]
        elif osname=="linux": patterns=[r"^Xray-linux-64\.zip$" if arch=="amd64" else rf"^Xray-linux-{arch}\.zip$"]
        elif osname=="darwin": patterns=[r"^Xray-macos-arm64-v8a\.zip$" if arch=="arm64" else r"^Xray-macos-64\.zip$"]
        else: patterns=[]
    else:
        plat_arch={"windows":{"amd64":"windows-amd64","arm64":"windows-arm64","386":"windows-386"},
                   "linux":{"amd64":"linux-amd64","arm64":"linux-arm64","386":"linux-386"},
                   "darwin":{"amd64":"darwin-amd64","arm64":"darwin-arm64"}}
        suffix=plat_arch.get(osname,{}).get(arch)
        patterns=[rf"^sing-box-[0-9][^-]*-{re.escape(suffix)}\.zip$",rf"^sing-box-[0-9][^-]*-{re.escape(suffix)}\.tar\.gz$"] if suffix else []
    name,url=asset_by_patterns(assets,patterns)
    if not url:
        # API naming differs occasionally. Use a cautious platform/architecture fallback.
        needle=f"{osname}-{arch}".lower()
        matches=[(a.get("name",""),a.get("browser_download_url","")) for a in assets if needle in a.get("name","").lower() and a.get("name","").lower().endswith((".zip",".tar.gz"))]
        if tool=="xray": matches=[x for x in matches if x[0].lower().startswith("xray-")]
        if matches: name,url=matches[0]
    if not url: raise RuntimeError(f"Could not find {tool} asset for {osname}/{arch} in {owner_repo} {tag}; available names were not matched")
    tools_dir.mkdir(parents=True,exist_ok=True)
    suffix=".zip" if name.lower().endswith(".zip") else ".tar.gz"
    archive=tools_dir/f"{tool}-download{suffix}"
    print(f"Downloading {tool}: {owner_repo} {tag} / {name}")
    download(url,archive)
    staging=tools_dir/f".{tool}-extract"; shutil.rmtree(staging,ignore_errors=True); staging.mkdir()
    try:
        if suffix==".zip":
            with zipfile.ZipFile(archive) as z:
                for item in z.infolist():
                    target=(staging/item.filename).resolve()
                    if staging.resolve() not in target.parents and target!=staging.resolve(): raise ValueError("unsafe archive path")
                z.extractall(staging)
        else:
            with tarfile.open(archive,"r:gz") as t:
                for item in t.getmembers():
                    target=(staging/item.name).resolve()
                    if staging.resolve() not in target.parents and target!=staging.resolve(): raise ValueError("unsafe archive path")
                t.extractall(staging,filter="data")
        names={"xray" if tool=="xray" else "sing-box", "xray.exe" if tool=="xray" else "sing-box.exe"}
        binary=next((p for p in staging.rglob("*") if p.is_file() and p.name in names),None)
        if binary is None: raise RuntimeError(f"{tool} executable not found in {name}")
        dest=tools_dir/("xray.exe" if osname=="windows" and tool=="xray" else "sing-box.exe" if osname=="windows" else tool)
        shutil.copy2(binary,dest)
        if osname!="windows": dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return {"repository":owner_repo,"version":tag,"asset":name,"binary":dest.name,"downloaded_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())}
    finally:
        shutil.rmtree(staging,ignore_errors=True)
        try: archive.unlink()
        except OSError: pass


def main():
    ap=argparse.ArgumentParser(description="Install latest stable Xray-core and sing-box binaries from their official GitHub releases")
    ap.add_argument("--platform",choices=("windows","linux","darwin"),default=None)
    ap.add_argument("--arch",choices=("amd64","arm64","386"),default=None)
    ap.add_argument("--tools-dir",type=Path,default=ROOT/"tools")
    args=ap.parse_args(); auto_os,auto_arch=detect_target(); osname=args.platform or auto_os; arch=args.arch or auto_arch
    if (osname,arch)==("darwin","386"): raise SystemExit("Unsupported target: macOS 32-bit is not supported")
    metadata={}; failures=[]
    # Latest non-prerelease release endpoints; no arbitrary forks or mirrors.
    targets=(("xray","XTLS/Xray-core"),("sing-box","SagerNet/sing-box"))
    for key,repo in targets:
        expected=args.tools_dir/("xray.exe" if osname=="windows" and key=="xray" else "sing-box.exe" if osname=="windows" else key)
        try:
            metadata[key]=install_archive(repo,key,osname,arch,args.tools_dir)
        except Exception as exc:
            if isinstance(exc,urllib.error.HTTPError):
                detail=f"HTTP {exc.code} {exc.reason}"
            elif isinstance(exc,urllib.error.URLError):
                detail=f"network error: {exc.reason}"
            else:
                detail=f"{type(exc).__name__}: {exc}"
            failures.append(f"{key}: {detail}")
            # An already installed official binary can still be used when updating it
            # fails due to a transient network/API error.
            if expected.is_file():
                metadata[key]={"binary":expected.name,"version":"existing_not_updated","warning":detail}
            print(f"[WARN] Could not update {key} from its official release page: {detail}",file=sys.stderr)
    args.tools_dir.mkdir(parents=True,exist_ok=True)
    (args.tools_dir/"core-versions.json").write_text(json.dumps(metadata,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(metadata,ensure_ascii=False,indent=2))
    required_binaries={
        "xray":args.tools_dir/("xray.exe" if osname=="windows" else "xray"),
        "sing-box":args.tools_dir/("sing-box.exe" if osname=="windows" else "sing-box"),
    }
    missing=[name for name,path in required_binaries.items() if not path.is_file()]
    if missing:
        details="; ".join(failures) if failures else "no additional download diagnostics"
        raise SystemExit(
            "Required official core binary/binaries missing: "+", ".join(missing)+
            ". Stopping before parsing; both Xray and sing-box are required by the current pipeline. "+
            details
        )
    if failures: print("[WARN] Some cores were not updated: "+", ".join(failures),file=sys.stderr)

if __name__=="__main__": main()
