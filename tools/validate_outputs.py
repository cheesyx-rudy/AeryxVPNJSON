from __future__ import annotations
import argparse, json, subprocess, sys
from pathlib import Path


def run(binary: str, args: list[str], timeout: int = 20) -> tuple[bool, str]:
    try:
        result = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
        message = (result.stdout + "\n" + result.stderr).strip()[-1000:]
        return result.returncode == 0, message
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate generated sing-box and Xray country JSON profiles")
    ap.add_argument("--root", type=Path, default=Path("output/publish"))
    ap.add_argument("--sing-box", default="tools/sing-box")
    ap.add_argument("--xray", default="tools/xray")
    args = ap.parse_args()
    root = args.root
    index_path = root / "index.json"
    if not index_path.is_file():
        print(f"ERROR: missing {index_path}", file=sys.stderr)
        return 2
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
        metadata = index["metadata"]
        countries = index["countries"]
        assert isinstance(countries, list) and countries
        assert int(metadata["validated_sing_box_config_count"]) > 0
    except Exception as exc:
        print(f"ERROR: invalid index.json: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    errors = []
    sing_count = 0
    for row in countries:
        code = str(row.get("code", ""))
        path = root / "countries" / f"{code}.json"
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
            outbounds = cfg["outbounds"]
            route_final = cfg["route"]["final"]
            by_tag = {x["tag"]: x for x in outbounds}
            balancer = by_tag[route_final]
            assert balancer.get("type") == "urltest"
            assert balancer.get("outbounds") and all(t in by_tag for t in balancer["outbounds"])
            assert all(by_tag[t].get("type") not in {"urltest", "direct", "block"} for t in balancer["outbounds"])
            assert cfg["inbounds"]
            sing_count += len(balancer["outbounds"])
        except Exception as exc:
            errors.append(f"sing-box {code}: {type(exc).__name__}: {exc}")
            continue
        ok, msg = run(args.sing_box, ["check", "-c", str(path)])
        if not ok:
            errors.append(f"sing-box {code} core validation failed: {msg}")

        xray_path = root / "xray" / f"{code}.json"
        if xray_path.exists():
            try:
                xcfg = json.loads(xray_path.read_text(encoding="utf-8"))
                balancers = xcfg["routing"]["balancers"]
                assert balancers
                bal = balancers[0]
                assert bal["strategy"]["type"] == "leastPing"
                assert xcfg["observatory"]["subjectSelector"]
                selector = bal["selector"]
                tags = [out["tag"] for out in xcfg["outbounds"]]
                assert selector and any(t.startswith(selector[0]) for t in tags)
            except Exception as exc:
                errors.append(f"Xray {code}: {type(exc).__name__}: {exc}")
                continue
            ok, msg = run(args.xray, ["run", "-test", "-config", str(xray_path)])
            if not ok:
                errors.append(f"Xray {code} core validation failed: {msg}")

    print(json.dumps({"countries": len(countries), "sing_box_nodes": sing_count, "errors": errors}, ensure_ascii=False, indent=2))
    return 1 if errors else 0

if __name__ == "__main__":
    raise SystemExit(main())
