from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def run(binary: str, args: list[str], timeout: int = 30) -> tuple[bool, str]:
    try:
        result = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
        message = (result.stdout + "\n" + result.stderr).strip()[-1500:]
        return result.returncode == 0, message
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate the single AeryxVPN sing-box JSON subscription")
    ap.add_argument("--root", type=Path, default=Path("output/publish"))
    ap.add_argument("--sing-box", default="tools/sing-box")
    args = ap.parse_args()
    root = args.root
    subscription_path = root / "AeryxVPN.json"
    metadata_path = root / "AeryxVPN.metadata.json"
    report_path = root / "build-report.json"
    errors: list[str] = []

    try:
        cfg = json.loads(subscription_path.read_text(encoding="utf-8"))
        metadata_doc = json.loads(metadata_path.read_text(encoding="utf-8"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        meta = metadata_doc["metadata"]
        outbounds = cfg["outbounds"]
        by_tag = {item["tag"]: item for item in outbounds}
        if len(by_tag) != len(outbounds):
            raise ValueError("duplicate outbound tags")
        final_tag = cfg["route"]["final"]
        selector = by_tag[final_tag]
        if selector.get("type") != "selector":
            raise ValueError("route.final must point to the top-level country selector")
        country_group_tags = selector.get("outbounds", [])
        if not country_group_tags or any(tag not in by_tag for tag in country_group_tags):
            raise ValueError("country selector references missing groups")
        if selector.get("default") not in country_group_tags:
            raise ValueError("country selector default is not one of the country groups")
        group_nodes = 0
        for country_tag in country_group_tags:
            group = by_tag[country_tag]
            if group.get("type") != "urltest":
                raise ValueError(f"country group {country_tag!r} is not urltest")
            node_tags = group.get("outbounds", [])
            if not node_tags or any(tag not in by_tag for tag in node_tags):
                raise ValueError(f"country group {country_tag!r} references missing node tags")
            if any(by_tag[tag].get("type") in {"urltest", "selector", "direct", "block"} for tag in node_tags):
                raise ValueError(f"country group {country_tag!r} contains a non-node outbound")
            group_nodes += len(node_tags)
        concrete_nodes = sum(1 for item in outbounds if item.get("type") not in {"urltest", "selector", "direct", "block"})
        if group_nodes != concrete_nodes:
            raise ValueError(f"country group references ({group_nodes}) != concrete node outbounds ({concrete_nodes})")
        if group_nodes <= 0 or group_nodes != int(meta["validated_config_count"]):
            raise ValueError("metadata config count does not match actual profile")
        if len(country_group_tags) != int(meta["country_count"]):
            raise ValueError("metadata country count does not match selector country groups")
        actual_hash = hashlib.sha256(subscription_path.read_bytes()).hexdigest()
        if actual_hash != meta.get("profile_sha256"):
            raise ValueError("metadata profile SHA-256 does not match subscription")
        if report.get("published_config_count") != concrete_nodes:
            raise ValueError("build report config count does not match subscription")
        if not cfg.get("inbounds") or not isinstance(cfg.get("route"), dict):
            raise ValueError("profile missing inbounds or route")
    except Exception as exc:
        print(f"ERROR: unified subscription is invalid: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    ok, msg = run(args.sing_box, ["check", "-c", str(subscription_path)])
    if not ok:
        errors.append(f"sing-box native config check failed: {msg}")

    print(json.dumps({
        "subscription": subscription_path.name,
        "countries": len(country_group_tags),
        "validated_configs": concrete_nodes,
        "selector": final_tag,
        "errors": errors,
    }, ensure_ascii=False, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
