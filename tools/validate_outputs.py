from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from aeryx_json_parser.xray_validation import safe_xray_diagnostic as _safe_xray_diagnostic

SPECIAL_PROTOCOLS = {"freedom", "blackhole", "dns", "loopback"}
SUPPORTED_PROXY_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria"}


def validate_structure(subscription_path: Path, metadata_path: Path, report_path: Path) -> dict[str, Any]:
    """Validate the published Happ Xray JSON array, including country balancing references."""
    profiles = json.loads(subscription_path.read_text(encoding="utf-8"))
    metadata_doc = json.loads(metadata_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("AeryxVPN.json must be a non-empty JSON array of Xray profiles")
    meta = metadata_doc.get("metadata")
    if not isinstance(meta, dict):
        raise ValueError("metadata sidecar is missing its metadata object")
    if meta.get("format") != "happ-xray-json-array":
        raise ValueError("metadata format must be happ-xray-json-array")
    if int(meta.get("profile_count", -1)) != len(profiles):
        raise ValueError("metadata profile_count does not match JSON array length")

    remarks = [str(profile.get("remarks") or "") for profile in profiles if isinstance(profile, dict)]
    if len(remarks) != len(profiles) or any(not name for name in remarks):
        raise ValueError("every array item must be an object with a non-empty remarks field")
    if len(remarks) != len(set(remarks)):
        raise ValueError("profile remarks must be unique")

    country_rows = meta.get("countries")
    if not isinstance(country_rows, list) or not country_rows:
        raise ValueError("metadata must contain country rows")
    if int(meta.get("country_count", -1)) != len(country_rows):
        raise ValueError("metadata country_count does not match country rows")
    row_by_name = {str(row.get("profile_name")): row for row in country_rows if isinstance(row, dict)}
    if len(row_by_name) != len(country_rows):
        raise ValueError("country profile names in metadata are missing or duplicated")
    country_profile_names = set(row_by_name)
    unknown_profiles = set(remarks) - country_profile_names
    auto_names = [name for name in remarks if name not in country_profile_names]
    expected_auto = {str(meta.get("auto_profile_name") or "🇪🇺 Автовыбор")} if meta.get("auto_profile_included") else set()
    if unknown_profiles != expected_auto or len(auto_names) > 1:
        raise ValueError("JSON array does not match the configured country profiles and global Auto profile")

    country_total = 0
    core_profiles: list[dict[str, Any]] = []
    for profile in profiles:
        if not isinstance(profile, dict):
            raise ValueError("each JSON array item must be an object")
        name = str(profile.get("remarks") or "(unnamed)")
        # The supplied working examples use meta: null; the visible title is remarks.
        if "meta" not in profile:
            raise ValueError(f"{name}: Happ profile must retain the meta field from the reference template")
        required_template_keys = {"api", "burstObservatory", "dns", "inbounds", "log", "meta", "metrics", "outbounds", "policy", "remarks", "routing", "stats"}
        if not required_template_keys.issubset(profile):
            missing = sorted(required_template_keys - set(profile))
            raise ValueError(f"{name}: shared Happ template fields are missing: {', '.join(missing)}")
        inbounds = profile.get("inbounds")
        socks = [item for item in inbounds or [] if item.get("tag") == "socks"]
        if len(socks) != 1 or socks[0].get("protocol") != "socks" or socks[0].get("listen") != "127.0.0.1":
            raise ValueError(f"{name}: profile must have one loopback SOCKS inbound tagged socks")

        outbounds = profile.get("outbounds")
        if not isinstance(outbounds, list) or not outbounds:
            raise ValueError(f"{name}: outbounds array is missing")
        tags = [str(item.get("tag") or "") for item in outbounds]
        if any(not tag for tag in tags) or len(tags) != len(set(tags)):
            raise ValueError(f"{name}: outbound tags must be non-empty and unique")
        by_tag = {item["tag"]: item for item in outbounds}
        if tags[0] != "proxy-1" or by_tag["proxy-1"].get("protocol") not in SUPPORTED_PROXY_PROTOCOLS:
            raise ValueError(f"{name}: the first outbound must be a supported server tagged proxy-1")
        proxy_tags = [tag for tag in tags if tag.startswith("proxy-")]
        if proxy_tags != [f"proxy-{index}" for index in range(1, len(proxy_tags) + 1)]:
            raise ValueError(f"{name}: proxy tags must be sequential proxy-1, proxy-2, ...")
        protocols = [str(item.get("protocol") or "") for item in outbounds]
        concrete = [item for item in outbounds if item.get("protocol") not in SPECIAL_PROTOCOLS]
        if not concrete or any(item.get("protocol") not in SUPPORTED_PROXY_PROTOCOLS for item in concrete):
            raise ValueError(f"{name}: unsupported or empty proxy outbound found")
        if "direct" not in by_tag or by_tag["direct"].get("protocol") != "freedom":
            raise ValueError(f"{name}: direct freedom outbound is missing")
        if "block" not in by_tag or by_tag["block"].get("protocol") != "blackhole":
            raise ValueError(f"{name}: block blackhole outbound is missing")

        observatory = profile.get("burstObservatory") or {}
        selector = observatory.get("subjectSelector") or []
        if selector != ["proxy"]:
            raise ValueError(f"{name}: burstObservatory must observe the proxy tag prefix")
        ping_config = observatory.get("pingConfig") or {}
        for key in ("connectivity", "destination", "httpMethod", "interval", "sampling", "timeout"):
            if ping_config.get(key) in (None, ""):
                raise ValueError(f"{name}: burstObservatory.pingConfig.{key} is missing")
        routing = profile.get("routing") or {}
        balancers = routing.get("balancers") or []
        if len(balancers) != 1:
            raise ValueError(f"{name}: exactly one leastPing balancer is required")
        balancer = balancers[0]
        if balancer.get("strategy", {}).get("type") != "leastPing":
            raise ValueError(f"{name}: balancer must use leastPing")
        if balancer.get("tag") != "balancer":
            raise ValueError(f"{name}: balancer tag must match the reference template")
        if balancer.get("selector") != ["proxy"]:
            raise ValueError(f"{name}: balancer selector must match proxy-N outbound tags")
        if "fallbackTag" in balancer:
            raise ValueError(f"{name}: reference template does not use fallbackTag")
        rules = routing.get("rules") or []
        if not any(rule.get("balancerTag") == balancer.get("tag") and rule.get("network") == "tcp,udp" for rule in rules):
            raise ValueError(f"{name}: catch-all TCP/UDP traffic is not routed through the balancer")

        node_count = len(concrete)
        if name in country_profile_names:
            country_total += node_count
            if int(row_by_name[name].get("node_count", -1)) != node_count:
                raise ValueError(f"{name}: country node_count in metadata does not match profile")
        # Happ consumes remarks/meta; Xray-core itself validates only the actual config.
        xray_cfg = copy.deepcopy(profile)
        xray_cfg.pop("remarks", None)
        xray_cfg.pop("meta", None)
        custom_geo_references = _find_unavailable_custom_geodata(xray_cfg)
        if custom_geo_references:
            raise ValueError(
                f"{name}: profile references custom geo data that is not bundled with the core: "
                + ", ".join(custom_geo_references)
            )
        # Validate the actual published profile. Only Happ presentation fields
        # (`remarks` and `meta`) are removed; no routing or DNS matcher is rewritten.
        core_profiles.append(xray_cfg)

    if country_total != int(meta.get("validated_config_count", -1)):
        raise ValueError("metadata validated_config_count does not match country profiles")
    if report.get("published_config_count") != country_total:
        raise ValueError("build report published_config_count does not match country profiles")
    if report.get("profile_count") != len(profiles):
        raise ValueError("build report profile_count does not match JSON array length")
    if bool(meta.get("auto_profile_included")) != bool(auto_names):
        raise ValueError("metadata auto_profile_included does not match JSON array")
    if auto_names:
        auto_profile = next(profile for profile in profiles if profile.get("remarks") == auto_names[0])
        auto_node_count = sum(1 for item in auto_profile["outbounds"] if item.get("protocol") not in SPECIAL_PROTOCOLS)
        if auto_node_count != country_total:
            raise ValueError("global Auto profile does not contain all country nodes")
    actual_hash = hashlib.sha256(subscription_path.read_bytes()).hexdigest()
    if actual_hash != meta.get("profile_sha256"):
        raise ValueError("metadata profile SHA-256 does not match subscription")

    return {
        "profiles": core_profiles,
        "profile_names": remarks,
        "countries": len(country_rows),
        "validated_nodes": country_total,
        "auto_profile_count": len(auto_names),
        "xray_validation_note": (
            "The published profile is validated as-is by official Xray-core, except for "
            "Happ presentation-only fields remarks/meta. Custom WH-DIRECT/STD-DIRECT geo labels are forbidden."
        ),
    }


_UNAVAILABLE_CUSTOM_GEO_TAGS = {"WH-DIRECT", "STD-DIRECT"}
_CUSTOM_GEO_SELECTOR = re.compile(r"^(?:geosite|geoip):([^:]+)$", flags=re.IGNORECASE)


def _find_unavailable_custom_geodata(value: Any, path: str = "$", found: list[str] | None = None) -> list[str]:
    """Find references to custom geo categories that aren't shipped with this project/core."""
    if found is None:
        found = []
    if isinstance(value, str):
        match = _CUSTOM_GEO_SELECTOR.fullmatch(value)
        if match and match.group(1).upper() in _UNAVAILABLE_CUSTOM_GEO_TAGS:
            found.append(f"{path}={value}")
    elif isinstance(value, dict):
        for key, child in value.items():
            _find_unavailable_custom_geodata(child, f"{path}.{key}", found)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _find_unavailable_custom_geodata(child, f"{path}[{index}]", found)
    return found


def validate_with_xray(binary: str, profiles: list[dict[str, Any]], profile_names: list[str] | None = None) -> list[dict[str, Any]]:
    """Run each published Xray-compatible profile through Xray's native checker.

    The caller removes only Happ presentation fields (`remarks` and `meta`).
    Routing and DNS remain unchanged so validation catches client startup errors.
    """
    errors: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="aeryx-xray-check-") as tempdir:
        root = Path(tempdir)
        for index, profile in enumerate(profiles, start=1):
            profile_name = profile_names[index - 1] if profile_names and index <= len(profile_names) else f"profile-{index:03d}"
            path = root / f"profile-{index:03d}.json"
            path.write_text(json.dumps(profile, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            try:
                proc = subprocess.run(
                    [binary, "run", "-test", "-config", str(path)],
                    capture_output=True, text=True, timeout=25,
                )
                if proc.returncode != 0:
                    error = {"profile_index": index, "profile": profile_name, "error": "xray_core_rejected_config", "exit_code": proc.returncode}
                    diagnostic = _safe_xray_diagnostic(proc, path)
                    if diagnostic:
                        error["diagnostic"] = diagnostic
                    errors.append(error)
            except subprocess.TimeoutExpired:
                errors.append({"profile_index": index, "profile": profile_name, "error": "xray_validation_timeout"})
            except FileNotFoundError:
                return [{"error": "xray_binary_not_found"}]
            except Exception as exc:
                errors.append({"profile_index": index, "profile": profile_name, "error": type(exc).__name__})
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate Happ-compatible Xray JSON-array subscription")
    ap.add_argument("--root", type=Path, default=Path("output/publish"))
    ap.add_argument("--xray", default="tools/xray")
    args = ap.parse_args()
    root = args.root
    try:
        validated = validate_structure(root / "AeryxVPN.json", root / "AeryxVPN.metadata.json", root / "build-report.json")
    except Exception as exc:
        print(json.dumps({"status": "invalid", "error": type(exc).__name__, "message": str(exc)}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2
    core_profiles = validated.pop("profiles")
    core_errors = validate_with_xray(args.xray, core_profiles, validated.get("profile_names"))
    validated.pop("profile_names", None)
    result = {"status": "valid" if not core_errors else "invalid", **validated, "xray_errors": core_errors}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if core_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
