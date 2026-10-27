"""Build one complete sing-box JSON subscription with country-level auto balancers.

The importable subscription is a single native sing-box configuration, AeryxVPN.json.
Every country is represented by a native urltest outbound, and one top-level selector
lets the user choose a country while each country's group selects its best node.
Subscription metadata is emitted as a sidecar because sing-box rejects arbitrary
non-standard metadata fields in a native client configuration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from .checks import build_singbox_outbound
from .geolocation import Country, country_from_label, flag_for_code

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "output" / "engine" / "parsed_proxies.json"
DEFAULT_CONFIG = ROOT / "config" / "settings.yaml"
DEFAULT_OUTPUT = ROOT / "output" / "publish"


def _load_config(path: Path) -> dict[str, Any]:
    obj = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(obj, dict):
        raise ValueError("settings.yaml must contain a JSON/YAML object")
    return obj


def _get_country(node: dict[str, Any]) -> Country | None:
    """Use the already-resolved node label as fallback country evidence."""
    candidates = [str(node.get("name") or "")]
    uri = str(node.get("uri") or "")
    try:
        fragment = urlsplit(uri).fragment
        if fragment:
            candidates.append(unquote(fragment))
    except Exception:
        pass
    for label in candidates:
        country = country_from_label(label, method="parser_label")
        if country:
            return country
    return None


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _country_sort(code: str) -> tuple[bool, str]:
    return (code != "EU", code)


def _tag_for_node(country: Country, index: int) -> str:
    return f"{flag_for_code(country.code)} {country.name} · AeryxVPN {index:03d}"


def _tag_for_country(country: Country) -> str:
    return f"{flag_for_code(country.code)} {country.name} · Автовыбор"


def _build_singbox_profile(
    grouped: dict[str, list[dict[str, Any]]],
    countries: dict[str, Country],
    settings: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Create a single sing-box profile with all nodes and one urltest per country."""
    cfg = settings.get("sing_box", {}) or {}
    probe_url = str(cfg.get("probe_url", "https://www.gstatic.com/generate_204"))
    interval = str(cfg.get("interval", "3m"))
    tolerance = max(0, int(cfg.get("tolerance_ms", 80)))

    all_outbounds: list[dict[str, Any]] = []
    country_groups: dict[str, dict[str, Any]] = {}
    country_counts: dict[str, dict[str, Any]] = {}

    # Add concrete proxy outbounds first. All countries live in this single array.
    ordered_codes = sorted(grouped, key=lambda code: (-len(grouped[code]), _country_sort(code)))
    for code in ordered_codes:
        country = countries[code]
        country_records = grouped[code]
        node_tags: list[str] = []
        seen_uris: set[str] = set()
        accepted_for_country = 0
        for record in country_records:
            uri = str(record["uri"])
            if uri in seen_uris:
                continue
            seen_uris.add(uri)
            accepted_for_country += 1
            tag = _tag_for_node(country, accepted_for_country)
            outbound = dict(record["singbox"])
            outbound["tag"] = tag
            all_outbounds.append(outbound)
            node_tags.append(tag)
        if not node_tags:
            continue

        country_tag = _tag_for_country(country)
        country_groups[code] = {
            "tag": country_tag,
            "outbounds": node_tags,
            "country": country,
            "node_count": len(node_tags),
        }
        country_counts[code] = {
            "name": country.name,
            "flag": flag_for_code(code),
            "node_count": len(node_tags),
            "balancer_tag": country_tag,
        }

    if not country_groups:
        raise ValueError("Safety stop: no country has a sing-box-compatible node")

    # Each country has its own native health-tested group.
    country_auto_tags: list[str] = []
    for code in ordered_codes:
        group = country_groups.get(code)
        if not group:
            continue
        all_outbounds.append({
            "type": "urltest",
            "tag": group["tag"],
            "outbounds": group["outbounds"],
            "url": probe_url,
            "interval": interval,
            "tolerance": tolerance,
            "idle_timeout": str(cfg.get("idle_timeout", "30m")),
            "interrupt_exist_connections": bool(cfg.get("interrupt_exist_connections", False)),
        })
        country_auto_tags.append(group["tag"])

    # Choose the largest country by default; user can switch the parent selector to any country.
    default_code = max(
        (code for code in country_groups),
        key=lambda code: (country_groups[code]["node_count"], code),
    )
    parent_selector_tag = str(cfg.get("country_selector_tag", "🌍 Выбор страны · AeryxVPN"))
    all_outbounds.append({
        "type": "selector",
        "tag": parent_selector_tag,
        "outbounds": country_auto_tags,
        "default": country_groups[default_code]["tag"],
        "interrupt_exist_connections": bool(cfg.get("interrupt_exist_connections", False)),
    })
    all_outbounds.append({"type": "direct", "tag": "direct"})

    profile = {
        "log": {"level": "warn"},
        "dns": {
            "servers": [{"type": "local", "tag": "local-dns"}],
            "final": "local-dns",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [
            {
                "type": "socks", "tag": "socks-in", "listen": "127.0.0.1",
                "listen_port": int(cfg.get("socks_listen_port", 2080)),
            },
            {
                "type": "http", "tag": "http-in", "listen": "127.0.0.1",
                "listen_port": int(cfg.get("http_listen_port", 2081)),
            },
        ],
        "outbounds": all_outbounds,
        "route": {
            "auto_detect_interface": True,
            "rules": [
                {"action": "sniff"},
                {"protocol": ["dns"], "action": "hijack-dns"},
            ],
            "final": parent_selector_tag,
        },
        # sing-box selectors are controlled through Clash API. Keep it loopback-only.
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{int(cfg.get('clash_api_port', 9090))}",
                "secret": "",
                "default_mode": "rule",
            }
        },
    }
    return profile, country_counts


def _build_country_outputs_in_place(
    input_path: Path = DEFAULT_INPUT,
    output_dir: Path = DEFAULT_OUTPUT,
    config_path: Path = DEFAULT_CONFIG,
    repository: str = "",
    branch: str = "main",
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build one complete importable JSON plus non-importable metadata/report sidecars."""
    cfg = _load_config(config_path)
    jcfg = cfg.get("json_subscription", {}) or {}
    outcfg = jcfg.get("output", {}) or {}
    if not bool((jcfg.get("sing_box", {}) or {}).get("enabled", True)):
        raise ValueError("sing-box JSON output must stay enabled; AeryxVPN.json is the single subscription")

    raw = json.loads(input_path.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, list):
        raise ValueError("parsed_proxies.json must contain a list")

    resolved: dict[str, Country] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rejected_reasons: Counter[str] = Counter()
    tunnel_validated_input_records = 0
    conversion_failures = 0

    for obj in raw:
        if not isinstance(obj, dict):
            rejected_reasons["invalid_record"] += 1
            continue
        status = str(obj.get("check_status") or "")
        if not status.startswith("proxy_ok"):
            rejected_reasons["not_tunnel_validated"] += 1
            continue
        tunnel_validated_input_records += 1
        uri = str(obj.get("uri") or "").strip()
        if not uri:
            rejected_reasons["missing_uri"] += 1
            continue
        country = _get_country(obj)
        if country is None:
            rejected_reasons["country_unknown"] += 1
            continue
        code = country.code.upper()
        resolved[code] = country
        try:
            outbound = build_singbox_outbound(uri)
            if not isinstance(outbound, dict) or not outbound.get("type"):
                raise ValueError("adapter_returned_no_outbound")
        except Exception as exc:
            conversion_failures += 1
            rejected_reasons["singbox_conversion:" + type(exc).__name__] += 1
            continue
        grouped[code].append({"uri": uri, "singbox": outbound})

    minimum_total = max(1, int(jcfg.get("minimum_total_configs", 5)))
    minimum_country = max(1, int(jcfg.get("minimum_country_configs", 1)))
    for code in list(grouped):
        unique: list[dict[str, Any]] = []
        seen: set[str] = set()
        for rec in grouped[code]:
            if rec["uri"] in seen:
                rejected_reasons["duplicate_uri"] += 1
                continue
            seen.add(rec["uri"])
            unique.append(rec)
        grouped[code] = unique
        if len(unique) < minimum_country:
            rejected_reasons["country_below_minimum"] += len(unique)
            del grouped[code]
            resolved.pop(code, None)

    usable_total = sum(len(items) for items in grouped.values())
    if usable_total < minimum_total:
        raise ValueError(
            f"Safety stop: only {usable_total} sing-box-compatible, tunnel-validated nodes; "
            f"minimum is {minimum_total}. Existing generated files were not touched."
        )

    profile, country_counts = _build_singbox_profile(grouped, resolved, jcfg)
    outdir = Path(output_dir)
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    subscription_name = str(outcfg.get("subscription_file", "AeryxVPN.json"))
    metadata_name = str(outcfg.get("metadata_file", "AeryxVPN.metadata.json"))
    subscription_path = outdir / subscription_name
    _write_json(subscription_path, profile)
    profile_hash = hashlib.sha256(subscription_path.read_bytes()).hexdigest()

    tz_name = str(jcfg.get("timezone", "Europe/Berlin"))
    try:
        tz = ZoneInfo(tz_name)
    except ZoneInfoNotFoundError:
        tz = timezone.utc
        tz_name = "UTC"
    moment = generated_at or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment_utc = moment.astimezone(timezone.utc)
    moment_local = moment.astimezone(tz)
    updated_at = moment_utc.isoformat(timespec="seconds").replace("+00:00", "Z")
    updated_local = moment_local.strftime("%d.%m.%Y %H:%M")

    raw_url = ""
    if repository:
        raw_url = f"https://raw.githubusercontent.com/{repository}/{branch or 'main'}/{subscription_name}"
    country_selector_tag = str((jcfg.get("sing_box", {}) or {}).get("country_selector_tag", "🌍 Выбор страны · AeryxVPN"))
    total_nodes = sum(item["node_count"] for item in country_counts.values())
    metadata = {
        "schema_version": "1.0.0",
        "metadata": {
            "title": str(jcfg.get("title", "AeryxVPN")),
            "project": "AeryxVPN",
            "description": "Одна JSON-подписка со странами в виде групп и автоматическим выбором узла внутри каждой страны.",
            "format": "sing-box-native-json",
            "subscription_file": subscription_name,
            "subscription_url": raw_url or subscription_name,
            "support_url": str(jcfg.get("support_url", "https://t.me/cheesyx")),
            "website_url": str(jcfg.get("website_url", "https://t.me/AeryxVPN")),
            "generated_at": updated_at,
            "updated_at_local": updated_local,
            "timezone": tz_name,
            "update_interval_hours": max(1, int(jcfg.get("update_interval_hours", 6))),
            "country_count": len(country_counts),
            "validated_config_count": total_nodes,
            "country_selector_tag": country_selector_tag,
            "balancing": {
                "per_country": "urltest",
                "country_selection": "selector",
                "probe_url": str((jcfg.get("sing_box", {}) or {}).get("probe_url", "https://www.gstatic.com/generate_204")),
                "interval": str((jcfg.get("sing_box", {}) or {}).get("interval", "3m")),
                "tolerance_ms": max(0, int((jcfg.get("sing_box", {}) or {}).get("tolerance_ms", 80))),
            },
            "profile_sha256": profile_hash,
            "countries": [
                {"code": code, **row}
                for code, row in sorted(country_counts.items(), key=lambda kv: (-kv[1]["node_count"], _country_sort(kv[0])))
            ],
            "note": "Metadata sidecar only; import AeryxVPN.json as the client profile. Arbitrary metadata fields are not inserted into the native sing-box schema.",
        },
    }
    metadata_path = outdir / metadata_name
    _write_json(metadata_path, metadata)

    report = {
        "status": "built",
        "generated_at": updated_at,
        "input_records": len(raw),
        "tunnel_validated_input_records": tunnel_validated_input_records,
        "published_config_count": total_nodes,
        "country_count": len(country_counts),
        "countries": country_counts,
        "rejected_counts": dict(rejected_reasons.most_common()),
        "conversion_failures": conversion_failures,
        "files_written": [subscription_name, metadata_name, "build-report.json"],
        "subscription_sha256": profile_hash,
        "note": "No raw proxy URIs, credentials, or rejected URI list are written to this report.",
    }
    _write_json(outdir / "build-report.json", report)
    return report


def build_country_outputs(
    input_path: Path = DEFAULT_INPUT,
    output_dir: Path = DEFAULT_OUTPUT,
    config_path: Path = DEFAULT_CONFIG,
    repository: str = "",
    branch: str = "main",
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build to a sibling staging directory and swap only after successful generation."""
    target = Path(output_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    backup = target.with_name(f".{target.name}.previous")
    if not target.exists() and backup.exists():
        backup.replace(target)
    elif target.exists() and backup.exists():
        shutil.rmtree(backup) if backup.is_dir() else backup.unlink()
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.staging-", dir=target.parent))
    try:
        report = _build_country_outputs_in_place(
            input_path=input_path, output_dir=staging, config_path=config_path,
            repository=repository, branch=branch, generated_at=generated_at,
        )
        if backup.exists():
            shutil.rmtree(backup) if backup.is_dir() else backup.unlink()
        had_target = target.exists()
        if had_target:
            target.replace(backup)
        try:
            staging.replace(target)
        except Exception:
            if had_target and backup.exists() and not target.exists():
                backup.replace(target)
            raise
        if backup.exists():
            shutil.rmtree(backup) if backup.is_dir() else backup.unlink()
        return report
    except Exception:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Build one AeryxVPN JSON subscription with country groups and native balancers")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--repository", default="", help="GitHub owner/repo for raw subscription URL metadata")
    parser.add_argument("--branch", default="main")
    args = parser.parse_args()
    try:
        report = build_country_outputs(args.input, args.output, args.config, args.repository, args.branch)
    except Exception as exc:
        print(json.dumps({"status": "safety_stop", "error_type": type(exc).__name__, "message": str(exc)}, ensure_ascii=False), flush=True)
        return 2
    print(json.dumps({k: report[k] for k in ("status", "published_config_count", "country_count", "countries", "rejected_counts", "files_written")}, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
