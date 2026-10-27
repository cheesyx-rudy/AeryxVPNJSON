"""Build one native JSON profile per country plus a metadata-only index.

The published `countries/*.json` files are complete sing-box client configurations.
`xray/*.json` are complete Xray client configurations where at least one accepted
node can be represented by Xray. Metadata stays in index/country-metadata sidecars
so native client parsers never receive non-standard JSON fields.
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

from .checks import build_singbox_outbound, build_xray_config
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
    """Use the parser's already-resolved country label; do not infer from endpoint ports."""
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


def _unique_tag(code: str, index: int, country: Country) -> str:
    # Stable and easy to read in client UI, while keeping tags unique per country.
    return f"{flag_for_code(code)} {country.name} · AeryxVPN {index:03d}"


def _singbox_config(country: Country, entries: list[dict[str, Any]], settings: dict[str, Any]) -> dict[str, Any]:
    cfg = settings.get("sing_box", {}) or {}
    tag = f"{flag_for_code(country.code)} {country.name} · Auto"
    node_tags = [str(entry["tag"]) for entry in entries]
    outbounds = [entry["outbound"] for entry in entries]
    outbounds.append({
        "type": "urltest",
        "tag": tag,
        "outbounds": node_tags,
        "url": str(cfg.get("probe_url", "https://www.gstatic.com/generate_204")),
        "interval": str(cfg.get("interval", "3m")),
        "tolerance": max(0, int(cfg.get("tolerance_ms", 80))),
    })
    outbounds.append({"type": "direct", "tag": "direct"})
    return {
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
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "rules": [
                {"action": "sniff"},
                {"protocol": ["dns"], "action": "hijack-dns"},
            ],
            "final": tag,
        },
    }


def _xray_config(country: Country, entries: list[dict[str, Any]], settings: dict[str, Any]) -> dict[str, Any] | None:
    cfg = settings.get("xray", {}) or {}
    prefix = f"aeryx-{country.code.lower()}-"
    outbounds: list[dict[str, Any]] = []
    for entry in entries:
        try:
            tag = str(entry["tag"])
            xray_out = entry["xray_outbound"]
            outbounds.append({**xray_out, "tag": tag})
        except Exception:
            continue
    if not outbounds:
        return None
    first_tag = str(outbounds[0]["tag"])
    balancer_tag = f"{flag_for_code(country.code)} {country.name} · Auto"
    outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1", "port": int(cfg.get("socks_listen_port", 10808)),
                "protocol": "socks", "tag": "socks-in",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            },
            {
                "listen": "127.0.0.1", "port": int(cfg.get("http_listen_port", 10809)),
                "protocol": "http", "tag": "http-in", "settings": {},
            },
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "inboundTag": ["socks-in", "http-in"], "balancerTag": balancer_tag}],
            "balancers": [{
                "tag": balancer_tag,
                "selector": [prefix],
                "fallbackTag": first_tag,
                "strategy": {"type": "leastPing"},
            }],
        },
        "observatory": {
            "subjectSelector": [prefix],
            "probeUrl": str(cfg.get("probe_url", "https://www.gstatic.com/generate_204")),
            "probeInterval": str(cfg.get("probe_interval", "30s")),
            "enableConcurrency": True,
        },
    }


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _country_code_sort(code: str) -> tuple[str, str]:
    return (code != "EU", code)


def _build_country_outputs_in_place(
    input_path: Path = DEFAULT_INPUT,
    output_dir: Path = DEFAULT_OUTPUT,
    config_path: Path = DEFAULT_CONFIG,
    repository: str = "",
    branch: str = "main",
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build an atomic output tree from the parser's accepted, tunnel-checked nodes."""
    cfg = _load_config(config_path)
    jcfg = cfg.get("json_subscription", {}) or {}
    outcfg = jcfg.get("output", {}) or {}
    if not bool((jcfg.get("sing_box", {}) or {}).get("enabled", True)):
        raise ValueError("sing-box JSON output must stay enabled; it is the primary country subscription format")

    raw = json.loads(input_path.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, list):
        raise ValueError("parsed_proxies.json must contain a list")

    resolved: dict[str, Country] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rejected_reasons: Counter[str] = Counter()
    input_accepted = 0
    conversion_failures = 0

    for obj in raw:
        if not isinstance(obj, dict):
            rejected_reasons["invalid_record"] += 1
            continue
        status = str(obj.get("check_status") or "")
        if not status.startswith("proxy_ok"):
            rejected_reasons["not_tunnel_validated"] += 1
            continue
        input_accepted += 1
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
            sing = build_singbox_outbound(uri)
            if not isinstance(sing, dict) or not sing.get("type"):
                raise ValueError("adapter_returned_no_outbound")
        except Exception as exc:
            conversion_failures += 1
            rejected_reasons["singbox_conversion:" + type(exc).__name__] += 1
            continue
        # Store the URI only in memory and in the native public config; never in build reports.
        grouped[code].append({"uri": uri, "singbox": sing, "name": country.name, "country": country})

    usable_total = sum(len(v) for v in grouped.values())
    minimum_total = max(1, int(jcfg.get("minimum_total_configs", 5)))
    minimum_country = max(1, int(jcfg.get("minimum_country_configs", 1)))
    if usable_total < minimum_total:
        raise ValueError(
            f"Safety stop: only {usable_total} sing-box-compatible, tunnel-validated nodes; "
            f"minimum is {minimum_total}. Existing generated files were not touched."
        )

    # Country output is built in a clean staging directory; caller only publishes it after validation.
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    countries_dir = output_dir / str(outcfg.get("countries_directory", "countries"))
    xray_dir = output_dir / str(outcfg.get("xray_directory", "xray"))
    metadata_dir = output_dir / str(outcfg.get("country_metadata_directory", "country-metadata"))
    for folder in (countries_dir, xray_dir, metadata_dir):
        folder.mkdir(parents=True, exist_ok=True)

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

    repo_base = ""
    if repository:
        safe_branch = branch or "main"
        repo_base = f"https://raw.githubusercontent.com/{repository}/{safe_branch}"

    country_records: list[dict[str, Any]] = []
    total_xray = 0
    build_groups: dict[str, dict[str, Any]] = {}

    for code in sorted(grouped, key=_country_code_sort):
        records = grouped[code]
        if len(records) < minimum_country:
            rejected_reasons["country_below_minimum"] += len(records)
            continue
        country = resolved[code]
        label = f"{flag_for_code(code)} {country.name}"
        sing_entries: list[dict[str, Any]] = []
        xray_entries: list[dict[str, Any]] = []
        seen = set()
        for record in records:
            uri = record["uri"]
            # Parser normally deduplicates first, this is a final per-country safety net.
            if uri in seen:
                rejected_reasons["duplicate_uri"] += 1
                continue
            seen.add(uri)
            index = len(sing_entries) + 1
            tag = _unique_tag(code, index, country)
            sing = dict(record["singbox"])
            sing["tag"] = tag
            sing_entries.append({"uri": uri, "tag": tag, "outbound": sing})
            try:
                xray_obj = build_xray_config(uri, 10808)
                xray_out = xray_obj["outbounds"][0]
                xray_tag = f"aeryx-{code.lower()}-{len(xray_entries)+1:03d}"
                xray_entries.append({"uri": uri, "tag": xray_tag, "xray_outbound": xray_out})
            except Exception as exc:
                rejected_reasons["xray_not_representable:" + type(exc).__name__] += 1

        if not sing_entries:
            continue
        sing_profile = _singbox_config(country, sing_entries, jcfg)
        sing_path = countries_dir / f"{code}.json"
        _write_json(sing_path, sing_profile)
        sing_hash = hashlib.sha256(sing_path.read_bytes()).hexdigest()

        xray_path = None
        xray_hash = None
        xray_profile = None
        if (jcfg.get("xray", {}) or {}).get("enabled", True) and xray_entries:
            # Xray balancer uses leastPing only when observatory can measure the same prefixed tags.
            xray_profile = _xray_config(country, xray_entries, jcfg)
            if xray_profile:
                xray_path = xray_dir / f"{code}.json"
                _write_json(xray_path, xray_profile)
                xray_hash = hashlib.sha256(xray_path.read_bytes()).hexdigest()
                total_xray += len(xray_entries)

        sing_url = f"{repo_base}/countries/{code}.json" if repo_base else f"countries/{code}.json"
        xray_url = (f"{repo_base}/xray/{code}.json" if repo_base else f"xray/{code}.json") if xray_path else None
        metadata_url = f"{repo_base}/country-metadata/{code}.json" if repo_base else f"country-metadata/{code}.json"
        country_meta = {
            "schema_version": "1.0.0",
            "metadata": {
                "title": f"{country.name} · AeryxVPN",
                "project": str(jcfg.get("title", "AeryxVPN JSON")),
                "support_url": str(jcfg.get("support_url", "https://t.me/cheesyx")),
                "website_url": str(jcfg.get("website_url", "https://t.me/AeryxVPN")),
                "country_code": code,
                "country_name": country.name,
                "flag": flag_for_code(code),
                "generated_at": updated_at,
                "updated_at_local": updated_local,
                "timezone": tz_name,
                "update_interval_hours": max(1, int(jcfg.get("update_interval_hours", 6))),
                "validated_node_count": len(sing_entries),
                "xray_compatible_node_count": len(xray_entries) if xray_path else 0,
                "balancing": {
                    "sing_box": {"type": "urltest", "probe_url": str((jcfg.get("sing_box", {}) or {}).get("probe_url", "https://www.gstatic.com/generate_204"))},
                    "xray": {"type": "leastPing", "observatory_enabled": bool(xray_path)} if xray_path else None,
                },
                "files": {
                    "sing_box": {"path": f"countries/{code}.json", "url": sing_url, "sha256": sing_hash},
                    "xray": {"path": f"xray/{code}.json", "url": xray_url, "sha256": xray_hash} if xray_path else None,
                },
            },
        }
        meta_path = metadata_dir / f"{code}.json"
        _write_json(meta_path, country_meta)
        meta_hash = hashlib.sha256(meta_path.read_bytes()).hexdigest()
        country_records.append({
            "code": code,
            "name": country.name,
            "flag": flag_for_code(code),
            "validated_node_count": len(sing_entries),
            "xray_compatible_node_count": len(xray_entries) if xray_path else 0,
            "files": {
                "sing_box": {"path": f"countries/{code}.json", "url": sing_url, "sha256": sing_hash},
                "xray": {"path": f"xray/{code}.json", "url": xray_url, "sha256": xray_hash} if xray_path else None,
                "metadata": {"path": f"country-metadata/{code}.json", "url": metadata_url, "sha256": meta_hash},
            },
            "balancers": {
                "sing_box": {"type": "urltest", "outbound_tag": f"{flag_for_code(code)} {country.name} · Auto"},
                "xray": {"type": "leastPing", "enabled": bool(xray_path)},
            },
        })
        build_groups[code] = {
            "country_name": country.name,
            "sing_box_nodes": len(sing_entries),
            "xray_compatible_nodes": len(xray_entries) if xray_path else 0,
            "sing_box_file_sha256": sing_hash,
            "xray_file_written": bool(xray_path),
        }

    if not country_records:
        raise ValueError("Safety stop: no country group produced a valid sing-box profile; old outputs must be retained")

    country_records.sort(key=lambda item: (-item["validated_node_count"], item["code"]))
    index_doc = {
        "schema_version": "1.0.0",
        "metadata": {
            "title": str(jcfg.get("title", "AeryxVPN JSON")),
            "project": "AeryxVPN",
            "description": "Country-separated VPN JSON profiles with native automatic node selection.",
            "support_url": str(jcfg.get("support_url", "https://t.me/cheesyx")),
            "website_url": str(jcfg.get("website_url", "https://t.me/AeryxVPN")),
            "generated_at": updated_at,
            "updated_at_local": updated_local,
            "timezone": tz_name,
            "update_interval_hours": max(1, int(jcfg.get("update_interval_hours", 6))),
            "country_count": len(country_records),
            "validated_sing_box_config_count": sum(r["validated_node_count"] for r in country_records),
            "xray_compatible_config_count": sum(r["xray_compatible_node_count"] for r in country_records),
            "checks": {"engine": "Xray-core / sing-box", "acceptance": "only tunnel-validated nodes from parser output"},
        },
        "countries": country_records,
    }
    _write_json(output_dir / str(outcfg.get("index_file", "index.json")), index_doc)
    report = {
        "status": "built",
        "generated_at": updated_at,
        "input_records": len(raw),
        "tunnel_validated_input_records": input_accepted,
        "sing_box_config_count": sum(r["validated_node_count"] for r in country_records),
        "xray_compatible_config_count": total_xray,
        "country_count": len(country_records),
        "countries": build_groups,
        "rejected_counts": dict(rejected_reasons.most_common()),
        "conversion_failures": conversion_failures,
        "files_written": [str(p.relative_to(output_dir)) for p in sorted(output_dir.rglob("*.json"))],
        "note": "Safe summary only. Credentials and raw proxy URIs are deliberately not written to this report.",
    }
    _write_json(output_dir / "build-report.json", report)
    return report


def build_country_outputs(
    input_path: Path = DEFAULT_INPUT,
    output_dir: Path = DEFAULT_OUTPUT,
    config_path: Path = DEFAULT_CONFIG,
    repository: str = "",
    branch: str = "main",
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build in a sibling staging directory and replace output only after success."""
    target = Path(output_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    backup = target.with_name(f".{target.name}.previous")
    # Recover the previous successful build if a runner was interrupted during promotion.
    if not target.exists() and backup.exists():
        backup.replace(target)
    elif target.exists() and backup.exists():
        shutil.rmtree(backup) if backup.is_dir() else backup.unlink()
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.staging-", dir=target.parent))
    try:
        report = _build_country_outputs_in_place(
            input_path=input_path,
            output_dir=staging,
            config_path=config_path,
            repository=repository,
            branch=branch,
            generated_at=generated_at,
        )
        # Keep the prior build recoverable until the new directory is in place.
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
    parser = argparse.ArgumentParser(description="Build country-split AeryxVPN JSON subscriptions and native balancers")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--repository", default="", help="GitHub owner/repo for raw links")
    parser.add_argument("--branch", default="main")
    args = parser.parse_args()
    try:
        report = build_country_outputs(args.input, args.output, args.config, args.repository, args.branch)
    except Exception as exc:
        print(json.dumps({"status": "safety_stop", "error_type": type(exc).__name__, "message": str(exc)}, ensure_ascii=False), flush=True)
        return 2
    print(json.dumps({k: report[k] for k in ("status", "sing_box_config_count", "xray_compatible_config_count", "country_count", "countries", "rejected_counts")}, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
