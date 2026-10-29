"""Build one Happ-compatible Xray JSON-array subscription.

The published AeryxVPN.json is one JSON array. Every array element is one
visible Happ profile (one country, plus a global Auto profile), and every
profile contains all compatible nodes for its scope with Xray burstObservatory +
leastPing balancing. The metadata and build report are non-importable sidecars.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from .geolocation import Country, CountryResolver, country_from_label, flag_for_code
from .xray_builder import build_xray_json_profile, uri_to_xray_outbound
from .xray_validation import safe_xray_diagnostic

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "output" / "engine" / "parsed_proxies.json"
DEFAULT_CONFIG = ROOT / "config" / "settings.yaml"
DEFAULT_OUTPUT = ROOT / "output" / "publish"


def _load_config(path: Path) -> dict[str, Any]:
    obj = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(obj, dict):
        raise ValueError("settings.yaml must contain a JSON/YAML object")
    return obj


def _label_candidates(node: dict[str, Any]) -> list[str]:
    values = [str(node.get("name") or ""), str(node.get("source_name") or ""), str(node.get("source") or "")]
    uri = str(node.get("uri") or "")
    try:
        fragment = urlsplit(uri).fragment
        if fragment:
            values.insert(0, unquote(fragment))
    except Exception:
        pass
    return [v for v in values if v]


def _get_country(node: dict[str, Any], resolver: CountryResolver | None = None) -> Country | None:
    """Resolve country by public endpoint IP first; use explicit labels/TLD only as fallback."""
    uri = str(node.get("uri") or "")
    try:
        host = str(node.get("host") or urlsplit(uri).hostname or "")
    except Exception:
        host = str(node.get("host") or "")
    ips: list[str] = []
    for key in ("endpoint_ip", "resolved_ip", "resolved_ips", "allowed_ips"):
        value = node.get(key)
        if isinstance(value, (list, tuple, set)):
            ips.extend(str(item) for item in value if item)
        elif value:
            ips.append(str(value))
    labels = _label_candidates(node)
    if resolver is not None:
        country = resolver.resolve(ips, labels, host)
        if country:
            return country
    for label in labels:
        country = country_from_label(label, method="parser_label")
        if country:
            return country
    return None


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _country_sort(code: str) -> tuple[bool, str]:
    return (code != "EU", code)


_RUSSIAN_COUNTRY_NAMES = {
    "Australia": "Австралия", "Austria": "Австрия", "Azerbaijan": "Азербайджан",
    "Belarus": "Беларусь", "Belgium": "Бельгия", "Brazil": "Бразилия",
    "Bulgaria": "Болгария", "Canada": "Канада", "Chile": "Чили",
    "China": "Китай", "Croatia": "Хорватия", "Cyprus": "Кипр",
    "Czechia": "Чехия", "Czech Republic": "Чехия", "Denmark": "Дания",
    "Estonia": "Эстония", "Finland": "Финляндия", "France": "Франция",
    "Georgia": "Грузия", "Germany": "Германия", "Greece": "Греция",
    "Hong Kong": "Гонконг", "Hungary": "Венгрия", "Iceland": "Исландия",
    "India": "Индия", "Indonesia": "Индонезия", "Ireland": "Ирландия",
    "Israel": "Израиль", "Italy": "Италия", "Japan": "Япония",
    "Kazakhstan": "Казахстан", "Latvia": "Латвия", "Lithuania": "Литва",
    "Luxembourg": "Люксембург", "Malaysia": "Малайзия", "Mexico": "Мексика",
    "Moldova": "Молдова", "Moldova, Republic of": "Молдова", "Netherlands": "Нидерланды",
    "New Zealand": "Новая Зеландия", "Norway": "Норвегия", "Poland": "Польша",
    "Portugal": "Португалия", "Romania": "Румыния", "Russia": "Россия",
    "Russian Federation": "Россия", "Serbia": "Сербия", "Singapore": "Сингапур",
    "Slovakia": "Словакия", "Slovenia": "Словения", "South Africa": "ЮАР",
    "South Korea": "Южная Корея", "Korea, Republic of": "Южная Корея",
    "Spain": "Испания", "Sweden": "Швеция", "Switzerland": "Швейцария",
    "Taiwan": "Тайвань", "Thailand": "Таиланд", "Turkey": "Турция",
    "Türkiye": "Турция", "Ukraine": "Украина", "United Arab Emirates": "ОАЭ",
    "United Kingdom": "Великобритания", "United States": "США", "United States of America": "США",
    "Vietnam": "Вьетнам", "Armenia": "Армения", "Argentina": "Аргентина",
    "UAE": "ОАЭ", "The Netherlands": "Нидерланды", "Republic of Korea": "Южная Корея",
}


def _country_profile_name(country: Country) -> str:
    # The provided working Happ profiles use Russian labels; unknown names keep their source label.
    name = _RUSSIAN_COUNTRY_NAMES.get(country.name, country.name)
    return f"{flag_for_code(country.code)} {name}"


def _build_profiles(
    grouped: dict[str, list[dict[str, Any]]],
    countries: dict[str, Country],
    settings: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    xcfg = settings.get("xray_json", {}) or {}
    burst_observatory = xcfg.get("burst_observatory", {}) or {}
    if not isinstance(burst_observatory, dict):
        raise ValueError("json_subscription.xray_json.burst_observatory must be an object")
    socks_port = int(xcfg.get("inbound_socks_port", 10808))
    suffix = str(xcfg.get("country_profile_name_suffix", "" )).strip()
    profiles: list[dict[str, Any]] = []
    country_rows: list[dict[str, Any]] = []

    ordered_codes = sorted(grouped, key=lambda code: (-len(grouped[code]), _country_sort(code)))
    all_records: list[dict[str, Any]] = []
    for code in ordered_codes:
        country = countries[code]
        records = grouped[code]
        if not records:
            continue
        # Outbound tags follow the supplied Happ template (`proxy-1`, `proxy-2`, ...);
        # Xray prefix selectors match all of them via the shared `proxy` prefix.
        name = _country_profile_name(country)
        if suffix:
            name = f"{name} {suffix}"
        profiles.append(build_xray_json_profile(name, records, burst_observatory, socks_port))
        country_rows.append({
            "code": code,
            "name": country.name,
            "flag": flag_for_code(code),
            "profile_name": name,
            "node_count": len(records),
            "balancer_tag": "balancer",
            "balancing": "burstObservatory+leastPing",
        })
        all_records.extend(records)

    if not profiles:
        raise ValueError("Safety stop: no country contains an Xray-compatible validated node")
    if bool(xcfg.get("include_auto_profile", True)) and len(all_records) > 1:
        auto_name = str(xcfg.get("auto_profile_name", "🇪🇺 Автовыбор"))
        # Happ displays profiles in JSON-array order; keep the global Auto profile first.
        profiles.insert(0, build_xray_json_profile(auto_name, all_records, burst_observatory, socks_port))
    return profiles, country_rows


def _reject_unsafe_plain_ip_outbound(outbound: dict[str, Any]) -> None:
    """Guard the generated Xray outbound itself against plain protocol/IP pairs.

    This complements URI-level validation so a normalization adapter cannot
    accidentally let a public literal IP through to every generated profile.
    """
    protocol = str(outbound.get("protocol") or "").lower()
    if protocol not in {"vless", "vmess", "trojan"}:
        return
    stream = outbound.get("streamSettings") or {}
    security = str(stream.get("security") or "none").lower()
    if security not in {"", "none"}:
        return
    settings = outbound.get("settings") or {}
    addresses: list[str] = []
    for item in settings.get("vnext") or []:
        if item.get("address"):
            addresses.append(str(item["address"]))
    if settings.get("address"):
        addresses.append(str(settings["address"]))
    for item in settings.get("servers") or []:
        if item.get("address"):
            addresses.append(str(item["address"]))
    for host in addresses:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            continue  # Xray allows domain-name endpoints without TLS.
        if not address.is_private:
            raise ValueError("xray_public_ip_requires_tls_or_reality")


def _xray_rejection_code(diagnostic: str | None) -> str:
    """Return a safe, stable rejection category rather than putting node data in reports."""
    value = (diagnostic or "").lower()
    if "without tls" in value or "requires tls" in value or "public ip" in value:
        return "security_required"
    if "unsupported" in value or "not supported" in value:
        return "unsupported_config"
    if "unknown" in value or "invalid" in value or "parse" in value or "decode" in value:
        return "invalid_config"
    if "failed to start" in value or "failed to load" in value or "failed to build" in value:
        return "startup_error"
    return "core_rejected_config"


def _xray_prevalidate_outbound(
    outbound: dict[str, Any],
    xray_binary: str | Path,
    burst_observatory: dict[str, Any] | None,
    socks_port: int,
) -> tuple[bool, str | None]:
    """Validate one candidate node inside the actual Happ/Xray profile shell.

    This runs before country grouping so one Xray-incompatible node cannot poison
    both its country profile and the global Auto profile.
    """
    profile = build_xray_json_profile(
        "AeryxVPN node compatibility check",
        [{"xray": outbound}],
        burst_observatory,
        socks_port,
    )
    profile.pop("remarks", None)
    profile.pop("meta", None)
    with tempfile.TemporaryDirectory(prefix="aeryx-xray-node-") as temp_dir:
        config_path = Path(temp_dir) / "node.json"
        config_path.write_text(json.dumps(profile, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        try:
            proc = subprocess.run(
                [str(xray_binary), "run", "-test", "-config", str(config_path)],
                capture_output=True,
                text=True,
                timeout=8,
            )
        except subprocess.TimeoutExpired as exc:
            # A timeout is an environment/core problem, not proof that the node is
            # bad. Abort the build rather than silently dropping every slow check.
            raise RuntimeError("xray_node_prevalidation_timeout") from exc
        except FileNotFoundError as exc:
            raise RuntimeError("xray_node_prevalidation_binary_missing") from exc
        if proc.returncode != 0:
            return False, safe_xray_diagnostic(proc, config_path)
    return True, None


def _build_country_outputs_in_place(
    input_path: Path = DEFAULT_INPUT,
    output_dir: Path = DEFAULT_OUTPUT,
    config_path: Path = DEFAULT_CONFIG,
    repository: str = "",
    branch: str = "main",
    generated_at: datetime | None = None,
    xray_binary: str | Path | None = None,
) -> dict[str, Any]:
    """Build one Xray JSON array and metadata/report sidecars in a staging directory."""
    cfg = _load_config(config_path)
    jcfg = cfg.get("json_subscription", {}) or {}
    outcfg = jcfg.get("output", {}) or {}
    xcfg = jcfg.get("xray_json", {}) or {}
    if not bool(xcfg.get("enabled", True)):
        raise ValueError("Xray JSON array output must be enabled")
    burst_cfg = xcfg.get("burst_observatory", {}) or {}
    socks_port = int(xcfg.get("inbound_socks_port", 10808))
    if xray_binary is not None and not Path(xray_binary).is_file():
        raise FileNotFoundError(f"Xray pre-validation binary not found: {xray_binary}")

    raw = json.loads(input_path.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, list):
        raise ValueError("parsed_proxies.json must contain a list")

    location_cfg = cfg.get("location", {}) or {}
    db_path_raw = str(location_cfg.get("database_path", "output/dbip-country-lite.mmdb"))
    db_path = Path(db_path_raw)
    if not db_path.is_absolute():
        db_path = ROOT / db_path
    resolver = CountryResolver(db_path)

    resolved: dict[str, Country] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rejected_reasons: Counter[str] = Counter()
    tunnel_validated_input_records = 0
    conversion_failures = 0
    xray_validation_failures = 0
    input_uri_seen: set[str] = set()

    try:
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
            # The upstream pipeline should already deduplicate; prevent duplicate full
            # URIs from inflating country profile counts if a source repeats an entry.
            if uri in input_uri_seen:
                rejected_reasons["duplicate_uri"] += 1
                continue
            input_uri_seen.add(uri)
            country = _get_country(obj, resolver)
            if country is None:
                rejected_reasons["country_unknown"] += 1
                continue
            code = country.code.upper()
            resolved[code] = country
            try:
                outbound = uri_to_xray_outbound(uri)
                if not isinstance(outbound, dict) or not outbound.get("protocol"):
                    raise ValueError("xray_adapter_returned_no_outbound")
                _reject_unsafe_plain_ip_outbound(outbound)
            except Exception as exc:
                conversion_failures += 1
                reason = str(exc).split(":", 1)[0]
                rejected_reasons["xray_conversion:" + reason] += 1
                continue
            if xray_binary is not None:
                compatible, diagnostic = _xray_prevalidate_outbound(
                    outbound, xray_binary, burst_cfg, socks_port
                )
                if not compatible:
                    xray_validation_failures += 1
                    rejected_reasons[
                        "xray_core_rejected_node:" + _xray_rejection_code(diagnostic)
                    ] += 1
                    continue
            grouped[code].append({"uri": uri, "xray": outbound, "country": code})
    finally:
        resolver.close()

    minimum_total = max(1, int(jcfg.get("minimum_total_configs", 5)))
    minimum_country = max(1, int(jcfg.get("minimum_country_configs", 1)))
    for code in list(grouped):
        if len(grouped[code]) < minimum_country:
            rejected_reasons["country_below_minimum"] += len(grouped[code])
            del grouped[code]
            resolved.pop(code, None)

    usable_total = sum(len(items) for items in grouped.values())
    if usable_total < minimum_total:
        raise ValueError(
            f"Safety stop: only {usable_total} Xray-compatible, tunnel-validated nodes; "
            f"minimum is {minimum_total}. Xray-core rejected {xray_validation_failures} node(s). "
            f"Rejection counts: {dict(rejected_reasons.most_common())}. "
            "Existing published files were not touched."
        )

    profiles, country_rows = _build_profiles(grouped, resolved, jcfg)
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    subscription_name = str(outcfg.get("subscription_file", "AeryxVPN.json"))
    metadata_name = str(outcfg.get("metadata_file", "AeryxVPN.metadata.json"))
    subscription_path = outdir / subscription_name
    _write_json(subscription_path, profiles)
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
    updated_at = moment_utc.isoformat(timespec="seconds").replace("+00:00", "Z")
    updated_local = moment.astimezone(tz).strftime("%d.%m.%Y %H:%M")
    raw_url = f"https://raw.githubusercontent.com/{repository}/{branch or 'main'}/{subscription_name}" if repository else subscription_name
    total_nodes = sum(row["node_count"] for row in country_rows)
    burst_cfg = xcfg.get("burst_observatory", {}) or {}
    balancing = {
        "engine": "Xray-core",
        "per_country": "burstObservatory+leastPing",
        "global_auto_profile": bool(xcfg.get("include_auto_profile", True)),
        "connectivity": str(burst_cfg.get("connectivity", "https://browser.yandex.ru/generate_204")),
        "destination": str(burst_cfg.get("destination", "https://www.google.com")),
        "interval": str(burst_cfg.get("interval", "15s")),
        "sampling": int(burst_cfg.get("sampling", 4)),
        "timeout": str(burst_cfg.get("timeout", "2s")),
        "method": "client-side; each profile measures its own nodes",
    }
    metadata = {
        "schema_version": "1.1.0",
        "metadata": {
            "title": str(jcfg.get("title", "AeryxVPN")),
            "project": "AeryxVPN",
            "description": "Happ-совместимая JSON-подписка на основе общего Xray-профиля: узлы сгруппированы по странам и доступны в профиле авто-выбора.",
            "format": "happ-xray-json-array",
            "subscription_file": subscription_name,
            "subscription_url": raw_url,
            "support_url": str(jcfg.get("support_url", "https://t.me/cheesyx")),
            "website_url": str(jcfg.get("website_url", "https://t.me/AeryxVPN")),
            "generated_at": updated_at,
            "updated_at_local": updated_local,
            "timezone": tz_name,
            "update_interval_hours": max(1, int(jcfg.get("update_interval_hours", 6))),
            "country_count": len(country_rows),
            "validated_config_count": total_nodes,
            "profile_count": len(profiles),
            "auto_profile_included": bool(xcfg.get("include_auto_profile", True)) and len(profiles) > len(country_rows),
            "auto_profile_name": str(xcfg.get("auto_profile_name", "🇪🇺 Автовыбор")),
            "balancing": balancing,
            "profile_sha256": profile_hash,
            "countries": sorted(country_rows, key=lambda row: (-row["node_count"], _country_sort(row["code"]))),
            "profile_template_revision": "1.4.4",
            "note": (
                "Metadata sidecar only. Import AeryxVPN.json; it is a JSON array of complete Xray profiles, one per country plus optional global Auto. "
                + ("Every candidate outbound was prevalidated with official Xray-core before grouping. " if xray_binary is not None else "Nodes passed source-pipeline checks and Xray JSON conversion; core prevalidation was not requested. ")
                + "The shared profile shell follows config/xray-profile-template.json. Custom WH-DIRECT/STD-DIRECT geosite/geoip selectors are not used, so no additional custom geo databases are required."
            ),
        },
    }
    _write_json(outdir / metadata_name, metadata)
    report = {
        "status": "built",
        "generated_at": updated_at,
        "input_records": len(raw),
        "tunnel_validated_input_records": tunnel_validated_input_records,
        "published_config_count": total_nodes,
        "country_count": len(country_rows),
        "profile_count": len(profiles),
        "countries": country_rows,
        "rejected_counts": dict(rejected_reasons.most_common()),
        "conversion_failures": conversion_failures,
        "xray_validation_enabled": xray_binary is not None,
        "xray_validation_failures": xray_validation_failures,
        "files_written": [subscription_name, metadata_name, "build-report.json"],
        "subscription_sha256": profile_hash,
        "balancing": balancing,
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
    xray_binary: str | Path | None = None,
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
            xray_binary=xray_binary,
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
    parser = argparse.ArgumentParser(description="Build one Happ-compatible AeryxVPN Xray JSON-array subscription")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--repository", default="", help="GitHub owner/repo for raw subscription URL metadata")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--xray", default=None, help="official Xray-core binary; prevalidates each node before publishing")
    args = parser.parse_args()
    try:
        report = build_country_outputs(
            args.input, args.output, args.config, args.repository, args.branch,
            xray_binary=args.xray,
        )
    except Exception as exc:
        print(json.dumps({"status": "safety_stop", "error_type": type(exc).__name__, "message": str(exc)}, ensure_ascii=False), flush=True)
        return 2
    print(json.dumps({k: report[k] for k in ("status", "published_config_count", "country_count", "profile_count", "countries", "rejected_counts", "files_written")}, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
