"""Country detection and stable, URI-safe proxy names for AeryxVPN."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit

try:
    import maxminddb
except ImportError:  # Optional for local/offline unit tests; CI installs it.
    maxminddb = None

try:
    import pycountry
except ImportError:  # Small fallback map below keeps import safe in minimal environments.
    pycountry = None


@dataclass(frozen=True, slots=True)
class Country:
    code: str
    name: str
    method: str
    matched_ip: str | None = None


# These aliases cover common labels produced by popular subscription generators.
ALIASES = {
    "russia": "RU", "russian federation": "RU", "россия": "RU", "российская федерация": "RU", "рф": "RU",
    "germany": "DE", "deutschland": "DE", "германия": "DE", "немецкий": "DE",
    "united states": "US", "united states of america": "US", "usa": "US", "u.s.a.": "US", "сша": "US", "америка": "US",
    "united kingdom": "GB", "great britain": "GB", "britain": "GB", "uk": "GB", "великобритания": "GB", "англия": "GB",
    "netherlands": "NL", "the netherlands": "NL", "holland": "NL", "нидерланды": "NL", "голландия": "NL",
    "turkey": "TR", "türkiye": "TR", "турция": "TR",
    "czech republic": "CZ", "czechia": "CZ", "чехия": "CZ",
    "south korea": "KR", "korea, republic of": "KR", "южная корея": "KR",
    "north macedonia": "MK", "северная македония": "MK", "macedonia": "MK",
    "sri lanka": "LK", "шри-ланка": "LK", "sri-lanka": "LK",
    "grenada": "GD", "гренада": "GD", "israel": "IL", "израиль": "IL", "израэль": "IL",
    "cyprus": "CY", "кипр": "CY", "singapore": "SG", "сингапур": "SG",
    "france": "FR", "франция": "FR", "poland": "PL", "польша": "PL", "sweden": "SE", "швеция": "SE",
    "finland": "FI", "финляндия": "FI", "norway": "NO", "норвегия": "NO", "denmark": "DK", "дания": "DK",
    "spain": "ES", "испания": "ES", "italy": "IT", "италия": "IT", "switzerland": "CH", "швейцария": "CH",
    "austria": "AT", "австрия": "AT", "belgium": "BE", "бельгия": "BE", "ireland": "IE", "ирландия": "IE",
    "romania": "RO", "румыния": "RO", "bulgaria": "BG", "болгария": "BG", "greece": "GR", "греция": "GR",
    "ukraine": "UA", "украина": "UA", "latvia": "LV", "латвия": "LV", "lithuania": "LT", "литва": "LT",
    "estonia": "EE", "эстония": "EE", "serbia": "RS", "сербия": "RS", "croatia": "HR", "хорватия": "HR",
    "slovakia": "SK", "словакия": "SK", "slovenia": "SI", "словения": "SI", "portugal": "PT", "португалия": "PT",
    "japan": "JP", "япония": "JP", "china": "CN", "китай": "CN", "hong kong": "HK", "гонконг": "HK",
    "taiwan": "TW", "тайвань": "TW", "india": "IN", "индия": "IN", "indonesia": "ID", "индонезия": "ID",
    "thailand": "TH", "таиланд": "TH", "vietnam": "VN", "вьетнам": "VN", "philippines": "PH", "филиппины": "PH",
    "malaysia": "MY", "малайзия": "MY", "brazil": "BR", "бразилия": "BR", "canada": "CA", "канада": "CA",
    "australia": "AU", "австралия": "AU", "new zealand": "NZ", "новая зеландия": "NZ", "south africa": "ZA", "юар": "ZA",
    "kazakhstan": "KZ", "казахстан": "KZ", "armenia": "AM", "армения": "AM", "azerbaijan": "AZ", "азербайджан": "AZ",
    "georgia": "GE", "грузия": "GE", "uzbekistan": "UZ", "узбекистан": "UZ", "belarus": "BY", "беларусь": "BY",
    "moldova": "MD", "молдова": "MD", "mexico": "MX", "мексика": "MX", "argentina": "AR", "аргентина": "AR",
    "chile": "CL", "чили": "CL", "iceland": "IS", "исландия": "IS", "luxembourg": "LU", "люксембург": "LU",
    "europe": "EU", "европа": "EU", "eu": "EU", "евросоюз": "EU",
}

# Fallback for cases where the database provides a code but not a localized name.
FALLBACK_NAMES = {
    "EU": "Europe", "XK": "Kosovo", "GB": "United Kingdom", "US": "United States",
    "KR": "South Korea", "RU": "Russia", "CZ": "Czechia", "TW": "Taiwan",
}

# TLD inference is a last-resort hint only, used when IP geolocation and source labels fail.
# Generic/personalized ccTLDs such as .io, .ai, .me, .tv, .co are deliberately excluded.
COUNTRY_TLDS = {
    "ru", "de", "nl", "gb", "uk", "fr", "es", "it", "pl", "cz", "sk", "se", "no", "fi", "dk", "ch", "at", "be", "lu",
    "ua", "ro", "bg", "gr", "tr", "rs", "hr", "si", "lt", "lv", "ee", "pt", "ie", "is", "cy", "sg", "jp", "kr", "in", "id",
    "th", "vn", "ph", "my", "cn", "hk", "tw", "br", "ar", "cl", "mx", "ca", "us", "au", "nz", "za", "il", "kz", "am", "az",
    "ge", "uz", "by", "md", "gd", "lk", "mk", "ae", "sa", "qa", "bh", "om", "pk", "bd", "np", "kh", "la", "mn", "ng", "ke", "eg",
}


def _country_name(code: str, preferred: str = "") -> str:
    code = code.upper()
    if preferred.strip():
        return preferred.strip()
    if code in FALLBACK_NAMES:
        return FALLBACK_NAMES[code]
    if pycountry is not None:
        item = pycountry.countries.get(alpha_2=code)
        if item:
            return getattr(item, "common_name", None) or item.name
    if code == "XK":
        return "Kosovo"
    return "Unknown country"


def flag_for_code(code: str) -> str:
    code = code.upper()
    if code == "EU":
        return "🇪🇺"
    if not re.fullmatch(r"[A-Z]{2}", code):
        return "🌐"
    return "".join(chr(127397 + ord(letter)) for letter in code)


def _flag_code(text: str) -> str | None:
    for match in re.finditer(r"[\U0001F1E6-\U0001F1FF]{2}", text):
        code = "".join(chr(ord(ch) - 127397) for ch in match.group(0))
        if code == "EU" or code == "XK" or (pycountry is not None and pycountry.countries.get(alpha_2=code)):
            return code
    return None


def country_from_label(text: str, method: str = "label") -> Country | None:
    if not text:
        return None
    code = _flag_code(text)
    if code:
        # Keep a known ISO/country flag's canonical English country name rather than a potentially misleading fragment.
        return Country(code, _country_name(code), method)
    raw_text = unquote(text)
    # Explicit standalone ISO alpha-2 markers such as `SG-01` or `DE | Frankfurt`
    # are useful fallbacks when no IP database record is available. Do not infer from
    # arbitrary lowercase substrings (for example the word "node").
    for token in re.findall(r"(?<![A-Za-z0-9])[A-Z]{2}(?![A-Za-z0-9])", raw_text):
        code = {"UK": "GB"}.get(token, token)
        if code == "EU" or code == "XK" or (pycountry is not None and pycountry.countries.get(alpha_2=code)):
            return Country(code, _country_name(code), method)
    normalized = re.sub(r"[_|•]+", " ", raw_text).casefold()
    normalized = re.sub(r"[^\w\s.-]", " ", normalized, flags=re.UNICODE)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    # Exact aliases first, longest names first to avoid e.g. "Georgia" inside another label.
    for alias, code in sorted(ALIASES.items(), key=lambda p: len(p[0]), reverse=True):
        if re.search(r"(?<![\w])" + re.escape(alias) + r"(?![\w])", normalized):
            return Country(code, _country_name(code), method)
    if pycountry is not None:
        countries = list(pycountry.countries)
        names: list[tuple[str, str]] = []
        for item in countries:
            for attr in ("common_name", "official_name", "name"):
                value = getattr(item, attr, None)
                if value:
                    names.append((value.casefold(), item.alpha_2))
        for alias, code in sorted(set(names), key=lambda p: len(p[0]), reverse=True):
            if len(alias) < 4:
                continue
            if re.search(r"(?<![\w])" + re.escape(alias) + r"(?![\w])", normalized):
                return Country(code, _country_name(code), method)
    return None


class CountryResolver:
    """Fast local MMDB lookups plus transparent name/TLD fallbacks."""
    def __init__(self, database_path: Path | str | None = None):
        self.database_path = Path(database_path) if database_path else None
        self.reader = None
        if self.database_path and self.database_path.is_file():
            if maxminddb is None:
                raise RuntimeError("maxminddb is required to read the DB-IP country database")
            self.reader = maxminddb.open_database(str(self.database_path))

    @property
    def available(self) -> bool:
        return self.reader is not None

    def lookup_ip(self, ip_text: str) -> Country | None:
        try:
            ip = ipaddress.ip_address(str(ip_text).strip().split("%", 1)[0])
        except ValueError:
            return None
        if not ip.is_global or self.reader is None:
            return None
        try:
            record = self.reader.get(ip.compressed) or {}
        except Exception:
            return None
        for key in ("country", "registered_country", "represented_country"):
            block = record.get(key) or {}
            code = str(block.get("iso_code") or "").upper()
            if re.fullmatch(r"[A-Z]{2}", code):
                names = block.get("names") or {}
                return Country(code, _country_name(code, str(names.get("en") or "")), "ip", ip.compressed)
        return None

    def resolve(self, ip_candidates: Iterable[str], labels: Iterable[str], host: str = "") -> Country | None:
        seen_ips: set[str] = set()
        for raw in ip_candidates:
            raw = str(raw or "").strip()
            if not raw or raw in seen_ips:
                continue
            seen_ips.add(raw)
            country = self.lookup_ip(raw)
            if country:
                return country
        for label in labels:
            country = country_from_label(str(label or ""), "label")
            if country:
                return country
        # Hostname ccTLD inference only comes after IP and explicit source/config labels.
        try:
            hostname = str(host).rstrip(".").split(".")
            tld = hostname[-1].casefold() if len(hostname) > 1 else ""
            if tld in COUNTRY_TLDS:
                code = {"uk": "GB"}.get(tld, tld.upper())
                return Country(code, _country_name(code), "hostname_tld")
        except Exception:
            pass
        return None

    def close(self) -> None:
        if self.reader is not None:
            try:
                self.reader.close()
            except Exception:
                pass
            self.reader = None


def set_node_name(node: Any, country: Country) -> str:
    """Set client-visible naming for URI types with both outer and embedded names."""
    import base64
    import json
    from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

    label = f"{flag_for_code(country.code)} {country.name} • AeryxVPN"
    parsed = urlsplit(node.uri)

    if parsed.scheme.lower() == "vmess":
        # VMess uses the JSON `ps` field inside Base64; some clients ignore an outer #fragment.
        try:
            from .models import _decode_base64
            payload = _decode_base64((parsed.netloc + parsed.path).strip())
            value = json.loads(payload.decode("utf-8-sig"))
            if isinstance(value, dict):
                value["ps"] = label
                encoded = base64.urlsafe_b64encode(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
                node.uri = "vmess://" + encoded
                parsed = urlsplit(node.uri)
        except Exception:
            # If a VMess blob is malformed here, do not corrupt it; the outer fragment
            # still provides a fallback name to clients that support ordinary fragments.
            pass
    elif parsed.scheme.lower() == "ssr":
        # SSR remarks are carried inside its Base64 payload in addition to an outer fragment.
        try:
            from .models import _decode_base64
            decoded = _decode_base64((parsed.netloc + parsed.path).strip()).decode("utf-8", "replace")
            head, sep, query = decoded.partition("/?")
            pairs = [(key, value) for key, value in parse_qsl(query, keep_blank_values=True) if key.lower() != "remarks"]
            remarks = base64.urlsafe_b64encode(label.encode("utf-8")).decode("ascii").rstrip("=")
            pairs.append(("remarks", remarks))
            rebuilt = head + "/?" + urlencode(pairs, doseq=True)
            encoded = base64.urlsafe_b64encode(rebuilt.encode("utf-8")).decode("ascii").rstrip("=")
            node.uri = "ssr://" + encoded
            parsed = urlsplit(node.uri)
        except Exception:
            pass

    # Percent-encode the entire fragment so spaces, bullet and emoji remain URI-safe.
    safe_uri = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, quote(label, safe="-._~")))
    node.uri = safe_uri
    node.name = label
    return label
