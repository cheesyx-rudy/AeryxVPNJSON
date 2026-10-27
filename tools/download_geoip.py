#!/usr/bin/env python3
"""Download and validate the latest available monthly DB-IP Lite country MMDB."""
from __future__ import annotations

import argparse
import gzip
import hashlib
from pathlib import Path
import sys
import tempfile
from datetime import datetime, timezone

import maxminddb
import requests

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "output" / "dbip-country-lite.mmdb"
MAX_GZIP_BYTES = 20 * 1024 * 1024
MAX_DB_BYTES = 50 * 1024 * 1024


def month_candidates(now: datetime | None = None, count: int = 5) -> list[str]:
    now = now or datetime.now(timezone.utc)
    year, month = now.year, now.month
    values = []
    for _ in range(count):
        values.append(f"{year:04d}-{month:02d}")
        month -= 1
        if month == 0:
            year -= 1
            month = 12
    return values


def download_database(output: Path, now: datetime | None = None) -> tuple[str, str]:
    output.parent.mkdir(parents=True, exist_ok=True)
    errors = []
    for release in month_candidates(now):
        url = f"https://download.db-ip.com/free/dbip-country-lite-{release}.mmdb.gz"
        try:
            with requests.get(url, timeout=(12, 45), stream=True, headers={"User-Agent": "AeryxJSON-Parser/1.0"}) as response:
                if response.status_code == 404:
                    errors.append(f"{release}: not published yet")
                    continue
                response.raise_for_status()
                with tempfile.NamedTemporaryFile(prefix="dbip-", suffix=".gz", delete=False) as tmp:
                    gz_path = Path(tmp.name)
                    total = 0
                    for chunk in response.iter_content(128 * 1024):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > MAX_GZIP_BYTES:
                            raise ValueError("compressed database exceeds size limit")
                        tmp.write(chunk)
            candidate = output.with_suffix(".mmdb.tmp")
            try:
                total = 0
                with gzip.open(gz_path, "rb") as source, candidate.open("wb") as target:
                    while True:
                        chunk = source.read(256 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_DB_BYTES:
                            raise ValueError("decompressed database exceeds size limit")
                        target.write(chunk)
                with maxminddb.open_database(str(candidate)) as reader:
                    record = reader.get("8.8.8.8") or {}
                    country = record.get("country") or record.get("registered_country") or {}
                    if not country.get("iso_code"):
                        raise ValueError("database validation failed: 8.8.8.8 has no country record")
                candidate.replace(output)
                digest = hashlib.sha256(output.read_bytes()).hexdigest()
                return release, digest
            finally:
                try:
                    gz_path.unlink(missing_ok=True)
                except Exception:
                    pass
                try:
                    candidate.unlink(missing_ok=True)
                except Exception:
                    pass
        except Exception as exc:
            errors.append(f"{release}: {type(exc).__name__}: {str(exc)[:180]}")
    raise RuntimeError("Could not download a valid DB-IP Lite country database; " + " | ".join(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        release, digest = download_database(args.output)
        print(f"DB-IP Lite country database loaded: {release}")
        print(f"Database path: {args.output}")
        print(f"SHA-256: {digest}")
        print("Data attribution: DB-IP.com (CC BY 4.0) — https://db-ip.com")
        return 0
    except Exception as exc:
        print(f"::error::GeoIP database setup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
