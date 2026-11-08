from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "AeryxVPN-core-installer/3.0",
    "X-GitHub-Api-Version": "2022-11-28",
}
RETRYABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}


def github_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def is_rate_limit_error(exc: urllib.error.HTTPError) -> bool:
    reason = str(exc.reason or "").lower()
    remaining = exc.headers.get("X-RateLimit-Remaining", "") if exc.headers else ""
    body = ""
    try:
        body = exc.read(4096).decode("utf-8", errors="replace").lower()
    except OSError:
        pass
    return exc.code == 403 and (
        "rate limit" in reason or "rate limit" in body or remaining == "0"
    )


def retryable_http_error(exc: urllib.error.HTTPError) -> bool:
    return exc.code in RETRYABLE_STATUS_CODES or is_rate_limit_error(exc)


def retry_delay(exc: urllib.error.HTTPError | None, attempt: int) -> int:
    headers = exc.headers if exc is not None else None
    if headers:
        retry_after = headers.get("Retry-After")
        if retry_after:
            try:
                return max(1, min(60, int(retry_after)))
            except (TypeError, ValueError):
                pass
        reset_at = headers.get("X-RateLimit-Reset")
        remaining = headers.get("X-RateLimit-Remaining")
        if reset_at and remaining == "0":
            try:
                return max(1, min(60, int(reset_at) - int(time.time()) + 1))
            except (TypeError, ValueError):
                pass
    return min(2 ** (attempt - 1), 16)


def get_json(url: str, attempts: int = 4) -> dict:
    """Fetch GitHub release metadata using the Actions token and retry transient API failures."""
    token = github_token()
    headers = dict(API_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        print(
            "[WARN] GITHUB_TOKEN is unavailable; GitHub API requests use the low unauthenticated quota.",
            file=sys.stderr,
        )

    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if not retryable_http_error(exc) or attempt >= attempts:
                raise
            delay = retry_delay(exc, attempt)
            print(
                f"[WARN] GitHub API HTTP {exc.code} while resolving release metadata; "
                f"retry {attempt}/{attempts} in {delay}s",
                file=sys.stderr,
            )
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt >= attempts:
                raise
            delay = min(2 ** (attempt - 1), 16)
            print(
                f"[WARN] GitHub API network error ({type(exc).__name__}); "
                f"retry {attempt}/{attempts} in {delay}s",
                file=sys.stderr,
            )
            time.sleep(delay)
    raise RuntimeError(f"Could not fetch GitHub API response: {url}")


def download(
    url: str,
    dest: Path,
    max_bytes: int = 250 * 1024 * 1024,
    attempts: int = 4,
    expected_digest: str | None = None,
) -> None:
    """Download an official release asset atomically and optionally verify its SHA-256."""
    partial = dest.with_name(dest.name + ".part")
    token = github_token()
    headers = {
        "User-Agent": "AeryxVPN-core-installer/3.0",
        "Accept": "application/octet-stream",
    }
    if token and urlsplit(url).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"

    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, headers=headers)
        digest = hashlib.sha256()
        total = 0
        try:
            with urllib.request.urlopen(request, timeout=90) as response, partial.open("wb") as file:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(f"download exceeds safety limit ({max_bytes} bytes)")
                    digest.update(chunk)
                    file.write(chunk)

            if total == 0:
                raise ValueError("downloaded release asset is empty")

            if expected_digest and expected_digest.startswith("sha256:"):
                expected = expected_digest.partition(":")[2].lower()
                actual = digest.hexdigest()
                if actual != expected:
                    raise ValueError(
                        f"SHA-256 mismatch for {dest.name}: expected {expected}, got {actual}"
                    )

            os.replace(partial, dest)
            return
        except urllib.error.HTTPError as exc:
            partial.unlink(missing_ok=True)
            if not retryable_http_error(exc) or attempt >= attempts:
                raise
            delay = retry_delay(exc, attempt)
            print(
                f"[WARN] HTTP {exc.code} while downloading release asset; "
                f"retry {attempt}/{attempts} in {delay}s",
                file=sys.stderr,
            )
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError) as exc:
            partial.unlink(missing_ok=True)
            if attempt >= attempts:
                raise
            delay = min(2 ** (attempt - 1), 16)
            print(
                f"[WARN] Network error while downloading release asset ({type(exc).__name__}); "
                f"retry {attempt}/{attempts} in {delay}s",
                file=sys.stderr,
            )
            time.sleep(delay)
        except Exception:
            partial.unlink(missing_ok=True)
            raise


def detect_target() -> tuple[str, str]:
    system_name = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {
        "windows": "windows",
        "linux": "linux",
        "darwin": "darwin",
    }.get(system_name)
    arch = (
        "arm64"
        if machine in {"arm64", "aarch64"}
        else "amd64"
        if machine in {"x86_64", "amd64", "x64"}
        else "386"
        if machine in {"i386", "i686", "x86"}
        else ""
    )
    if not os_name or not arch:
        raise SystemExit(f"Unsupported platform/architecture: {system_name}/{machine}")
    return os_name, arch


def asset_by_patterns(assets: list[dict], patterns: list[str]) -> dict | None:
    for pattern in patterns:
        for asset in assets:
            if re.search(pattern, asset.get("name", ""), re.I):
                return asset
    return None


def install_archive(
    owner_repo: str,
    tool: str,
    os_name: str,
    arch: str,
    tools_dir: Path,
) -> dict:
    release = get_json(f"https://api.github.com/repos/{owner_repo}/releases/latest")
    tag = release.get("tag_name", "unknown")
    assets = release.get("assets", [])

    if tool == "xray":
        if os_name == "windows":
            patterns = [
                r"^Xray-windows-64\.zip$"
                if arch == "amd64"
                else rf"^Xray-windows-{arch}\.zip$"
            ]
        elif os_name == "linux":
            patterns = [
                r"^Xray-linux-64\.zip$"
                if arch == "amd64"
                else rf"^Xray-linux-{arch}\.zip$"
            ]
        elif os_name == "darwin":
            patterns = [
                r"^Xray-macos-arm64-v8a\.zip$"
                if arch == "arm64"
                else r"^Xray-macos-64\.zip$"
            ]
        else:
            patterns = []
    else:
        platform_arch = {
            "windows": {
                "amd64": "windows-amd64",
                "arm64": "windows-arm64",
                "386": "windows-386",
            },
            "linux": {
                "amd64": "linux-amd64",
                "arm64": "linux-arm64",
                "386": "linux-386",
            },
            "darwin": {"amd64": "darwin-amd64", "arm64": "darwin-arm64"},
        }
        suffix = platform_arch.get(os_name, {}).get(arch)
        patterns = (
            [
                rf"^sing-box-[0-9][^-]*-{re.escape(suffix)}\.zip$",
                rf"^sing-box-[0-9][^-]*-{re.escape(suffix)}\.tar\.gz$",
            ]
            if suffix
            else []
        )

    asset = asset_by_patterns(assets, patterns)
    if asset is None:
        needle = f"{os_name}-{arch}".lower()
        matches = [
            candidate
            for candidate in assets
            if needle in candidate.get("name", "").lower()
            and candidate.get("name", "").lower().endswith((".zip", ".tar.gz"))
        ]
        if tool == "xray":
            matches = [
                candidate
                for candidate in matches
                if candidate.get("name", "").lower().startswith("xray-")
            ]
        asset = matches[0] if matches else None

    if asset is None:
        available = ", ".join(item.get("name", "?") for item in assets)
        raise RuntimeError(
            f"Could not find {tool} asset for {os_name}/{arch} in {owner_repo} {tag}. "
            f"Available assets: {available}"
        )

    name = asset["name"]
    browser_url = asset.get("browser_download_url")
    asset_id = asset.get("id")
    if not browser_url and not asset_id:
        raise RuntimeError(f"Release asset {name} has no downloadable URL or asset ID")

    tools_dir.mkdir(parents=True, exist_ok=True)
    suffix = ".zip" if name.lower().endswith(".zip") else ".tar.gz"
    archive = tools_dir / f"{tool}-download{suffix}"
    digest = asset.get("digest")
    print(f"Resolving {tool}: {owner_repo} {tag} / {name}")

    # Prefer the authenticated Release Asset API. This avoids relying on the
    # unauthenticated releases/latest API and gives us the official asset digest.
    api_url = (
        f"https://api.github.com/repos/{owner_repo}/releases/assets/{asset_id}"
        if asset_id
        else None
    )
    if github_token() and api_url:
        try:
            print(f"Downloading {tool} through authenticated GitHub Release Asset API")
            download(api_url, archive, expected_digest=digest)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as api_error:
            if not browser_url:
                raise
            print(
                f"[WARN] Release Asset API download failed ({type(api_error).__name__}: "
                f"{api_error}); falling back to the official browser download URL.",
                file=sys.stderr,
            )
            download(browser_url, archive, expected_digest=digest)
    else:
        if not browser_url:
            raise RuntimeError(
                f"Cannot download {name}: GITHUB_TOKEN is missing and no browser URL is available"
            )
        print(
            "[WARN] GITHUB_TOKEN is missing; using the unauthenticated browser download URL.",
            file=sys.stderr,
        )
        download(browser_url, archive, expected_digest=digest)

    staging = tools_dir / f".{tool}-extract"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir()
    try:
        if suffix == ".zip":
            with zipfile.ZipFile(archive) as zip_file:
                for item in zip_file.infolist():
                    target = (staging / item.filename).resolve()
                    if staging.resolve() not in target.parents and target != staging.resolve():
                        raise ValueError("unsafe archive path")
                zip_file.extractall(staging)
        else:
            with tarfile.open(archive, "r:gz") as tar_file:
                for item in tar_file.getmembers():
                    target = (staging / item.name).resolve()
                    if staging.resolve() not in target.parents and target != staging.resolve():
                        raise ValueError("unsafe archive path")
                tar_file.extractall(staging, filter="data")

        binary_names = (
            {"xray", "xray.exe"}
            if tool == "xray"
            else {"sing-box", "sing-box.exe"}
        )
        binary = next(
            (path for path in staging.rglob("*") if path.is_file() and path.name in binary_names),
            None,
        )
        if binary is None:
            raise RuntimeError(f"{tool} executable not found in {name}")

        destination = tools_dir / (
            "xray.exe"
            if os_name == "windows" and tool == "xray"
            else "sing-box.exe"
            if os_name == "windows"
            else tool
        )
        shutil.copy2(binary, destination)
        if os_name != "windows":
            destination.chmod(
                destination.stat().st_mode
                | stat.S_IXUSR
                | stat.S_IXGRP
                | stat.S_IXOTH
            )

        return {
            "repository": owner_repo,
            "version": tag,
            "asset": name,
            "binary": destination.name,
            "digest": digest,
            "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        archive.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Install stable Xray-core and sing-box binaries from official GitHub releases"
        )
    )
    parser.add_argument("--platform", choices=("windows", "linux", "darwin"), default=None)
    parser.add_argument("--arch", choices=("amd64", "arm64", "386"), default=None)
    parser.add_argument("--tools-dir", type=Path, default=ROOT / "tools")
    args = parser.parse_args()

    auto_os, auto_arch = detect_target()
    os_name = args.platform or auto_os
    arch = args.arch or auto_arch
    if (os_name, arch) == ("darwin", "386"):
        raise SystemExit("Unsupported target: macOS 32-bit is not supported")

    token_available = bool(github_token())
    print(
        "GitHub Releases API authentication: "
        + ("GITHUB_TOKEN available" if token_available else "not available")
    )

    metadata = {}
    failures = []
    targets = (("xray", "XTLS/Xray-core"), ("sing-box", "SagerNet/sing-box"))

    for key, repository in targets:
        expected = args.tools_dir / (
            "xray.exe"
            if os_name == "windows" and key == "xray"
            else "sing-box.exe"
            if os_name == "windows"
            else key
        )
        try:
            metadata[key] = install_archive(repository, key, os_name, arch, args.tools_dir)
        except Exception as exc:
            if isinstance(exc, urllib.error.HTTPError):
                detail = f"HTTP {exc.code} {exc.reason}"
            elif isinstance(exc, urllib.error.URLError):
                detail = f"network error: {exc.reason}"
            else:
                detail = f"{type(exc).__name__}: {exc}"
            failures.append(f"{key}: {detail}")
            if expected.is_file():
                metadata[key] = {
                    "binary": expected.name,
                    "version": "existing_not_updated",
                    "warning": detail,
                }
            print(
                f"[WARN] Could not update {key} from its official release: {detail}",
                file=sys.stderr,
            )

    args.tools_dir.mkdir(parents=True, exist_ok=True)
    versions_file = args.tools_dir / "core-versions.json"
    versions_file.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metadata, ensure_ascii=False, indent=2))

    required_binaries = {
        "xray": args.tools_dir / ("xray.exe" if os_name == "windows" else "xray"),
        "sing-box": args.tools_dir / ("sing-box.exe" if os_name == "windows" else "sing-box"),
    }
    missing = [
        name for name, path in required_binaries.items() if not path.is_file() or path.stat().st_size == 0
    ]
    if missing:
        details = "; ".join(failures) if failures else "no additional download diagnostics"
        raise SystemExit(
            "Required official core binary/binaries missing or empty: "
            + ", ".join(missing)
            + ". Stopping before parsing; both Xray and sing-box are required. "
            + details
        )
    if failures:
        print("[WARN] Some cores were not updated: " + ", ".join(failures), file=sys.stderr)


if __name__ == "__main__":
    main()
