from __future__ import annotations

import io
import json
import os
import time
import zipfile
from pathlib import Path
from typing import Any

import requests


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing configuration: {name}")
    return value


def local_class(status: str) -> str:
    value = (status or "").lower()
    if value.startswith("proxy_ok"):
        return "working"
    if value.startswith("proxy_degraded"):
        return "degraded"
    if value.startswith("proxy_unstable"):
        return "unstable"
    if value in {"not_checkable", "unsupported"}:
        return "unsupported"
    if value in {"not_checked", "validation_not_started"}:
        return "not_checked"
    if value == "proxy_duplicate_core":
        return "duplicate"
    return "failed"


def write_unavailable(report_path: Path, code: str) -> None:
    if not report_path.is_file():
        return
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["moshub_validation"] = {
            "status": "unavailable",
            "reason_code": code,
            "message": "Mos.Hub did not return a report; local validation and publication are unchanged.",
        }
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except Exception:
        pass


def api_request(method: str, url: str, headers: dict[str, str], **kwargs: Any) -> requests.Response:
    response = requests.request(method, url, headers=headers, timeout=30, **kwargs)
    if not response.ok:
        raise RuntimeError(f"Mos.Hub API returned HTTP {response.status_code}")
    return response


def download_job_artifact(base: str, project_id: str, job_id: int, token: str) -> bytes:
    url = f"{base}/projects/{project_id}/jobs/{job_id}/artifacts"
    response = requests.get(
        url, headers={"PRIVATE-TOKEN": token}, timeout=60, allow_redirects=False
    )
    if response.status_code in {301, 302, 303, 307, 308}:
        location = response.headers.get("Location")
        if not location:
            raise RuntimeError("Mos.Hub artifact redirect has no download URL")
        # Do not forward the project token to the external object-storage URL.
        response = requests.get(location, timeout=90, allow_redirects=True)
    if response.status_code != 200:
        raise RuntimeError(f"Mos.Hub artifact download returned HTTP {response.status_code}")
    if not response.content or len(response.content) > 50 * 1024 * 1024:
        raise RuntimeError("Mos.Hub artifact is empty or exceeds 50 MiB")
    return response.content


def extract_result(data: bytes) -> dict[str, Any]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = [
            item for item in archive.infolist()
            if not item.is_dir() and Path(item.filename).name == "moshub-result.json"
        ]
        if len(members) != 1 or members[0].file_size > 20 * 1024 * 1024:
            raise RuntimeError("Mos.Hub artifact must contain exactly one result JSON")
        result = json.loads(archive.read(members[0]).decode("utf-8"))
    if not isinstance(result, dict) or result.get("schema_version") != 1:
        raise RuntimeError("unsupported Mos.Hub result schema")
    return result


def merge_report(
    report_path: Path,
    result: dict[str, Any],
    request_id: str,
    parser_kind: str,
) -> None:
    if result.get("request_id") != request_id or result.get("parser_kind") != parser_kind:
        raise RuntimeError("Mos.Hub result does not match this parser run")
    records = result.get("results")
    if not isinstance(records, list):
        raise RuntimeError("Mos.Hub result has no results array")

    remote: dict[str, dict[str, Any]] = {}
    for item in records:
        if not isinstance(item, dict):
            continue
        key = str(item.get("candidate_id", ""))
        if len(key) == 64 and key not in remote:
            remote[key] = item

    report = (
        json.loads(report_path.read_text(encoding="utf-8"))
        if report_path.is_file()
        else {}
    )
    validation = report.setdefault("validation", {})
    local_nodes = validation.get("node_results", [])
    comparisons = {
        "both_working": 0,
        "github_only_working": 0,
        "moshub_only_working": 0,
        "neither_working": 0,
        "unmatched": 0,
    }
    matched = 0
    if isinstance(local_nodes, list):
        for node in local_nodes:
            if not isinstance(node, dict):
                continue
            other = remote.get(str(node.get("candidate_id", "")))
            if other is None:
                continue
            matched += 1
            local_status = local_class(str(node.get("status", "")))
            remote_status = str(other.get("status", "unknown")).lower()
            node["moshub_status"] = remote_status
            node["moshub_confidence"] = other.get("confidence", "unknown")
            node["moshub_reason_code"] = other.get("reason_code", "")
            if local_status == "working" and remote_status == "working":
                comparisons["both_working"] += 1
            elif local_status == "working":
                comparisons["github_only_working"] += 1
            elif remote_status == "working":
                comparisons["moshub_only_working"] += 1
            else:
                comparisons["neither_working"] += 1
    comparisons["unmatched"] = max(0, len(remote) - matched)
    report["moshub_validation"] = {
        "status": "completed",
        "request_id": request_id,
        "parser_kind": parser_kind,
        "core_version": result.get("core_version"),
        "runner_platform": result.get("runner_platform"),
        "candidate_count": result.get("candidate_count", len(records)),
        "result_count": len(records),
        "matched_with_github": matched,
        "remote_status_counts": result.get("status_counts", {}),
        "comparison": comparisons,
        "elapsed_seconds": result.get("elapsed_seconds"),
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser_kind = required("MOSHUB_PARSER_KIND")
    if parser_kind not in {"private", "json"}:
        raise RuntimeError("MOSHUB_PARSER_KIND must be private or json")
    request_id = required("MOSHUB_REQUEST_ID")
    if not request_id.replace("-", "").replace("_", "").isalnum() or len(request_id) > 100:
        raise RuntimeError("invalid request ID")

    report_path = Path(required("MOSHUB_LOCAL_REPORT"))
    try:
        base = required("MOSHUB_API_URL").rstrip("/")
        project_id = required("MOSHUB_PROJECT_ID")
        trigger_token = required("MOSHUB_TRIGGER_TOKEN")
        read_token = required("MOSHUB_READ_API_TOKEN")
        artifact_id = required("MOSHUB_ARTIFACT_ID")
        artifact_name = required("MOSHUB_ARTIFACT_NAME")
        github_repo = required("GITHUB_REPOSITORY")
        github_run_id = required("GITHUB_RUN_ID")

        if not all(value.isdigit() for value in (project_id, artifact_id, github_run_id)):
            raise RuntimeError("project, artifact and GitHub run IDs must be numeric")
        if artifact_name != f"moshub-input-{parser_kind}-{request_id}":
            raise RuntimeError("artifact name does not match parser kind and request ID")

        trigger_data = {
            "token": trigger_token,
            "ref": "main",
            "variables[PARSER_KIND]": parser_kind,
            "variables[REQUEST_ID]": request_id,
            "variables[GH_REPO]": github_repo,
            "variables[GH_RUN_ID]": github_run_id,
            "variables[GH_ARTIFACT_ID]": artifact_id,
            "variables[GH_ARTIFACT_NAME]": artifact_name,
        }
        trigger = api_request(
            "POST",
            f"{base}/projects/{project_id}/trigger/pipeline",
            {"Content-Type": "application/x-www-form-urlencoded"},
            data=trigger_data,
        ).json()
        pipeline_id = int(trigger["id"])
        print(f"Mos.Hub accepted pipeline {pipeline_id} for {parser_kind}")

        api_headers = {"PRIVATE-TOKEN": read_token}
        deadline = time.monotonic() + 2400
        while time.monotonic() < deadline:
            pipeline = api_request(
                "GET",
                f"{base}/projects/{project_id}/pipelines/{pipeline_id}",
                api_headers,
            ).json()
            status = str(pipeline.get("status", "unknown"))
            print(f"Mos.Hub pipeline {pipeline_id}: {status}")
            if status in {"success", "failed", "canceled", "skipped"}:
                break
            time.sleep(10)
        else:
            raise RuntimeError("Mos.Hub pipeline exceeded the 40-minute wait limit")

        if pipeline.get("status") != "success":
            raise RuntimeError(f"Mos.Hub pipeline ended as {pipeline.get('status')}")

        jobs = api_request(
            "GET",
            f"{base}/projects/{project_id}/pipelines/{pipeline_id}/jobs?per_page=100",
            api_headers,
        ).json()
        job = next(
            (
                item for item in jobs
                if item.get("name") == "aeryx-validation-worker"
                and item.get("status") == "success"
            ),
            None,
        )
        if not job:
            raise RuntimeError("successful Worker job was not found")

        result = extract_result(
            download_job_artifact(base, project_id, int(job["id"]), read_token)
        )
        merge_report(report_path, result, request_id, parser_kind)
        Path("output").mkdir(exist_ok=True)
        Path("output/moshub-result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(
            "Mos.Hub validation complete: "
            f"{result.get('result_count', len(result.get('results', [])))} candidates; "
            f"status counts={json.dumps(result.get('status_counts', {}), sort_keys=True)}"
        )
    except Exception as exc:
        code = type(exc).__name__.lower()
        print(
            f"::warning::Mos.Hub secondary validation unavailable ({code}); "
            "local validation and publication will continue unchanged."
        )
        write_unavailable(report_path, code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
