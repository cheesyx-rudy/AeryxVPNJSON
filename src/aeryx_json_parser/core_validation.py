from __future__ import annotations

import asyncio
import time
from collections import Counter
from collections.abc import Callable

from aeryx_core import (
    ProbePolicy,
    ProbeTarget,
    ShareURIAdapter,
    StabilityPolicy,
    ValidationContext,
    ValidationStatus,
    create_validation_engine,
)
from aeryx_core.validation.redundancy import (
    group_similar_candidates,
    select_validated_candidates,
)

from .models import ProxyNode


def _provider_for(url: str) -> str:
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    providers = {
        "gstatic.com": "google",
        "cloudflare.com": "cloudflare",
        "msftconnecttest.com": "microsoft",
        "ipify.org": "ipify",
        "amazonaws.com": "amazon",
    }
    return next(
        (provider for domain, provider in providers.items()
         if host == domain or host.endswith(f".{domain}")),
        host,
    )


def _probe_targets(configured: list[tuple[str, set[int]]]) -> tuple[ProbeTarget, ...]:
    return tuple(
        ProbeTarget(
            url=url,
            accepted_statuses=frozenset(statuses),
            provider=_provider_for(url),
        )
        for url, statuses in configured
    )


def _core_status(result: object) -> tuple[str, str, str, int | None, int]:
    status = result.status
    reason_code = result.reason_code or status.value
    reason = reason_code
    confidence = result.confidence.value
    elapsed_ms = result.elapsed_ms

    if status is ValidationStatus.WORKING:
        return f"proxy_ok_{confidence}", reason, confidence, elapsed_ms, result.score or 0
    if status is ValidationStatus.DEGRADED:
        return "proxy_degraded", reason, confidence, elapsed_ms, result.score or 0
    if status is ValidationStatus.UNSUPPORTED:
        return "not_checkable", reason, confidence, elapsed_ms, result.score or 0
    if status is ValidationStatus.NOT_CHECKED:
        return "not_checked", reason, confidence, elapsed_ms, result.score or 0
    return "proxy_failed", reason, confidence, elapsed_ms, result.score or 0


def validate_nodes_with_core(
    nodes: list[ProxyNode],
    cores: dict[str, str],
    *,
    workers: int,
    deadline: float,
    per_node_timeout: float,
    targets: list[tuple[str, set[int]]],
    minimum_successes: int,
    require_independent_providers: bool,
    retry_single_success: bool,
    stability_samples: int = 2,
    engine_factory: Callable[..., object] = create_validation_engine,
    progress_callback: Callable[[int, int, dict[str, int]], None] | None = None,
) -> dict[str, int]:
    """Validate parsed share links through AeryxVPN Core without changing parser output data."""
    if not nodes:
        return {}

    probe_targets = _probe_targets(targets)
    engine = engine_factory(
        xray_binary=cores.get("xray"),
        sing_box_binary=cores.get("sing-box"),
        probe_policy=ProbePolicy(
            minimum_successes=minimum_successes,
            require_independent_providers=require_independent_providers,
            retry_single_success=retry_single_success,
            request_timeout_seconds=min(3.6, max(0.5, per_node_timeout / 2)),
        ),
        probe_targets=probe_targets,
        stability_policy=StabilityPolicy(
            sample_count=max(1, min(stability_samples, 5)),
            sample_interval_seconds=0.1,
        ),
    )
    adapter = ShareURIAdapter()
    candidates_by_fingerprint = {}
    candidate_nodes = {}

    for node in nodes:
        parsed = adapter.parse_with_report(node.uri, source_name=node.source)
        if not parsed.candidates:
            node.check_status = "not_checkable"
            issue = parsed.issues[0] if parsed.issues else None
            node.check_reason = issue.reason_code if issue else "core_uri_adapter_rejected"
            node.validation_confidence = "unknown"
            continue
        candidate = parsed.candidates[0]
        candidates_by_fingerprint[candidate.fingerprint] = candidate
        candidate_nodes[candidate.fingerprint] = node

    async def run_validation() -> dict[str, object]:
        semaphore = asyncio.Semaphore(max(1, min(workers, 32)))
        results: dict[str, object] = {}
        completed = 0
        counts: Counter[str] = Counter()

        async def validate_one(fingerprint: str, candidate: object) -> None:
            nonlocal completed
            async with semaphore:
                remaining = deadline - time.monotonic()
                budget = min(per_node_timeout, remaining)
                if budget <= 0:
                    result = None
                else:
                    context = ValidationContext(
                        run_id="aeryx-json-parser",
                        timeout_seconds=budget,
                    )
                    try:
                        result = await asyncio.wait_for(
                            engine.validate(candidate, context),
                            timeout=budget + 0.25,
                        )
                    except Exception as exc:
                        result = None
                        node = candidate_nodes[fingerprint]
                        node.check_reason = f"core_validation_{type(exc).__name__.lower()}"
                if result is not None:
                    results[fingerprint] = result
                    status, reason, confidence, elapsed, score = _core_status(result)
                    node = candidate_nodes[fingerprint]
                    node.check_status = status
                    node.check_reason = reason
                    node.validation_confidence = confidence
                    node.elapsed_ms = elapsed
                    node.validation_score = score
                    node.validation_votes = {
                        "core_tunnel_validation": 1 if status.startswith("proxy_ok") else -1,
                    }
                    checks = [
                        check for check in result.checks
                        if check.name in {"http_health_probes", "http_health_stability"}
                    ]
                    if checks:
                        details = checks[-1].details
                        node.successful_probe_count = int(
                            details.get("successful_samples", details.get("successful_count", 0))
                        )
                        node.probe_target_count = int(
                            details.get(
                                "planned_samples",
                                details.get("target_count", len(probe_targets)),
                            )
                        )
                else:
                    node = candidate_nodes[fingerprint]
                    node.check_status = "not_checked"
                    node.validation_confidence = "unknown"
                    node.elapsed_ms = None
                    if not node.check_reason:
                        node.check_reason = "validation_budget_exhausted"
                counts[node.check_status] += 1
                completed += 1
                if progress_callback:
                    progress_callback(completed, len(candidates_by_fingerprint), dict(counts))

        await asyncio.gather(*(
            validate_one(fingerprint, candidate)
            for fingerprint, candidate in candidates_by_fingerprint.items()
        ))
        return results

    results_by_fingerprint = asyncio.run(run_validation()) if candidates_by_fingerprint else {}

    # Match the strict publication policy used by the URI parser: only a fully
    # WORKING tunnel may be selected for automatic publication.
    grouping = group_similar_candidates(list(candidates_by_fingerprint.values()))
    selection = select_validated_candidates(grouping, results_by_fingerprint)
    group_ids = {
        candidate.fingerprint: group.group_id
        for group in grouping.groups
        for candidate in group.candidates
    }
    for fingerprint in selection.redundant_fingerprints:
        node = candidate_nodes[fingerprint]
        node.check_status = "proxy_duplicate_core"
        node.check_reason = (
            f"duplicate_account_variant:{group_ids[fingerprint]}: "
            "a higher-quality accepted sibling was retained"
        )

    counts: Counter[str] = Counter(node.check_status for node in nodes)
    return dict(counts)
