# Changelog

## Unreleased

- Replace broad mixed-purpose IP aggregates with focused AntiFilter and Re-filter blocked-IP/subnet feeds.
- Treat public-feed CIDR matches as validation flags: only nodes that fail tunnel validation are rejected for a blocklist match; a verified working tunnel is retained.
- Keep non-global-only endpoints out of the public subscription even if a local runner can reach them.
- Retain tunnel-verified candidates when geolocation is unavailable by assigning a dedicated `ZZ` / «Не определена» profile.
- Skip the live subscription-generation job on pull requests; PRs run offline CI only.


## 1.0.0 - 2026-11-04

- Integrated AeryxVPN Core 0.8.0 into proxy tunnel validation.
- Added a dedicated Core adapter that maps Core statuses to existing parser diagnostics.
- Kept the Happ JSON-array builder and publication schema unchanged.
- Added regression coverage for Core result mapping and URI preservation.
- Corrected package metadata to identify the JSON parser as its own distribution.


## 0.2.0 - 2026-11-04

- Added shared URI extraction utilities migrated from both parser repositories.
- Added `ShareURIAdapter` for raw and Base64-wrapped URI subscriptions.
- Added `StructuredJSONAdapter` for Xray, sing-box, Clash JSON, and SIP008 input.
- Added `ClashYAMLAdapter` using safe YAML parsing and the same structured-node path.
- Migrated the shared country resolver and Happ routing-profile utility into Core.
- Preserved the complete original JSON document and source node in each candidate payload.
- Added stable fingerprints that ignore display labels but retain transport/authentication differences.
- Added per-item parse diagnostics so one malformed node does not abort an entire subscription.
- Added regression tests for VLESS, VMess, Shadowsocks, Xray, sing-box, Clash JSON, and SIP008 adapters.

## 0.1.0 — foundation

- Добавлены общие доменные типы: протоколы, endpoint, исходные данные и модель кандидата.
- Добавлены типизированные результаты проверок и статусы валидации.
- Добавлен Validation Engine с диспетчеризацией по протоколам и ограничением конкурентности.
- Добавлены контракты входных и выходных адаптеров.
- Добавлены настройки на `pydantic-settings`, общий Loguru logger и CI workflow.
- Реальные проверки Xray/sing-box и миграция логики парсеров пока не входят в эту версию.
