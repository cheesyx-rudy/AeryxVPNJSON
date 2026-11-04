# AeryxVPN JSON Parser

**Current release:** 1.0.0  
**Validation engine:** AeryxVPN Core 0.8.0 (pinned immutable commit)

The parser collects supported subscription sources, extracts and deduplicates share links, resolves endpoints, validates proxy tunnels with Xray/sing-box, and builds the Happ-compatible `AeryxVPN.json` profile array.

## IP and subnet lists

The default feeds use focused address/subnet sources:

- AntiFilter resolved IP list: `ipresolve.lst`
- AntiFilter subnet list: `subnet.lst`
- Re-filter list: `ipsum.lst`
- AntiFilter community list: `community.lst`

Downloads are cached per feed. The default cache lifetime is 72 hours. IPv4 ranges broader than /24 and IPv6 ranges broader than /48 are ignored by default to reduce false positives from large hosting and CDN networks. Manual CIDRs can still be maintained in `config/manual-deny-cidrs.txt`.

A public feed match is recorded in diagnostics but does not reject a candidate before tunnel testing. In proxy mode, a node is included only after a positive Xray/sing-box tunnel result. A feed match cannot discard a tunnel-verified public endpoint; a matching node that does not pass tunnel validation is rejected. Endpoints whose DNS results are exclusively private, loopback, link-local, or otherwise non-global remain excluded from public output. TCP-only and no-check runs are diagnostic and cannot automatically replace the final subscription; `force_publish` is an explicit override.

The Core repository is private. Configure `AERYX_CORE_READ_TOKEN` as a read-only GitHub Actions secret for `cheesyx-rudy/AeryxVPN-Core`.

## Geolocation

Country lookup uses the local database first, then source/config labels and supported country-code host suffixes. When no reliable country is available, a validated node is placed in a separate `ZZ` / «Не определена» profile instead of being mislabeled as Europe or silently removed.

## Diagnostics and safety

The pipeline writes `output/engine/validation_report.json`, including feed status, cache use, matched CIDRs, validation status and rejection reason codes. Do not share raw proxy credentials or subscription URLs publicly.

The live subscription workflow is not run by pull requests. PRs execute offline tests; live generation remains an explicit workflow dispatch or main-branch release operation.

## Development

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python -m ruff check .
```
