# AeryxVPN Core

Shared Python library for the AeryxVPN URI and JSON subscription parsers.

> **Status: `0.2.0` — shared input adapters are ready; validation migration is in progress.**
> Core extracts share-URI subscriptions and parses Xray JSON, sing-box JSON, Clash JSON/YAML, and
> SIP008. Shared country resolution and Happ routing utilities are also included. Production Xray/sing-box checks have not yet been migrated, so do not replace the
> existing parser validation pipelines with this release.

## Architecture

- **Input adapters** convert share URI, Xray JSON, sing-box JSON, Clash JSON/YAML, and SIP008
  into `ProxyCandidate` objects.
- **Validation Engine** dispatches candidates to protocol-aware validators.
- **Output adapters** preserve each parser's output contract: ordinary share links for
  the URI parser and the existing Happ-compatible JSON schema for the JSON parser.
- **SourcePayload** retains original input data so unknown JSON fields are not silently
  discarded during conversion.

The Core is a library executed inside GitHub-hosted Actions runners. It is not a daemon,
web service, or always-on server.

## Development

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python -m ruff check .
```

## Versioning

Parser workflows should pin a Core release tag (for example `v0.2.0`) rather than track
`main`. Breaking public API changes require a major version once the integration API is
stable.

## Private repository access

The JSON parser repository is public, so its workflow must retrieve this private repository
using a narrowly scoped read-only credential stored as a GitHub Actions secret. Never put
a token in source code, workflow literals, URLs committed to Git, artifacts, or logs.
Do not expose the secret to workflows triggered by untrusted pull requests.


## Release 1.0.0

The JSON parser uses AeryxVPN Core 0.8.0 for protocol-aware tunnel validation. The
existing Happ-compatible JSON-array builder remains the output authority; validation
results do not reconstruct or rewrite source profile fields. The workflow pins the exact immutable AeryxVPN Core 0.8.0 commit by SHA and checks the installed wheel before running tests and generation.

The Core repository is private. Configure `AERYX_CORE_READ_TOKEN` as a read-only
Actions secret with access to `cheesyx-rudy/AeryxVPN-Core`.
