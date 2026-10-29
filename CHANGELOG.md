## 1.4.4 — remove unavailable custom geodata dependencies

- Removed `geosite:WH-DIRECT`, `geosite:STD-DIRECT`, `geoip:WH-DIRECT`, and `geoip:STD-DIRECT` rules from the profile template and all published profiles.
- Removed the DNS-over-HTTPS server entry restricted to those custom geosite selectors.
- Updated validation to check the real published profile (except Happ presentation-only `remarks`/`meta`) instead of silently stripping unsupported selectors from a temporary copy.
- Added a guard/test preventing custom geodata selectors from returning.
- Kept all proxy outbound/server parameters and the `burstObservatory` + `leastPing` balancer unchanged.
- Live server reachability was not re-tested as part of this change.

## 1.4.3 — remove unrelated IP routing rule

- Removed the dedicated `138.124.110.69` routing rule from the shared profile template and all 13 committed Happ/Xray profiles. Remaining routing rules and balancing settings are unchanged; no replacement was added.
- Updated subscription SHA-256 metadata and added a regression assertion to prevent the unrelated IP rule from returning.

## 1.4.2 — remove unrelated domain routing rule

- Removed `domain:flaregate.dedyn.io` from the shared Happ/Xray profile template and all currently published profiles because it is not an AeryxVPN-controlled domain. No replacement domain was invented.
- Updated the committed subscription SHA-256 metadata and added a regression assertion that generated profiles do not restore the rule.

## 1.4.1 — 2026-10-28

- Fixed CI Xray validation for the Happ reference profile: `WH-DIRECT` and `STD-DIRECT` are app-specific geodata selectors and their data files are not supplied to the official Xray binary. The validator now removes only those selectors from a temporary validation copy, leaving the published Happ JSON and its routing rules unchanged.
- Added sanitized Xray stderr diagnostics to validation failures, so the next error report includes the actual cause without dumping proxy credentials or complete configs.
- Added regression tests for custom-geodata handling and safe diagnostics.

## 1.4.5 — Xray TLS compatibility and per-node validation

- Stop emitting the removed `allowInsecure` option in generated Xray JSON and Xray validation configs; legacy sources now use normal certificate verification unless explicit modern pin/name settings are supplied.
- Apply the same certificate-verification policy to sing-box source probes so TLS nodes that only work by skipping certificate checks are not incorrectly accepted for Xray publication.
- Guard the generated Xray outbound itself against VLESS/VMess/Trojan using an unencrypted public literal IP.
- Keep `--xray tools/xray` in the workflow's JSON-builder step so each node is checked against the same official Xray core before country and Auto profiles are built.
- Added regression tests for TLS field removal, public-IP rejection and workflow prevalidation.

# Changelog

## 1.4.0 — sample-aligned Happ/Xray JSON profiles

- Replaced the simplified profile shell with `config/xray-profile-template.json`, based on the four supplied examples.
- Matches the sample root structure: API, burstObservatory, DNS, four inbounds, metrics/statistics/policy, direct/block and shared routing rules.
- Uses sequential `proxy-1`, `proxy-2`, ... outbounds with the shared `proxy` prefix selector and one `balancer` leastPing strategy.
- Removes the non-sample `meta.serverDescription` and `fallbackTag` fields; sets Auto label to `🇪🇺 Автовыбор`.
- Adds Xray outbound `level: 8`, sample-compatible `sockopt`, Hysteria method, and fixes double-decoding of the XHTTP `extra` query parameter.
- Adds tests for the new profile structure, routing and XHTTP parsing regression.

## 1.3.0 — Happ/Xray JSON array

- Replaced the incompatible single sing-box profile with one Happ-compatible JSON array.
- Emits one visible Xray profile per detected country plus an optional global Auto profile.
- Converts supported VLESS, VMess, Trojan, Shadowsocks, SOCKS/HTTP(S), and Hysteria2 URIs into native Xray outbounds.
- Explicitly rejects protocols/transports that cannot be represented losslessly by the installed Xray core.
- Uses endpoint IP GeoIP before label/TLD fallback.
- Validates every profile with official Xray-core before publication; updates metadata schema and Actions workflow.
