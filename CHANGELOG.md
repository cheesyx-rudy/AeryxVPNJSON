## 1.4.1 — 2026-10-28

- Fixed CI Xray validation for the Happ reference profile: `WH-DIRECT` and `STD-DIRECT` are app-specific geodata selectors and their data files are not supplied to the official Xray binary. The validator now removes only those selectors from a temporary validation copy, leaving the published Happ JSON and its routing rules unchanged.
- Added sanitized Xray stderr diagnostics to validation failures, so the next error report includes the actual cause without dumping proxy credentials or complete configs.
- Added regression tests for custom-geodata handling and safe diagnostics.

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
