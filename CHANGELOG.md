# Changelog

## 1.3.0 — Happ/Xray JSON array

- Replaced the incompatible single sing-box profile with one Happ-compatible JSON array.
- Emits one visible Xray profile per detected country plus an optional global `🌐 AeryxVPN Auto` profile.
- Adds per-profile Xray `observatory` + `leastPing` balancer with a concrete `proxy` outbound for Happ summaries.
- Converts supported VLESS, VMess, Trojan, Shadowsocks, SOCKS/HTTP(S), and Hysteria2 URIs into native Xray outbounds.
- Explicitly rejects protocols/transports that cannot be represented losslessly by the installed Xray core.
- Uses endpoint IP GeoIP before label/TLD fallback.
- Validates every profile with official Xray-core before publication; updates metadata schema and Actions workflow.
