# AeryxVPN JSON Subscription

Automated AeryxVPN subscription published in the Happ-compatible Xray JSON-array format.

[English](README.md) · [Русский](README_RU.md)

## Subscription

- **JSON subscription:** [AeryxVPN.json](https://raw.githubusercontent.com/cheesyx-rudy/AeryxVPNJSON/main/AeryxVPN.json)
- **Metadata:** [AeryxVPN.metadata.json](https://raw.githubusercontent.com/cheesyx-rudy/AeryxVPNJSON/main/AeryxVPN.metadata.json)

The subscription is intended for clients that support Happ-compatible Xray JSON arrays. The metadata file contains generation details, profile and country information, and the configured update interval.

## Included features

- Separate profiles grouped by country.
- An automatic profile for selecting a node based on measured latency.
- Client-side Xray balancing using `burstObservatory` and `leastPing`.
- Subscription metadata with the generation time and current output statistics.

The number of available nodes and countries changes as the subscription is regenerated. Actual connectivity and performance depend on the network, the destination service, and the client being used.

## Processing and validation

The automated pipeline collects configured sources, extracts supported proxy entries, applies filtering and duplicate reduction, validates candidates through the private **AeryxVPN Core 1.0.0**, and builds the JSON subscription.

The generated profiles are additionally checked with the official Xray-core binary before publication.

Publication has safety thresholds. When the run does not produce enough acceptable candidates or validation requirements are not met, the workflow keeps the previously published subscription instead of replacing it with an incomplete result.

The workflow can be started by the connected automation through `repository_dispatch`. It also supports manual runs in GitHub Actions and runs triggered by changes to `sources.enc`.

## Source data

The configured source list is stored in this repository as encrypted `sources.enc`. The workflow decrypts it at runtime using a GitHub Actions secret. The decryption key and other credentials must not be committed to the repository.

The parser's full production workflow depends on the separate private AeryxVPN Core repository and its read-only Actions credential. A public clone of this repository alone is therefore not a self-contained copy of the production environment.

## Repository contents

| Path | Purpose |
| --- | --- |
| `AeryxVPN.json` | Published JSON-array subscription |
| `AeryxVPN.metadata.json` | Metadata for the published subscription |
| `src/aeryx_json_parser/` | JSON parser and subscription-generation code |
| `config/` | Parser and output settings |
| `schemas/` | JSON schemas for generated data |
| `tools/` | Source decryption and validation utilities |
| `.github/workflows/` | Automation and CI workflows |
| `LICENSE`, `LICENSE-SCOPE.md` | Software license and its scope |

## License

The original software code listed in [LICENSE-SCOPE.md](LICENSE-SCOPE.md) is covered by PolyForm Strict License 1.0.0 ([LICENSE](LICENSE)).

The license scope does **not** include the published VPN subscription, configuration and source-list data, documentation, or third-party materials. This project does not claim ownership of third-party configurations or grant rights the project does not hold.
