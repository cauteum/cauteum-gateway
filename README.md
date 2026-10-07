<h1 align="center">whaleshell-gateway</h1>

<p align="center">
  <strong>Control-plane registry & relay</strong><br>
  HTTP registry for sandboxes, providers, policy, proposals, and relayed exec.
</p>
<p align="center">
  <a href="https://github.com/whaleshell/whaleshell-gateway/actions/workflows/ci.yml"><img src="https://github.com/whaleshell/whaleshell-gateway/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/whaleshell/whaleshell-gateway"><img src="https://pkg.go.dev/badge/github.com/whaleshell/whaleshell-gateway.svg" alt="Go Reference"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/whaleshell/whaleshell-gateway"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>

  <a href="https://github.com/whaleshell/whaleshell-gateway/actions/workflows/images-gateway.yml"><img src="https://github.com/whaleshell/whaleshell-gateway/actions/workflows/images-gateway.yml/badge.svg" alt="images-gateway"></a>
</p>
<p align="center">
  <sub>Part of the <a href="https://github.com/whaleshell">whaleshell / whaleshell</a> ecosystem</sub>
</p>

---

## Overview

Use the [gateway guide](https://whaleshell.github.io/guides/gateway/) for setup and the [OpenShell compatibility page](https://whaleshell.github.io/reference/openshell-compatibility/) for the current supported scope.

**whaleshell-gateway** is the optional control-plane daemon. Sandboxes register here; the CLI and SDKs talk HTTP for inventory, effective policy, provider attach, policy proposals, logs, and relayed exec.

### Key Features

| Category | Capabilities |
|----------|--------------|
| **Registry** | Sandbox upsert / list / delete |
| **Policy** | Base + effective policy; provider attach |
| **Proposals** | Store / approve / reject (`policy.local` sync) |
| **Relay** | Long-poll exec for `whaleshell-agent` guests |
| **Image** | `ghcr.io/whaleshell/whaleshell/gateway` |

---

## Installation

```bash
go build -o whaleshell-gateway ./cmd/whaleshell-gateway
./whaleshell-gateway --listen 127.0.0.1:7443
```

**Requirements:** Go 1.27+

**Container:** `ghcr.io/whaleshell/whaleshell/gateway:latest`

---

## Quick Start

```bash
./whaleshell-gateway --listen 127.0.0.1:7443 &
whaleshell gateway add http://127.0.0.1:7443 --local --name local
whaleshell gateway select local
curl -s http://127.0.0.1:7443/healthz
```

### HTTP API (selected)

| Method | Path | Role |
|--------|------|------|
| GET | `/healthz` | liveness |
| GET | `/v1/info` | gateway id + sandbox count |
| GET/PUT/DELETE | `/v1/sandboxes/{name}` | registry |
| GET/PUT | `/v1/sandboxes/{name}/policy` | base / effective policy |
| GET/POST | `/v1/sandboxes/{name}/proposals` | policy advisor chunks |
| GET | `/v1/profiles` | provider profiles |

Durable state: `$XDG_STATE_HOME/whaleshell/gateway/state.json`.

---

## Package Structure

| Path | Purpose |
|------|---------|
| `cmd/whaleshell-gateway` | Daemon entrypoint |
| `internal/` | HTTP handlers, state, relay |


---

## Related

| Resource | Link |
|----------|------|
| Roadmap | [ROADMAP.md](./ROADMAP.md) |
| Organization | [https://github.com/whaleshell](https://github.com/whaleshell) |
| Organization overview | [github.com/whaleshell](https://github.com/whaleshell) |
| pkg.go.dev | [`github.com/whaleshell/whaleshell-gateway`](https://pkg.go.dev/github.com/whaleshell/whaleshell-gateway) |

## License

[Apache-2.0](./LICENSE) © whaleshell

## OpenShell gateway TOML

The daemon reads `--config gateway.toml`, then `OPENSHELL_GATEWAY_CONFIG`,
then an optional `$XDG_CONFIG_HOME/openshell/gateway.toml`
(`~/.config/openshell/gateway.toml` fallback). Explicit missing files fail.
Supported values follow flag > environment > file precedence.

Current startup applies the main bind address, installation name in logs,
simple log levels, SSH session TTL, the local auth switch, TLS certificate/key
paths, and `disable_tls`. Referenced paths remain literal and relative to the
process working directory. `disable_tls=true` ignores the TLS table at runtime.

This support is partial. Full OpenShell deployment files still require missing
driver, storage, identity, middleware, interceptor, telemetry, and auxiliary
listener consumers. Supplied unsupported settings fail before the daemon
creates state or opens listeners. The loader also rejects unknown/duplicate
keys, invalid required fields/enums, and a database URL embedded in TOML.
Without an OpenShell file, the existing whaleshell defaults still apply.
