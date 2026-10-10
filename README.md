<h1 align="center">cautem-gateway</h1>

<p align="center">
  <strong>RPC control plane and relay</strong><br>
  OpenShell and cautem RPC APIs with HTTP health, auth bootstrap, and streaming relay transport.
</p>
<p align="center">
  <a href="https://github.com/cautem/cautem-gateway/actions/workflows/ci.yml"><img src="https://github.com/cautem/cautem-gateway/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/cautem/cautem-gateway"><img src="https://pkg.go.dev/badge/github.com/cautem/cautem-gateway.svg" alt="Go Reference"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/cautem/cautem-gateway"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>

  <a href="https://github.com/cautem/cautem-gateway/actions/workflows/images-gateway.yml"><img src="https://github.com/cautem/cautem-gateway/actions/workflows/images-gateway.yml/badge.svg" alt="images-gateway"></a>
</p>
<p align="center">
  <sub>Part of the <a href="https://github.com/cautem">cautem / cautem</a> ecosystem</sub>
</p>

---

## Overview

Use the [gateway guide](https://cautem.github.io/sandbox.dev/guides/gateway/) for setup and the [OpenShell compatibility page](https://cautem.github.io/sandbox.dev/reference/openshell-compatibility/) for the current supported scope.

**cautem-gateway** is the optional control-plane daemon. Client management workflows use authenticated RPC. HTTP remains for health, browser/auth bootstrap, and relay/stream transport.

### Key Features

| Category | Capabilities |
|----------|--------------|
| **Registry** | Sandbox upsert / list / delete |
| **Policy** | Base + effective policy over Control RPC; provider attach via OpenShell RPC |
| **Proposals** | Store / approve / reject (`policy.local` sync) |
| **Relay** | Stream and exec relay for guests |
| **Image** | `ghcr.io/cautem/cautem/gateway` |

---

## Installation

```bash
go build -o cautem-gateway ./cmd/cautem-gateway
./cautem-gateway --listen 127.0.0.1:7443
```

**Requirements:** Go 1.27+

**Container:** `ghcr.io/cautem/cautem/gateway:latest`

---

## Quick Start

```bash
./cautem-gateway --listen 127.0.0.1:7443 &
cautem gateway add http://127.0.0.1:7443 --local --name local
cautem gateway select local
curl -s http://127.0.0.1:7443/healthz
```

### HTTP API (selected)

| Method | Path | Role |
|--------|------|------|
| GET | `/healthz` | liveness |

The remaining HTTP contract is documented in [`api/openapi.yaml`](./api/openapi.yaml).
It covers health and bootstrap flows; management operations use the generated
Control RPC or the pinned OpenShell RPC contract. No REST compatibility layer
is maintained for beta clients.

The separate `cautem.control.v1` Connect API serves authenticated UI and
SDK clients on the gateway listener. Its generated Proto source and private
TypeScript client are under [`api/`](./api/). Lifecycle mutations require a
client-generated `request_id`; reuse the same ID when retrying, then call
`GetOperation` with that ID to reconcile a lost response. An operation left
running across a gateway restart is reported as `uncertain` because the server
cannot infer whether the backend completed the side effect. The control API
also exposes workspace-filtered service/template summaries and admin operation
and audit history. These summaries omit backend routing addresses and template
environment values.

Provider profile reads and writes use `cautem.control.v1`; the service
preserves the full cautem YAML profile and uses resource-version checks for
updates. Global profiles require platform admin access, and workspace profiles
require provider scopes plus workspace membership.

The first read-only browser console is in [`ui/`](./ui/). It uses the generated
TypeScript Connect client and OIDC authorization-code flow with PKCE. See its
README for local setup and the current deployment boundary; production static
hosting is not yet wired into the gateway.

Durable state: `$XDG_STATE_HOME/cautem/gateway/state.json`.

---

## Package Structure

| Path | Purpose |
|------|---------|
| `cmd/cautem-gateway` | Daemon entrypoint |
| `internal/` | HTTP handlers, state, relay |


---

## Related

| Resource | Link |
|----------|------|
| Roadmap | [ROADMAP.md](./ROADMAP.md) |
| Organization | [https://github.com/cautem](https://github.com/cautem) |
| Organization overview | [github.com/cautem](https://github.com/cautem) |
| pkg.go.dev | [`github.com/cautem/cautem-gateway`](https://pkg.go.dev/github.com/cautem/cautem-gateway) |

## License

[Apache-2.0](./LICENSE) © cautem

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
Without an OpenShell file, the existing cautem defaults still apply.
