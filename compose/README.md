# Compose — local production control plane (+ optional OIDC)

Runs **cautem-gateway** with a durable volume for `state.json` + encrypted provider secrets.
The image build uses sibling module checkouts and `go.work`; run these commands from the
multi-repo workspace root, not from a standalone gateway checkout.
Optional **Dex** IdP via Compose profile `oidc` (`cautem gateway login` PKCE).

```bash
# from workspace root — local-dev token auth
docker compose -f cautem-gateway/compose/docker-compose.yml up -d --build
cautem gateway add http://127.0.0.1:7443 --local --name local
cautem gateway select local
cautem doctor
```

## OIDC (Dex)

```bash
docker compose -f cautem-gateway/compose/docker-compose.yml \
  -f cautem-gateway/compose/docker-compose.oidc.yml --profile oidc up -d --build

cautem gateway add http://127.0.0.1:7443 --local --name local \
  --oidc-issuer http://127.0.0.1:5556/dex \
  --oidc-client-id cautem-cli \
  --oidc-allow-insecure-http

cautem gateway login
# browser → Dex → admin@example.com / password
cautem whoami          # idp=oidc
cautem gateway logout
```

Host networking overlay makes JWT `iss` (`http://127.0.0.1:5556/dex`) reachable for both CLI and gateway JWKS.
CLI PKCE callback is fixed at `http://127.0.0.1:18765/callback` (registered in `dex/config.yaml`).

## Secrets KEK (do this once)

Without `CAUTEM_SECRETS_KEK`, the gateway generates `secrets.kek` inside the volume. That survives container recreate **as long as the named volume is kept**. If the volume is removed (`docker compose down -v`), ciphertext becomes unreadable unless the same KEK is restored.

Pin a KEK:

```bash
python3 -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())'
cp cautem-gateway/compose/.env.example cautem-gateway/compose/.env
# edit .env → CAUTEM_SECRETS_KEK=…
docker compose -f cautem-gateway/compose/docker-compose.yml up -d
```

Rotation runbook: [Credentials](https://cautem.github.io/sandbox.dev/guides/credentials/).

## Tasks

```bash
task gateway:up
task gateway:down
```

Full agent path: [Docker guide](https://cautem.github.io/sandbox.dev/providers/docker/).
