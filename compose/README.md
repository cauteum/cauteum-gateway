# Compose — local production control plane (+ optional OIDC)

Runs **whaleshell-gateway** with a durable volume for `state.json` + encrypted provider secrets.
The image build uses sibling module checkouts and `go.work`; run these commands from the
multi-repo workspace root, not from a standalone gateway checkout.
Optional **Dex** IdP via Compose profile `oidc` (`whaleshell gateway login` PKCE).

```bash
# from org hub root — local-dev token auth
docker compose -f whaleshell-gateway/compose/docker-compose.yml up -d --build
whaleshell gateway add http://127.0.0.1:7443 --local --name local
whaleshell gateway select local
whaleshell doctor
```

## OIDC (Dex)

```bash
docker compose -f whaleshell-gateway/compose/docker-compose.yml \
  -f whaleshell-gateway/compose/docker-compose.oidc.yml --profile oidc up -d --build

whaleshell gateway add http://127.0.0.1:7443 --local --name local \
  --oidc-issuer http://127.0.0.1:5556/dex \
  --oidc-client-id whaleshell-cli \
  --oidc-allow-insecure-http

whaleshell gateway login
# browser → Dex → admin@example.com / password
whaleshell whoami          # idp=oidc
whaleshell gateway logout
```

Host networking overlay makes JWT `iss` (`http://127.0.0.1:5556/dex`) reachable for both CLI and gateway JWKS.
CLI PKCE callback is fixed at `http://127.0.0.1:18765/callback` (registered in `dex/config.yaml`).

## Secrets KEK (do this once)

Without `WHALESHELL_SECRETS_KEK`, the gateway generates `secrets.kek` inside the volume. That survives container recreate **as long as the named volume is kept**. If the volume is removed (`docker compose down -v`), ciphertext becomes unreadable unless the same KEK is restored.

Pin a KEK:

```bash
python3 -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())'
cp whaleshell-gateway/compose/.env.example whaleshell-gateway/compose/.env
# edit .env → WHALESHELL_SECRETS_KEK=…
docker compose -f whaleshell-gateway/compose/docker-compose.yml up -d
```

Rotation runbook: [Credentials](https://whaleshell.github.io/guides/credentials/).

## Tasks

```bash
task gateway:up
task gateway:down
```

Full agent path: [Docker guide](https://whaleshell.github.io/providers/docker/).
