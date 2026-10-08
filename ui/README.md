# Cauteum control console

This is the first browser client for the `cauteum.control.v1` Connect API.
It is a read-only inventory slice: sign in, inspect authorized sandbox records,
filter the list, and read the gateway's bounded in-memory log tail.

## Run locally

Build the generated client first, then start the UI:

```bash
cd ../api/typescript && npm ci && npm run check
cd ../../ui && npm ci && npm run dev
```

Vite proxies `/v1/auth/oidc` and Connect requests to `https://127.0.0.1:7443`
by default and accepts the local gateway's development certificate. Point it at
another gateway with `CAUTEUM_GATEWAY_TARGET`. This proxy setting is for local
development only.

Configure the gateway with its OIDC issuer, audience, and browser `client_id`.
Register the UI origin's `/auth/callback` URL as a redirect URI for a public
authorization-code client with PKCE enabled. The identity provider must allow
browser discovery/token requests from the UI origin and issue an access token
whose audience matches the gateway's configured audience. Open the UI on the
same origin as the gateway proxy.

The access token lives in memory and is discarded on reload or sign-out. The
authorization-code state verifier uses the OIDC library's temporary browser
state storage so the redirect can complete. The UI never calls local login or
receives the gateway owner token, supervisor tokens, or driver credentials.

## Current boundary

Production static hosting and the gateway's same-origin reverse-proxy route are
not wired yet. Deploy the built `dist/` behind a same-origin reverse proxy that
routes `/v1/auth/oidc` and `cauteum.control.v1` to the gateway and serves the
SPA fallback for `/auth/callback`. Do not expose a development Vite proxy.

The UI presents `registry_status` as registry data. Runtime health is explicitly
unavailable in the current view. Lifecycle buttons, live stream rendering,
workspace administration, and broader policy/provider workflows are not part of
this slice.
