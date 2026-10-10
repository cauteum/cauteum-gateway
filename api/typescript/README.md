# cautem control client

Generated TypeScript contract and Connect browser client for `cautem.control.v1`.
The source schema is `../proto/cautem/control/v1/console.proto`. This package
is private until the client API and browser authentication are reviewed.

```bash
npm ci
npm run check
```

Use `createControlTransport({ baseUrl: window.location.origin })` and
`createControlClients(transport)` from the same origin as the gateway. A
browser must use its own user session or OIDC credential; never place a
gateway owner or sandbox supervisor token in browser code.
