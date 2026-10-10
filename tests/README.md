# Gateway integration and E2E tests

Tests in this directory are black-box tests for the gateway module:

- `integration/` covers public gateway HTTP/gRPC behavior and in-process
  service boundaries.
- `e2e/` owns Testcontainers lifecycle and real gateway/engine scenarios.

Tests that require unexported `httpapi` state remain package-local until the
corresponding public test seam is extracted. They are not new integration
tests and should not grow additional cross-service setup.
