# Changelog

## [v0.1.0-beta.1] - 2026-10-07

### Added

- Add contextual structured logs for gateway relay operations.

### Changed

- Use `cauteum-core` v0.1.0-beta.1 and `cauteum-runtime` v0.1.0-beta.1.
- Update AWS SDK, go-jose, and SPIFFE dependencies to their latest compatible releases.

### Fixed

- Restrict gateway token files with Windows ACLs and run HTTP security integration tests across platforms.
- Wait for the gateway listener before making RPC readiness assertions.

## [v0.1.0-alpha.2] - 2026-10-07

### Added

- Workspace/global provider profile catalog APIs with authorization and resource-version conflict checks.
- Encrypted OAuth refresh material, output token rotation, and lazy credential refresh during sandbox secret resolution.

### Changed

- Align runtime, driver, and slogx with v0.1.0-alpha.2; update Go crypto, gRPC, protobuf, and SPIFFE dependencies.

## [v0.0.2-alpha.1] - 2026-09-28

### Security

- Refuse `allow_unauthenticated` on non-loopback listen addresses.
- Force `security_flagged` on pending proposals so bulk approve cannot clear sensitive rules by client trust.

### Added

- Gateway info exposes `allow_unauthenticated`, KEK `format`, and `migration_needed`.
