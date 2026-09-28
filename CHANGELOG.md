# Changelog

## [Unreleased]

### Added

- Workspace/global provider profile catalog APIs with authorization and resource-version conflict checks.
- Encrypted OAuth refresh material, output token rotation, and lazy credential refresh during sandbox secret resolution.

## [v0.0.2-alpha.1] - 2026-09-28

### Security

- Refuse `allow_unauthenticated` on non-loopback listen addresses.
- Force `security_flagged` on pending proposals so bulk approve cannot clear sensitive rules by client trust.

### Added

- Gateway info exposes `allow_unauthenticated`, KEK `format`, and `migration_needed`.
