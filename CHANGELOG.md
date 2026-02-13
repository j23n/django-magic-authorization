# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.5] - 2026-02-13

### Added

- Signals: `access_granted` and `access_denied` for monitoring access events.
- Custom 403 responses via `FORBIDDEN_TEMPLATE` and `FORBIDDEN_HANDLER` settings.
- Token expiration (`expires_at`) and usage limits (`max_uses`).
- Auth cookies scoped to the static prefix of the protected path pattern.
- Tokens stripped from URLs via redirect after query-param validation.
- `cleanup_expired_tokens` management command.
- Conditional protection with `protect_fn` on `protected_path`.
- Admin interface with access link display and path validation.
