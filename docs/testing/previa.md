# Previa

This document tracks the initial Previa smoke suite created for `vaultick`.

## Project

- Name: `vaultick local smoke`
- Project ID: `019d457d-7ad3-7a93-a31d-6487db881c92`

## Scope

The current Previa coverage targets the two HTTP-facing services in this
repository:

- `vaultick-proxy`
- `vaultick-mcp`

The suite is intentionally small and stable. It focuses on smoke scenarios that
match the behavior already covered by the Rust E2E tests.

## Specs

Two local runtime specs were created in Previa:

- `vaultick_proxy`
  - base URL: `http://127.0.0.1:38080`
- `vaultick_mcp`
  - base URL: `http://127.0.0.1:38081`

## Pipelines

The project currently contains these pipelines:

- `proxy-forward-redaction-local`
  - sends a request through `vaultick-proxy`
  - expects preserved query/header forwarding
  - expects the secret-backed auth header to be redacted as `Bearer [REDACTED]`
- `proxy-route-miss-local`
  - confirms unmatched routes return `404`
- `mcp-initialize-local`
  - sends a JSON-RPC `initialize` request to `/mcp`
  - expects protocol negotiation and `vaultick-mcp` server metadata
- `mcp-missing-token-local`
  - confirms `/mcp` rejects `initialize` without bearer auth

## Fixture Assumptions

These pipelines assume a local fixture stack equivalent to the Rust E2E setup:

- `vaultick-proxy` listening on `127.0.0.1:38080`
- `vaultick-mcp` listening on `127.0.0.1:38081`
- `vaultick-mcp` configured with bearer token `test-token`
- `vaultick-proxy` configured with a `/github` route that forwards to a mock
  upstream and injects `GITHUB_TOKEN`
- the upstream echo route returns JSON fields compatible with the Rust proxy
  E2E assertions:
  - `auth`
  - `user`
  - `query`
  - `body`

## Notes

- The repository currently does not contain a checked-in local fixture launcher
  for these Previa ports yet.
- If we want these tests to become routine for local/dev validation, the next
  step should be adding a small bootstrap script that brings up the proxy, MCP,
  and mock upstream with the same fixtures used by the Rust E2E suite.
