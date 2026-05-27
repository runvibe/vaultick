# Project Conventions

## Change Flow

- Keep route handlers focused on HTTP transport and delegate reusable behavior to services or focused modules.
- Add regression tests before behavior changes.
- Run `cargo test --workspace`, `cargo fmt --all -- --check`, and `cargo clippy --workspace --all-targets -- -D warnings` before opening review.

## Release Flow

- Release asset names must stay aligned across `.github/workflows/release.yml`, `install.sh`, `release-metadata.json`, and docs.
- After implementation work, run `cargo build --release`.
- If the release build succeeds and the change is intended for publication, commit and push the branch.
