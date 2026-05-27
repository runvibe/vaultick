# Agents

- Document and adjust each agent as provider workflows change.
- **Architecture**: keep transport concerns inside routes/, move reusable logic
  into dedicated modules, and align data contracts with openapi.yaml and models/
  structs.
- **Project structure**: routes/ handles HTTP transport and wiring, services/
  owns reusable business logic and integrations, models/ defines data contracts
  and DB-facing structs; keep modules small and focused.
- **Separation rule**: always split routes from services and models; do not mix
  request/response handling with business logic or data structs.
- **Persistence**: the current storage layer uses `rusqlite`; keep schema
  changes in `vaultick-lib/migrations/`, load them from `vaultick-lib`, use
  bound parameters, and avoid inline schema drift. Do not migrate to SQLx
  without a dedicated migration plan.
- **Processes**: discuss changes via PROJECT.md conventions, open pull requests
  with review context, and keep agents.md current when workflows shift.
- **Release assets**: keep `install.sh`, `release-metadata.json`, GitHub
  Release asset names, and docs aligned whenever the release workflow changes.
- **Release build & push**: after finishing any change run
  `cargo build --release`; if the release build succeeds, commit the changes and
  push to the remote.
