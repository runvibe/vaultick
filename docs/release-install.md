# Release and Install

This guide explains how `vaultick` binaries and proxy images are published, and
how the public installer works from the operator point of view.

## Installer

The public installer is:

```bash
curl -fsSL https://downloads.vaultick.dev/install.sh | sh
```

It currently:

- downloads `latest.json` from `https://downloads.vaultick.dev/latest.json`
- resolves the latest published version and Linux binary links
- detects `amd64` or `arm64`
- installs the `vaultick` CLI under the default user-scoped Vaultick home
- sets `VAULTICK_HOME`
- updates shell startup files on Unix-like systems so `~/.vaultick/bin` lands on
  `PATH`

At this stage the installer is Linux-only. The release workflow can also publish
macOS and Windows CLI assets on GitHub Releases, but there is not yet a
PowerShell installer and the public installer does not target macOS.

## What Gets Installed

The installer installs the `vaultick` CLI.

The default install location is:

```text
$HOME/.vaultick/bin/vaultick
```

The installer also exports:

```text
VAULTICK_HOME=$HOME/.vaultick
```

This matches the CLI default database resolution:

```text
VAULTICK_HOME/databases/database.db
```

## `latest.json`

The release workflow publishes a manifest at:

```text
https://downloads.vaultick.dev/latest.json
```

That manifest contains:

- the latest version
- direct download links for published binaries

Current link keys are:

- `vaultick_linux_amd64`
- `vaultick_linux_arm64`
- `vaultick_proxy_linux_amd64`
- `vaultick_proxy_linux_arm64`

The installer currently consumes only the `vaultick_*` CLI entries.
The manifest remains Linux-only.

## Docker Images

The release workflow also publishes the proxy image to GHCR:

- `ghcr.io/cloudvibedev/vaultick-proxy`

These tags are published:

- `latest`
- `<version>`
- `latest-amd64`
- `latest-arm64`
- `<version>-amd64`
- `<version>-arm64`

## Release Workflow

At a high level, the release workflow:

1. resolves the workspace version
2. resolves the selected release scope
3. creates or validates the matching git tag
4. builds the binaries required by that scope
5. creates the GitHub release and uploads the selected assets
6. when Linux is included, publishes Linux assets plus `latest.json` and
   `install.sh` to the downloads bucket
7. when Linux is included, builds and publishes the multi-arch
   `vaultick-proxy` image
8. when Linux is included, optionally publishes Rust crates when
   `CARGO_REGISTRY_TOKEN` is configured

The manual workflow supports four scopes:

- `linux`: GitHub Release assets for Linux plus Docker, crates.io, and bucket
  publishing
- `mac`: GitHub Release asset for macOS only
- `windows`: GitHub Release asset for Windows only
- `all`: Linux full publishing plus macOS and Windows release assets

When the workflow runs from a pushed `v*` tag, it behaves as `all`.

## Platform Coverage

Current published assets are:

- Linux:
  - `vaultick`
  - `vaultick-proxy`
  - `amd64` and `arm64`
- macOS:
  - `vaultick`
  - `amd64`
- Windows:
  - `vaultick.exe`
  - `amd64`

Only Linux artifacts are uploaded to `downloads.vaultick.dev` and referenced by
`latest.json`.

## Uninstall

To remove a default installation, delete `~/.vaultick` and remove the installer
block from your shell rc files.

Remove the default home:

```bash
rm -rf ~/.vaultick
```

Then remove the lines added by the installer between:

```text
# >>> Vaultick installer >>>
# <<< Vaultick installer <<<
```

The installer may write that block to:

- `~/.zshrc`
- `~/.bashrc`

After removing the block, open a new shell or reload your rc file so `PATH` no
longer includes `VAULTICK_HOME/bin`.
