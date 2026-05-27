# Release and Install

This guide explains how `vaultick` binaries and proxy images are published, and
how the public installer works from the operator point of view.

## Installer

The public installer is:

```bash
curl -fsSL https://raw.githubusercontent.com/runvibe/vaultick/main/install.sh | sh
```

It currently:

- downloads `release-metadata.json` from
  `https://raw.githubusercontent.com/runvibe/vaultick/main/release-metadata.json`
- resolves the latest published version and Linux or macOS binary links
- detects `amd64` or `arm64`
- installs the `vaultick` CLI under the default user-scoped Vaultick home
- sets `VAULTICK_HOME`
- updates shell startup files on Unix-like systems so `~/.vaultick/bin` lands on
  `PATH`

At this stage the installer supports Linux and macOS. The release workflow can
also publish Windows CLI assets on GitHub Releases, but there is not yet a
PowerShell installer.

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

## `release-metadata.json`

The release workflow updates a metadata file in the repository at:

```text
https://raw.githubusercontent.com/runvibe/vaultick/main/release-metadata.json
```

That metadata file contains:

- the latest version
- direct GitHub Release download links for published binaries

Current link keys are:

- `vaultick_linux_amd64`
- `vaultick_linux_arm64`
- `vaultick_proxy_linux_amd64`
- `vaultick_proxy_linux_arm64`
- `vaultick_macos_amd64` when the latest metadata-producing release included
  macOS assets
- `vaultick_macos_arm64` when the latest metadata-producing release included
  macOS assets
- `vaultick_windows_amd64` when the latest metadata-producing release included
  Windows assets

The installer currently consumes only the `vaultick_*` CLI entries.
This metadata file is updated only when the release scope includes Linux,
because Linux scopes also publish the repository metadata used by the installer.

## Docker Images

The release workflow also publishes the proxy image to GHCR:

- `ghcr.io/runvibe/vaultick-proxy`

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
6. when Linux is included, updates `release-metadata.json` on `main`
7. when Linux is included, builds and publishes the multi-arch
   `vaultick-proxy` image
8. when Linux is included, optionally publishes Rust crates when
   `CARGO_REGISTRY_TOKEN` is configured

The manual workflow supports four scopes:

- `linux`: GitHub Release assets for Linux plus repository metadata, Docker, and
  crates.io publishing
- `mac`: GitHub Release asset for macOS only
- `windows`: GitHub Release asset for Windows only
- `all`: Linux full publishing plus macOS and Windows release assets

When the workflow runs from a pushed `v*` tag, it behaves as `all`.

If the current workspace version does not have a published GitHub Release yet,
the committed metadata may exist before the release assets do. The next Linux or
`all` release is what makes the metadata resolvable for the installer.

## Platform Coverage

Current published assets are:

- Linux:
  - `vaultick`
  - `vaultick-proxy`
  - `amd64` and `arm64`
- macOS:
  - `vaultick`
  - `amd64` and `arm64`
- Windows:
  - `vaultick.exe`
  - `amd64`

`release-metadata.json` tracks the latest Linux-installable release and points
at GitHub Release assets.

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
