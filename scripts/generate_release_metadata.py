#!/usr/bin/env python3

import json
import os
from pathlib import Path


def main() -> None:
    version = os.environ["VERSION"]
    repository = os.environ["REPOSITORY"]
    release_scope = os.environ["RELEASE_SCOPE"]
    published_at = os.environ["PUBLISHED_AT"]

    base_url = f"https://github.com/{repository}/releases/download/v{version}"

    links = {
        "vaultick_linux_amd64": f"{base_url}/vaultick-linux-amd64",
        "vaultick_linux_arm64": f"{base_url}/vaultick-linux-arm64",
        "vaultick_proxy_linux_amd64": f"{base_url}/vaultick-proxy-linux-amd64",
        "vaultick_proxy_linux_arm64": f"{base_url}/vaultick-proxy-linux-arm64",
    }

    if release_scope == "all":
        links["vaultick_macos_amd64"] = f"{base_url}/vaultick-macos-amd64"
        links["vaultick_windows_amd64"] = f"{base_url}/vaultick-windows-amd64.exe"

    payload = {
        "name": "vaultick",
        "version": version,
        "tag": f"v{version}",
        "published_at": published_at,
        "links": links,
    }

    Path("release-metadata.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
