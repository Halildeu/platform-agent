#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

package_dir="dist/windows/EndpointAgent"
rm -rf "$package_dir"
mkdir -p "$package_dir"

./scripts/build/windows.sh >/dev/null

cp bin/endpoint-agent.exe "$package_dir/endpoint-agent.exe"
cp installers/windows/install.ps1 "$package_dir/install.ps1"
cp installers/windows/uninstall.ps1 "$package_dir/uninstall.ps1"
cp installers/windows/README.md "$package_dir/README.md"

(
  cd "$package_dir"
  shasum -a 256 endpoint-agent.exe install.ps1 uninstall.ps1 README.md > SHA256SUMS
)

find "$package_dir" -maxdepth 1 -type f -print | sort
