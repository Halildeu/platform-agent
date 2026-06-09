#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

package_dir="dist/windows/EndpointAgent"
zip_path="dist/windows/EndpointAgent.zip"
rm -rf "$package_dir"
rm -f "$zip_path"
mkdir -p "$package_dir"

# PREBUILT_EXE lets CI (release.yml publish job) package the *signed* binary
# produced by the windows build+sign job instead of cross-compiling a fresh
# unsigned dev binary here. Local dev with no PREBUILT_EXE keeps the old
# behaviour: build via scripts/build/windows.sh. Either way the resulting
# endpoint-agent.exe is the one whose hash lands in the package SHA256SUMS.
if [ -n "${PREBUILT_EXE:-}" ]; then
  test -f "$PREBUILT_EXE" || { echo "windows-package.sh: PREBUILT_EXE not found: $PREBUILT_EXE" >&2; exit 1; }
  exe_src="$PREBUILT_EXE"
else
  ./scripts/build/windows.sh >/dev/null
  exe_src="bin/endpoint-agent.exe"
fi

copy_ps1_with_bom() {
  local source_path="$1"
  local target_path="$2"
  python3 - "$source_path" "$target_path" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
content = source.read_text(encoding="utf-8-sig")
target.write_text(content, encoding="utf-8-sig", newline="")
PY
}

cp "$exe_src" "$package_dir/endpoint-agent.exe"
copy_ps1_with_bom installers/windows/bootstrap-package.ps1 "$package_dir/bootstrap-package.ps1"
copy_ps1_with_bom installers/windows/install.ps1 "$package_dir/install.ps1"
copy_ps1_with_bom installers/windows/uninstall.ps1 "$package_dir/uninstall.ps1"
cp installers/windows/README.md "$package_dir/README.md"

(
  cd "$package_dir"
  shasum -a 256 endpoint-agent.exe bootstrap-package.ps1 install.ps1 uninstall.ps1 README.md > SHA256SUMS
  zip -qr "../EndpointAgent.zip" .
)

find "$package_dir" -maxdepth 1 -type f -print | sort
shasum -a 256 "$zip_path"
