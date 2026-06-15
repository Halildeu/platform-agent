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
  install_src="${PACKAGE_INSTALL_PS1:-dist/install.ps1}"
  bootstrap_src="${PACKAGE_BOOTSTRAP_PS1:-dist/bootstrap-package.ps1}"
  uninstall_src="${PACKAGE_UNINSTALL_PS1:-dist/uninstall.ps1}"

  test -f "$install_src" || { echo "windows-package.sh: patched install.ps1 not found for PREBUILT_EXE packaging: $install_src" >&2; exit 1; }
  test -f "$bootstrap_src" || { echo "windows-package.sh: bootstrap-package.ps1 not found for PREBUILT_EXE packaging: $bootstrap_src" >&2; exit 1; }
  test -f "$uninstall_src" || { echo "windows-package.sh: uninstall.ps1 not found for PREBUILT_EXE packaging: $uninstall_src" >&2; exit 1; }
  if grep -Eq '__INJECTED_(BINARY_URL|EXPECTED_SHA256|EXPECTED_THUMBPRINT|SIGNING_TIER|RELEASE_TAG)__' "$install_src"; then
    echo "windows-package.sh: patched install.ps1 still contains release __INJECTED_* sentinel(s): $install_src" >&2
    exit 1
  fi
else
  ./scripts/build/windows.sh >/dev/null
  exe_src="bin/endpoint-agent.exe"
  install_src="${PACKAGE_INSTALL_PS1:-installers/windows/install.ps1}"
  bootstrap_src="${PACKAGE_BOOTSTRAP_PS1:-installers/windows/bootstrap-package.ps1}"
  uninstall_src="${PACKAGE_UNINSTALL_PS1:-installers/windows/uninstall.ps1}"
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
copy_ps1_with_bom "$bootstrap_src" "$package_dir/bootstrap-package.ps1"
copy_ps1_with_bom "$install_src" "$package_dir/install.ps1"
copy_ps1_with_bom "$uninstall_src" "$package_dir/uninstall.ps1"
cp installers/windows/README.md "$package_dir/README.md"

(
  cd "$package_dir"
  shasum -a 256 endpoint-agent.exe bootstrap-package.ps1 install.ps1 uninstall.ps1 README.md > SHA256SUMS
  zip -qr "../EndpointAgent.zip" .
)

find "$package_dir" -maxdepth 1 -type f -print | sort
shasum -a 256 "$zip_path"
