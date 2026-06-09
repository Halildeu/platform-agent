#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

python3 - <<'PY'
from pathlib import Path
import sys

failures = []

bootstrap_source = Path("installers/windows/bootstrap-package.ps1")
install_source = Path("installers/windows/install.ps1")
uninstall_source = Path("installers/windows/uninstall.ps1")

for source in (bootstrap_source, install_source, uninstall_source):
    try:
        source.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        failures.append(f"{source}: not valid UTF-8 ({exc})")

for source in (bootstrap_source, install_source, uninstall_source):
    source_text = source.read_text(encoding="utf-8")
    non_ascii = sorted({f"U+{ord(char):04X}" for char in source_text if ord(char) > 127})
    if non_ascii:
        failures.append(
            f"{source}: contains non-ASCII characters {', '.join(non_ascii)}; "
            "Windows PowerShell 5.1 standard-host install path must stay ASCII-only"
        )

install_text = install_source.read_text(encoding="utf-8")
bootstrap_text = bootstrap_source.read_text(encoding="utf-8")
required_install_markers = [
    "[switch]$AutoEnroll",
    "[switch]$ResetCredentialStore",
    'https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent',
    '"Mode" -Value "auto-enroll"',
    "Clear-AgentAutoEnrollRegistry",
    "clearing auto-enroll registry mode for HMAC install",
    "Assert-HmacEnrollmentTokenStorePolicy",
    "Backup-HmacCredentialStoreForFreshEnroll",
    "ENDPOINT_AGENT_AUTO_ENROLL_API_URL",
    "ENDPOINT_AGENT_AUTO_ENROLL_CERT_SAN_URI_PREFIX",
    "-AutoEnroll is mutually exclusive",
    "-ResetCredentialStore is only valid",
]
required_bootstrap_markers = [
    "[switch]$AutoEnroll",
    "[switch]$ResetCredentialStore",
    'https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent',
    '$installArgs["AutoEnroll"] = $true',
    '$installArgs["AutoEnrollApiUrl"] = $AutoEnrollApiUrl',
    '$installArgs["AutoEnrollCertSANURIPrefix"] = $AutoEnrollCertSANURIPrefix',
    '$installArgs["ResetCredentialStore"] = $true',
]
for marker in required_install_markers:
    if marker not in install_text:
        failures.append(f"{install_source}: missing auto-enroll installer marker: {marker}")
for marker in required_bootstrap_markers:
    if marker not in bootstrap_text:
        failures.append(f"{bootstrap_source}: missing auto-enroll bootstrap marker: {marker}")

stale_autoenroll_base = "https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-admin"
if stale_autoenroll_base in install_text:
    failures.append(f"{install_source}: stale AutoEnroll endpoint-admin base URL present")
if stale_autoenroll_base in bootstrap_text:
    failures.append(f"{bootstrap_source}: stale AutoEnroll endpoint-admin base URL present")

package_dir = Path("dist/windows/EndpointAgent")
if package_dir.exists():
    for name in ("bootstrap-package.ps1", "install.ps1", "uninstall.ps1"):
        packaged = package_dir / name
        if not packaged.exists():
            failures.append(f"{packaged}: missing from package output")
            continue
        if not packaged.read_bytes().startswith(b"\xef\xbb\xbf"):
            failures.append(f"{packaged}: packaged PowerShell script must be UTF-8 BOM encoded")

if failures:
    for failure in failures:
        print(failure, file=sys.stderr)
    sys.exit(1)

print("windows installer encoding gate PASS")
PY
