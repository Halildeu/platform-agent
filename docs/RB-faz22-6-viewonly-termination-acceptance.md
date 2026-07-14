# Faz 22.6 VIEW_ONLY termination acceptance

Status: source-readiness runbook. A merged commit is not live acceptance. Run
this only after the exact signed agent artifact has been rolled out by digest.

## Scope

The acceptance command closes only the active banner bound to the supplied
broker session. It sends the real Win32 `WM_CLOSE` message; the production path
must then produce:

1. helper IPC `INDICATOR_LOST`;
2. agent CONTROL audit event `AGENT_INDICATOR_LOST`;
3. broker terminal audit `KILLED:indicator-lost`;
4. no screen frame after the terminal boundary.

The trigger is disabled by default. It requires all of the following:

- exact process-local mode `ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ACCEPTANCE_MODE=test`;
- protected HKLM machine value `ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ACCEPTANCE_ALLOWED=test`;
- an elevated local Administrator process;
- the configured maintenance token, supplied on stdin only;
- the exact active broker session id;
- a matching, currently visible session-bound banner.

Wrong, stale, missing, malformed, non-test, non-elevated, or unauthorized input
fails closed. The command cannot choose a window message or inject IPC/input.

## Operator command

Run in elevated PowerShell on the attended test endpoint. Set `$SessionId` from
the protected collector output; do not paste a production credential.

```powershell
$ErrorActionPreference = "Stop"
$Exe = "C:\Program Files\EndpointAgent\endpoint-agent.exe"
$SessionId = "<ACTIVE_VIEW_ONLY_SESSION_ID>"
$ProtectedAcceptanceValue = "ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ACCEPTANCE_ALLOWED"
$Bstr = [IntPtr]::Zero

try {
  [Environment]::SetEnvironmentVariable($ProtectedAcceptanceValue, "test", "Machine")
  $SecureToken = Read-Host -Prompt "Fresh TEST maintenance token" -AsSecureString
  $Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
  $PlainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
  $env:ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ACCEPTANCE_MODE = "test"
  $PlainToken | & $Exe acceptance trigger-indicator-loss --session-id $SessionId
  if ($LASTEXITCODE -ne 0) {
    throw "indicator-loss acceptance trigger failed with exit code $LASTEXITCODE"
  }
}
finally {
  Remove-Item Env:\ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ACCEPTANCE_MODE -ErrorAction SilentlyContinue
  [Environment]::SetEnvironmentVariable($ProtectedAcceptanceValue, $null, "Machine")
  if ($Bstr -ne [IntPtr]::Zero) {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
  }
  $PlainToken = $null
  $SecureToken = $null
}
```

The command emits redacted JSON containing only the schema, opaque session
binding hash, submission time, and hygiene booleans. That JSON proves trigger
submission only. Final acceptance still requires the correlated agent/broker
events and post-terminal no-frame proof from the protected collector.
