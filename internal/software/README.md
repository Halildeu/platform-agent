# internal/software (AG-025) + internal/winget (AG-026, AG-026A)

Read-only Windows software inventory + WinGet App Installer readiness
probe foundation for the endpoint agent. **Discovery / enumeration
only — no install, no uninstall, no source repair, no elevation.**

## Scope

| Component | Surface |
|---|---|
| `software.Collect(now, opts)` | HKLM + HKLM\WOW6432Node Uninstall hives via `golang.org/x/sys/windows/registry`. Returns a `SoftwareSnapshot` with normalised `InstalledApp` entries. |
| `software.Normalize(sources, now, opts)` | Pure function: parses pre-read registry data into the wire-safe snapshot. Lets tests drive the parser without a real registry. |
| `software.Summarize(snap, wingetReady, wingetVersion, includeApps)` | Collapses snapshot + WinGet readiness into the `Summary` embedded in `inventory.Snapshot.Software`. |
| `winget.Detect(now)` / `winget.Probe(opts)` | AG-026 — locates `winget.exe`, runs `winget --version` under a 5 s timeout, reports `availableInCurrentContext` + `systemContextReady` separately. |
| `winget.DetectSourceEgress(now)` / `winget.RunSourceEgressPreflight(opts)` | AG-026A — read-only `winget source list` parser + fixed-id `winget show --id 7zip.7zip --exact --disable-interactivity` reachability probe + DNS/TCP/HTTPS checks against the hard-coded `DefaultEgressTargets` list. |

## Hard boundaries (verbatim — do not remove)

This package **NEVER**:

1. opens a raw shell, runs PowerShell, or invokes `winget install` /
   `winget upgrade` / `winget uninstall` / `winget source add|remove|update|reset` /
   `winget settings` / `winget export` / `winget import`.
   AG-026A widens the read-only surface to `winget source list` and
   `winget show --id 7zip.7zip --exact --disable-interactivity` (both
   fixed argv, hard-coded package id) but DOES NOT open install /
   mutation paths — those are scoped to AG-027 + BE-021A;
2. downloads a binary from any URL;
3. installs / uninstalls / upgrades / repairs any package;
4. resets passwords, disables/enables users, or touches any local-user
   adapter;
5. surfaces the raw `UninstallString` from the registry to the wire
   payload (only a presence bool plus, for MSI subkeys, the SHA-256
   hash of the canonicalised ProductCode GUID);
6. enumerates `HKCU` by default. Under the LocalSystem service hive,
   `HKCU` resolves to the `S-1-5-18` profile (NOT a human user) — a
   real per-user inventory means enumerating `HKEY_USERS\<SID>` hives
   and is a separate ticket;
7. claims a host is "deployment-ready for WinGet rollout" purely
   because the probe succeeded.

## Sanitisation

All free-form strings from the registry (DisplayName, Publisher,
DisplayVersion, probe error messages, executable paths) go through
`security.RedactSoftwareString` before leaving the process:

| Pattern | Replacement |
|---|---|
| JWT-style tokens (`eyJ…`) | `[REDACTED]` |
| `password=` / `pwd=` / `pass=` query-string or env style | `<key>=[REDACTED]` |
| Email / UPN | `[REDACTED]` |
| Full domain SIDs `S-1-5-21-…` | `S-1-5-21-REDACTED` |
| User-profile paths `C:\Users\<name>\…` | `C:\Users\[REDACTED]\…` |
| 5×5 alphanumeric license keys | `[REDACTED]` |

Dotted version triplets ("1.7.10861") survive — the patterns are tuned
to avoid clobbering versioned filenames or release strings.

## Payload discipline

* `DefaultMaxApps = 5000` — defence-in-depth against pathological hosts.
* `DefaultMaxPayloadBytes = 1 MiB` — Apps slice is repeatedly remarshalled
  during accumulation, so the cap is precise.
* `Truncated=true` is set when either cap fires; `AppCount` always
  records the pre-cap total so backend can flag overspill.
* Output ordering is deterministic (case-insensitive `DisplayName`, then
  `DisplayVersion`, then `InstallSource`) so HMAC-signed bodies are
  byte-stable across collects.

## How the inventory wiring uses it

`internal/inventory/inventory.go` (AG-025H lightweight contract):

* `inventory.Collect(...)` — heartbeat / auto-enroll default. Leaves
  `Snapshot.Software` **nil**; no registry enumeration, no WinGet probe.
  The wire payload omits the `software` field entirely thanks to the
  `omitempty` JSON tag.
* `inventory.CollectWithOptions(..., CollectOptions{IncludeSoftwareApps: true})`
  — explicit opt-in. Runs the registry enumeration + WinGet `--version`
  probe and attaches a full `Software *software.Summary` with the
  size-capped `Apps` list. This is the branch `internal/commands/executor.go`
  selects when the `COLLECT_INVENTORY` payload carries
  `includeSoftware: true`.

## Diagnose subcommands

```sh
endpoint-agent diagnose software   # JSON dump of SoftwareSnapshot
endpoint-agent diagnose winget     # JSON dump of WinGet Readiness
```

Both exit 0 even on probe errors — error visibility lives in the JSON
(`probeErrors`, `probeError`, `timeout`). Exit code 1 is reserved for
hard JSON-marshal failures, which should never happen in practice.

## Future-out-of-scope (DO NOT add here)

* **BE-020 Approved Software Catalog** — backend hash/publisher allowlist.
* **AG-027 7-Zip install adapter** — first WinGet pilot install, gated by
  BE-020.
* `HKEY_USERS\<SID>` enumeration for real per-user software view.
* `winget search` / `winget upgrade` invocation.
* Any `winget source` mutation subcommand (`add`, `remove`, `update`,
  `reset`). AG-026A read-only `winget source list` is in scope today
  (see scope table above); mutation paths stay out.
* `winget install` / `winget uninstall` (AG-027 + BE-021A scope).

These belong in separate, individually-reviewed PRs.
