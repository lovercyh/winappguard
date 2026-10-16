# WinAppGuard

**See what's using your network, and block it in two clicks.**

English · [简体中文](README.zh-CN.md)

WinAppGuard is a Windows firewall rule manager that works the other way round from most tools.
Instead of browsing a list of executables, it shows you **live TCP connections** — so you start
from *"what is talking to the internet right now?"* and end with *"blocked"*.

> WinAppGuard does not filter any traffic itself. All blocking is done by **Windows Firewall**.
> WinAppGuard only creates and cleans up the rules for you.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20x64-lightgrey.svg)](#requirements)
[![.NET](https://img.shields.io/badge/.NET-8%2B-512BD4.svg)](#build-from-source)
[![Release](https://img.shields.io/github/v/release/lovercyh/winappguard)](https://github.com/lovercyh/winappguard/releases/latest)
[![Build](https://github.com/lovercyh/winappguard/actions/workflows/build.yml/badge.svg)](https://github.com/lovercyh/winappguard/actions/workflows/build.yml)

![Connections tab](docs/screenshots/01-connections.png)

---

## What it does

- **Lists live TCP connections** with program name, full path, PID, local port, remote IP,
  remote port, state, protocol (IPv4/IPv6) and **the program's digital signature**.
- **Blocks a program** — writes a single outbound Windows Firewall rule (TCP **and** UDP) for
  that executable.
- **Unblocks it** — deletes the rules it created for that program.
- **Keeps a list of everything it manages**, so you can always undo — even if the program
  is not running any more.
- **Optionally auto-starts at logon**, to the system tray.
- **Every rule it creates is named `AppGuard_*`** so you can find them in `wf.msc` yourself.

## What it does **not** do

Being explicit about this matters, because the tool needs administrator rights.

- ❌ It does **not** filter, inspect, or route any traffic. Windows Firewall does all of that.
- ❌ It does **not** change global firewall policy. It never enables/disables the firewall and
  never touches the default inbound/outbound actions.
- ❌ It does **not** touch firewall rules created by anything else. Deletion is hard-limited to
  rules whose name starts with `AppGuard_`.
- ❌ It does **not** block critical system processes (`lsass.exe`, `svchost.exe`, itself, …).
- ❌ It does **not** send anything anywhere. No telemetry, no analytics, no update check.
- ⚠️ **But it does reach the network by default** — see the honest note below.

### About "no network" — the honest version

WinAppGuard's own code contains **zero networking APIs**. That part is verifiable with `--audit`.

However, the **digital signature column** checks certificate revocation status by default. That makes
Windows' certificate services (Crypt32) contact CA servers on the tool's behalf. You will see
`WinAppGuard.exe` making outbound connections in Resource Monitor.

- **This is a deliberate trade-off**: checking revocation gives a more accurate answer about whether a
  certificate has been revoked.
- **You can turn it off**: *Settings → Data & privacy* → uncheck "check certificate revocation status".
  The tool then reads only the local revocation cache and makes **no network traffic at all**.
- It is always **Windows' certificate service** doing the fetching, never application code, and nothing
  about you or your machine is ever sent — it is a standard CRL/OCSP lookup.

- ❌ It does **not** use the registry for persistence. Auto-start uses Task Scheduler only.

## Why another firewall tool?

Most firewall GUIs start from a list of installed programs. That is fine when you already know
what you want to block.

WinAppGuard starts from **live connections**. That is the right starting point when you don't:
you notice traffic, you want to know which program is responsible, and you want it gone.
The recovery path is designed around the same idea — blocked programs disappear from the
connection list (they can't connect any more), so there is a dedicated
**"Blocked programs"** tab that lists your rules instead of your connections.

## Download

Grab `WinAppGuard.exe` from the [latest release](https://github.com/lovercyh/winappguard/releases/latest).

- Single self-contained file, ~49 MB. No .NET installation required.
- Verify your download against the SHA-256 listed in the release notes:
  ```powershell
  Get-FileHash .\WinAppGuard.exe -Algorithm SHA256
  ```
- **The exe is not code-signed**, so SmartScreen will warn about an unknown publisher.
  This is expected — see the [FAQ](#faq).

## Requirements

- Windows 10 or Windows 11, x64
- Administrator rights (it edits firewall rules and Task Scheduler)

## Screenshots

| Blocked programs | Settings |
|---|---|
| ![Rules tab](docs/screenshots/02-rules.png) | ![Settings tab](docs/screenshots/03-settings.png) |

![Block confirmation](docs/screenshots/04-confirm-block.png)

Every state-changing action goes through a confirmation dialog that names the exact program,
its full path, the scope of the change, and the rule that is about to be created or deleted.

## How it works

| Concern | Implementation |
|---|---|
| Blocking | One outbound Windows Firewall rule per executable path, protocol *any* (TCP + UDP), all profiles |
| Rule naming | `AppGuard_Block_<exe name>_<8 hex chars of the path>` — deterministic, so re-blocking is idempotent |
| Firewall access | Windows Firewall COM API (`HNetCfg.FwPolicy2`) — no third-party library |
| Connection listing | `GetExtendedTcpTable` via `iphlpapi.dll` |
| Process path lookup | `QueryFullProcessImageNameW` (no `System.Diagnostics.Process` objects, so no handle leak while refreshing) |
| Auto-start | One Task Scheduler task named `WinAppGuard`, logon trigger, highest privileges, no execution time limit |
| Single instance | Named mutex + a broadcast window message, so launching it twice focuses the existing window |

## Verifiable trust

Most tools ask you to take their word for it. This one ships with the means to check:

```powershell
WinAppGuard.SelfCheck.exe --audit
```

This does **not** grep the source. It reads the **metadata of the compiled assembly** — including
indirect references and anything the framework drags in — and reports:

```
Referenced assemblies        22, all from the .NET framework    → no third-party libraries
Networking types referenced  0                                   → no networking code in the app
Native API calls (P/Invoke)  16
Registry access              none
```

Those 16 native calls are the complete set of unmanaged functions the program can reach:

```
iphlpapi.dll!GetExtendedTcpTable                    read the TCP connection table
kernel32.dll!OpenProcess                            open a process (to resolve its path)
kernel32.dll!QueryFullProcessImageNameW             query a process's executable path
kernel32.dll!CloseHandle                            close a handle
user32.dll!RegisterWindowMessageW                   register the single-instance window message
user32.dll!PostMessageW                             broadcast the single-instance window message
wintrust.dll!WinVerifyTrust                         verify an embedded Authenticode signature
wintrust.dll!CryptCATAdminAcquireContext2           open a catalog-signature context
wintrust.dll!CryptCATAdminCalcHashFromFileHandle2   hash a file (to look it up in a catalog)
wintrust.dll!CryptCATAdminEnumCatalogFromHash       find the catalog containing that hash
wintrust.dll!CryptCATCatalogInfoFromContext         read the catalog file path
wintrust.dll!CryptCATAdminReleaseCatalogContext     release the catalog context
wintrust.dll!CryptCATAdminReleaseContext            release the catalog admin context
wintrust.dll!WTHelperProvDataFromStateData          read data from a verification state
wintrust.dll!WTHelperGetProvSignerFromChain         read the signer
wintrust.dll!WTHelperGetProvCertFromChain           read the signer's certificate
```

16. It cannot reach anything else below the .NET runtime.

## Safety guards

These are enforced **in the firewall layer**, not in the UI. Getting the UI logic wrong cannot
bypass them.

| Guard | Where |
|---|---|
| Only rules named `AppGuard_*` may be deleted — everything else is rejected with an exception | `FirewallManager.DeleteRule` |
| Critical processes are refused before a rule is created | `FirewallManager.ValidateProgramPath` |
| Missing file, non-`.exe`, or UNC path is refused | same |
| Existing connections: the firewall blocks new ones; in practice the app drops offline immediately | — |
| All dangerous actions require confirmation | `Forms/ConfirmForm.cs` |

Full details, plus copy-pasteable verification steps for each claim:
[`docs/安全说明.md`](docs/安全说明.md) (Chinese).

## Build from source

Requires the [.NET SDK 10](https://dotnet.microsoft.com/download) or newer.

```powershell
git clone https://github.com/lovercyh/winappguard.git
cd winappguard

dotnet build WinAppGuard.sln -c Debug

# Produce dist\WinAppGuard.exe (win-x64, self-contained, single file)
powershell -ExecutionPolicy Bypass -File .\build\publish.ps1
```

The build must produce **0 warnings and 0 errors**. Warnings are treated as defects in this
project, not as noise.

### Self-check tool

`tools/SelfCheck` is a development tool, not part of the shipped product. It can:

```powershell
WinAppGuard.SelfCheck.exe                    # firewall: full automated test (creates then cleans up rules)
WinAppGuard.SelfCheck.exe --status           # firewall: read-only
WinAppGuard.SelfCheck.exe --leave            # firewall: create one demo rule and keep it, for inspecting in wf.msc
WinAppGuard.SelfCheck.exe --cleanup          # firewall: delete all AppGuard_ rules
WinAppGuard.SelfCheck.exe --autostart-test   # auto-start: create → check → delete
WinAppGuard.SelfCheck.exe --audit            # audit the compiled assembly (no admin needed)
```

`--audit` is deliberately the only mode that runs without elevation, so CI can use it.

## FAQ

### Why does my antivirus flag this?

Because of what it legitimately does:

- creates Windows Firewall rules,
- creates a scheduled task that runs **at logon with highest privileges** — which is, technically,
  privilege persistence,
- reads the TCP connection table and resolves process paths.

Heuristic engines react to exactly that combination. Everything it creates is visible and
removable: the task is named `WinAppGuard` and is not hidden, and the firewall rules are all
prefixed `AppGuard_`. Run `--audit` above if you want to check the binary's capabilities.

### SmartScreen says "unknown publisher"

The exe is not code-signed — a code-signing certificate costs money and this is a free tool.
Click *More info* → *Run anyway*, or verify the SHA-256 against the release notes first.

### Why does it need administrator rights?

Creating firewall rules and registering a scheduled task both require elevation. The app
declares `requireAdministrator` in its manifest, so Windows prompts for UAC at launch.

### I closed the window but it's still running

By design. Closing the window minimises to the tray; quitting outright would leave firewall
rules active with no visible way to undo them. Use **tray icon → Exit** to really quit.

### Does quitting the app unblock everything?

**No.** Quitting only ends the UI process. The firewall rules stay in force and the blocked
programs stay blocked. To unblock, use *Allow selected program* or *Delete all AppGuard rules*.
The exit confirmation says this explicitly.

### How do I get rid of everything?

```
1. Open WinAppGuard
2. "Blocked programs" tab → Delete all AppGuard rules
3. "Settings" tab → turn off auto-start
4. Tray icon → Exit
5. Delete WinAppGuard.exe
6. (optional) delete %LOCALAPPDATA%\WinAppGuard
```

Skipping steps 2 and 3 leaves rules and a scheduled task behind. If that happens, search for
`AppGuard` in `wf.msc` and `WinAppGuard` in `taskschd.msc`.

### Blocking works on paths, not PIDs

Windows Firewall matches on the executable path, so:

- all instances of that path are blocked together, regardless of arguments;
- the same program run from a different directory is **not** affected;
- if the program updates and moves, the rule stops applying — block it again.

### Why do blocked programs vanish from the connections list?

Because they can no longer connect, so they have no connections to list. Use the
**Blocked programs** tab to manage them — that tab is driven by your rules, not by live traffic.

### Where is the log?

`%LOCALAPPDATA%\WinAppGuard\logs\`, one file per day, last 7 days kept. Local only — nothing is
ever uploaded. The Settings tab shows the path and has a button to open it.

## Documentation

All documentation is in Chinese.

| Document | Contents |
|---|---|
| [`docs/安全说明.md`](docs/安全说明.md) | The security model, with a verification method for every claim |
| [`docs/验收清单.md`](docs/验收清单.md) | Full acceptance checklist (automated results + manual items) |
| [`docs/测试用例.md`](docs/测试用例.md) | Per-phase test cases and measured results |
| [`docs/发布手册.md`](docs/发布手册.md) | Build → verify → release workflow |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Short version: **code comments and commit messages are
in Chinese**, the build must be warning-free, and behaviour changes should come with an
assertion that would have caught the bug.

## License

[MIT](LICENSE).
