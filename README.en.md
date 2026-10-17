# WinAppGuard

**See what's using your network, and block it in two clicks.**

[简体中文](README.md) · English

WinAppGuard is a Windows firewall rule manager that works the other way round from most tools.
Instead of browsing a list of executables, it shows you **live TCP connections** — so you start
from *"what is talking to the internet right now?"* and end with *"blocked"*.

> WinAppGuard does not filter any traffic itself. All blocking is done by **Windows Firewall**.
> WinAppGuard only creates and cleans up the rules for you.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20x64-lightgrey.svg)](#requirements)
[![.NET](https://img.shields.io/badge/.NET-10-512BD4.svg)](#build-from-source)
[![Release](https://img.shields.io/github/v/release/lovercyh/winappguard)](https://github.com/lovercyh/winappguard/releases/latest)
[![Build](https://github.com/lovercyh/winappguard/actions/workflows/build.yml/badge.svg)](https://github.com/lovercyh/winappguard/actions/workflows/build.yml)

![Connections tab](docs/screenshots/01-connections.png)

---

## What it does

- **Lists live TCP connections** with program name, full path, PID, local port, remote IP,
  remote port, state, protocol (IPv4/IPv6) and **the program's digital signature**.
- **Tells you who a connection belongs to** — hover a remote IP to see its country and
  network operator (autonomous system).
- **Search and sort the list** — filter by process name, PID, remote IP or remote port;
  click a column header to sort (ports and IPs sort **numerically**, not as text).
- **Blocks a program** — writes a single outbound Windows Firewall rule (TCP **and** UDP) for
  that executable. You can choose for **how long**: permanently, 30 minutes, 2 hours,
  or until the next restart — a timed block removes itself when it expires.
- **Unblocks it** — deletes the rules it created for that program.
- **Strict mode (off by default, advanced)** — sets Windows' *default outbound action* to **block**,
  so only whitelisted programs can reach the network. The whitelist is what you add via
  *Add to whitelist*. It is **session-scoped**: quitting the app (or the next launch after a crash)
  restores the default action to *allow* automatically. It never touches other programs' rules —
  which is why built-in Windows rules and rules created by other software still let their
  programs through, and why the **Release** column shows that fact in three distinct states
  instead of a vague "allowed".
- **Keeps a list of everything it manages**, so you can always undo — even if the program
  is not running any more.
- **Optionally auto-starts at logon**, to the system tray.
- **Every rule it creates is named `AppGuard_*`** so you can find them in `wf.msc` yourself.

## What it does **not** do

Being explicit about this matters, because the tool needs administrator rights.

- ❌ It does **not** filter, inspect, or route any traffic. Windows Firewall does all of that.
- ❌ It does **not** change global firewall policy — **the one exception is strict mode**
  (off by default, must be turned on explicitly, and reverts automatically when the app exits).
  Apart from that it never enables/disables the firewall and never touches the default inbound action.
- ❌ It does **not** touch firewall rules created by anything else. Deletion is hard-limited to
  rules whose name starts with `AppGuard_`.
- ❌ It does **not** block critical system processes (`lsass.exe`, `svchost.exe`, itself, …).
- ⚠️ It **does** reach the network by default, for two specific purposes (see below).
  It sends **no telemetry, no analytics, no usage data**, and there is no update check.

### About "no network" — the honest version

**WinAppGuard is not a zero-network program, and these docs no longer pretend otherwise.**
Up to 1.1 it *was* — the app's own code contained zero networking APIs. 1.2 added the IP ownership
lookup, so that claim was **retired** rather than kept alive with careful wording.

There are exactly **two** things that touch the network. Both are on by default, and **both can be
switched off** in *Settings → Data & privacy*:

| | Who initiates it | What is sent | Where it goes |
|---|---|---|---|
| **IP ownership lookup** | WinAppGuard's own code | the **remote IP** only | `whois.cymru.com:43` |
| **Certificate revocation check** | Windows' certificate service (Crypt32) | a CRL/OCSP lookup | that certificate's CA |

Turn both off and WinAppGuard makes **no network traffic at all**.

**About the IP ownership lookup** (new in 1.2). It resolves each connection's remote IP to a country
and an autonomous system, so the connection list answers *"who am I talking to?"* and not just
*"which IP?"*:

- Only the **remote IP** is sent — never the process name, path, PID, port, or anything else local.
- LAN / loopback / link-local addresses are **filtered out before sending**; they never leave the machine.
- Connecting by hostname means the .NET runtime performs one DNS lookup for `whois.cymru.com`.
  That is not an HTTP request, but it is a real name resolution, so it is stated rather than hidden.
- Switching it off is **persistent** (stored in `settings.json`) — it will not silently come back
  on the next launch.
- The very first launch shows a one-time notice explaining the above.

**About the revocation check**: it is always **Windows' certificate service** doing the fetching,
never application code, and nothing about you or your machine is sent — it is a standard CRL/OCSP
lookup. Turn it off and the tool reads only the local revocation cache.

- ❌ It does **not** use the registry for persistence. Auto-start uses Task Scheduler; settings go to
  a plain JSON file under `%LOCALAPPDATA%`.

## Why another firewall tool?

Most firewall GUIs start from a list of installed programs. That is fine when you already know
what you want to block.

WinAppGuard starts from **live connections**. That is the right starting point when you don't:
you notice traffic, you want to know which program is responsible, and you want it gone.
The recovery path is designed around the same idea — blocked programs disappear from the
connection list (they can't connect any more), so there is a dedicated
**"Rules"** tab that lists your rules instead of your connections.

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

## Command line

For scripting / batch deployment (needs **administrator rights**, including `--help`):

```powershell
WinAppGuard.exe --block "C:\Tools\a.exe"   # block a program (idempotent)
WinAppGuard.exe --list-blocked             # list every "block" rule
WinAppGuard.exe --unblock-all              # preview only, deletes nothing
WinAppGuard.exe --unblock-all --yes        # actually delete
WinAppGuard.exe --help                     # usage
```

- **Exit codes**: `0` ok / `1` bad arguments or not confirmed / `2` failed / `3` not elevated.
- `--list-blocked` prints **one rule per line**, tab separated, with `#` comment lines — easy to parse.
- These commands do **not** show a confirmation dialog (the command line *is* the instruction);
  operations in the GUI still ask every time.
- Starting the GUI briefly shows a console window (~0.5 s) — the price of a synchronous CLI —
  then it closes itself.

## Screenshots

| Rules | Settings |
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
| IP ownership | Team Cymru WHOIS over plain TCP to `whois.cymru.com:43` — the app's **only** outbound endpoint, batched and cached in memory, on by default, switchable off |
| Timed blocks | The expiry is stored **in the firewall rule's own description** (`自动解除=…`), so it is visible in `wf.msc` and survives restarts. A background 30-second timer removes expired rules and shows a tray notification. |
| Strict mode | Sets the *default outbound action* to block on all three network profiles, combined with the app's own `AppGuard_Allow_*` whitelist rules. **Session-scoped** (reverted on exit, and recovered on the next launch after a crash); it can only be enabled when all three profiles are currently set to allow. |

## Verifiable trust

Most tools ask you to take their word for it. This one ships with the means to check:

```powershell
WinAppGuard.SelfCheck.exe --audit
```

This does **not** grep the source. It reads the **metadata of the compiled assembly** — including
indirect references and anything the framework drags in — and reports:

```
Referenced assemblies         25, all from the .NET framework   → no third-party libraries
Networking types referenced   2 — TcpClient / NetworkStream     → the IP ownership lookup only
Native API calls (P/Invoke)   16
Network-related native calls  none                              → nothing bypasses the managed check
Registry access               none
```

Two notes on that output:

- Since 1.2 the audit **no longer demands "zero networking types"**. It demands that every
  networking type is **on an expected list**, and it adds a check that nobody bypassed the managed
  types by calling `ws2_32` / `winhttp` / `wininet` through P/Invoke. An audit that stays green
  while a network path hides behind it would be worse than no audit at all.
- `--audit` needs no administrator rights, so it runs in CI too.

Those 17 native calls are the complete set of unmanaged functions the program can reach:

```
iphlpapi.dll!GetExtendedTcpTable                    read the TCP connection table
kernel32.dll!OpenProcess                            open a process (to resolve its path)
kernel32.dll!QueryFullProcessImageNameW             query a process's executable path
kernel32.dll!CloseHandle                            close a handle
kernel32.dll!FreeConsole                             drop the console window in GUI mode
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
2. "Rules" tab → Delete all AppGuard rules
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
**Rules** tab to manage them — that tab is driven by your rules, not by live traffic.

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
