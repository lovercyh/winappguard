# WinAppGuard

**See what's using your network, and block it in two clicks.**

[简体中文](README.md) · English

WinAppGuard is a Windows program network-control tool that works the other way round from most tools.
Instead of browsing a list of executables, it shows you **live TCP connections** — so you start
from *"what is talking to the internet right now?"* and end with *"blocked"*.

> WinAppGuard does not handle any traffic itself. All blocking is done by an independent filtering
> engine built on WFP: WinAppGuard only creates and cleans up WFP filters for you, while packet
> matching and blocking are performed by WFP in the Windows kernel.
> Since 2.0 it **no longer uses Windows Firewall** and never changes any Windows Firewall setting.

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
- **Blocks a program** — writes **two** outbound WFP filters (IPv4 + IPv6) for that executable,
  covering TCP **and** UDP. You can choose for **how long**: permanently, 30 minutes, 2 hours,
  or until the next restart — a timed block removes itself when it expires.
- **Unblocks it** — deletes the filters it created for that program.
- **Strict mode (off by default, advanced)** — a **true whitelist**: only whitelisted programs can
  reach the network. It opens a **dynamic WFP session inside this process** (whitelist permit at
  high weight + block-all at low weight), so it **changes no system setting**, and the restriction
  is **removed automatically** when the app exits, crashes, or is force-killed. A built-in list of
  required system programs (mostly `svchost.exe`) stays allowed so DNS / time sync / Windows Update
  keep working. The whitelist is what you add via *Add to whitelist*.
- **Keeps a list of everything it manages**, so you can always undo — even if the program
  is not running any more.
- **Optionally auto-starts at logon**, to the system tray.
- **Every rule lands in a dedicated WFP sublayer with a fixed GUID** — manage them on the *Rules*
  page; `wf.msc` will not show them (it only lists Windows Firewall's own rules).

## What it does **not** do

Being explicit about this matters, because the tool needs administrator rights.

- ❌ It does **not** filter, inspect, or route any traffic. The system's WFP does all of that.
- ❌ It does **not** change any Windows Firewall setting — it does not disable the firewall and does
  not change the default inbound or outbound action. **Strict mode is no exception**: it only opens
  an in-process session that is revoked on exit.
- ❌ It does **not** touch filters or rules created by anything else. It only sees and deletes
  filters under its own sublayer GUID.
- ❌ It does **not** block critical system processes (`lsass.exe`, `svchost.exe`, itself, …) —
  this guard applies to **blocking** only, never to allowing (an allow can never lock anyone out).
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

## Why another network-control tool?

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
- Administrator rights (it manages WFP filters and Task Scheduler)

## Command line

For scripting / batch deployment (needs **administrator rights**, including `--help`):

```powershell
WinAppGuard.exe --block "C:\Tools\a.exe"   # block a program (idempotent)
WinAppGuard.exe --list-blocked             # list every "block" rule
WinAppGuard.exe --unblock-all              # preview only, deletes nothing
WinAppGuard.exe --unblock-all --yes        # actually delete
WinAppGuard.exe --migrate                  # migrate 1.x rules to 2.0 and print a report
WinAppGuard.exe --recover                  # remove this tool's WFP objects and 1.x leftovers
WinAppGuard.exe --help                     # usage
```

- **Exit codes**: `0` ok / `1` bad arguments or not confirmed / `2` failed / `3` not elevated.
- `--list-blocked` prints **one rule per line**, tab separated, with `#` comment lines — easy to parse.
- On first launch, both the GUI and the CLI automatically migrate 1.x rules to 2.0; rule names stay
  the same.
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
| Blocking | **Two** outbound filters per executable path (IPv4 + IPv6), attached to WFP's `ALE_AUTH_CONNECT` layer, covering TCP + UDP |
| Rule naming | `AppGuard_Block_<exe name>_<8 hex chars of the path>` — deterministic, so re-blocking is idempotent |
| Firewall access | Calls `fwpuclnt.dll` directly (the WFP user-mode API) — 12 functions, no third-party library |
| Only its own objects | Every enumeration and deletion is filtered by the **sublayer GUID**; other software and system objects are never touched |
| Connection listing | `GetExtendedTcpTable` via `iphlpapi.dll` |
| Process path lookup | `QueryFullProcessImageNameW` (no `System.Diagnostics.Process` objects, so no handle leak while refreshing) |
| Auto-start | One Task Scheduler task named `WinAppGuard`, logon trigger, highest privileges, no execution time limit |
| Single instance | Named mutex + a broadcast window message, so launching it twice focuses the existing window |
| IP ownership | Team Cymru WHOIS over plain TCP to `whois.cymru.com:43` — the app's **only** outbound endpoint, batched and cached in memory, on by default, switchable off |
| Strict mode | Opens a **dynamic WFP session inside the process**: whitelist permit (high weight) + block all (low weight). **Revoked automatically** on exit or crash; changes no system setting |
| Timed blocks | The expiry is stored **in the filter's own description field** (`AppGuard\|1\|Block\|C:\path\a.exe\|自动解除=…`), so it survives restarts. A background 30-second timer removes expired filters and shows a tray notification. |

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
Native API calls (P/Invoke)   29                                → 17 Win32 + 12 WFP
Network-related native calls  none                              → nothing bypasses the managed check
Registry access               none
```

Two notes on that output:

- Since 1.2 the audit **no longer demands "zero networking types"**. It demands that every
  networking type is **on an expected list**, and it adds a check that nobody bypassed the managed
  types by calling `ws2_32` / `winhttp` / `wininet` through P/Invoke. An audit that stays green
  while a network path hides behind it would be worse than no audit at all.
- `--audit` needs no administrator rights, so it runs in CI too.

Those 29 native calls (17 Win32 + 12 WFP) are the complete set of unmanaged functions the program
can reach; the list above shows the 17 Win32 ones:

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

29. It cannot reach anything else below the .NET runtime.

## Safety guards

These are enforced **where rules are written**, not in the UI. Getting the UI logic wrong cannot
bypass them.

| Guard | Where |
|---|---|
| Only filters under its own sublayer GUID may be deleted — everything else is invisible and cannot be deleted | `WfpRuleStore` / `WfpEngine` |
| Critical processes are refused before a rule is created | `FirewallManager.ValidateProgramPath` |
| Missing file, non-`.exe`, or UNC path is refused | same |
| Existing connections: WFP blocks new ones; in practice the app drops offline immediately | — |
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
WinAppGuard.SelfCheck.exe                    # WFP: full automated test (creates then cleans up filters)
WinAppGuard.SelfCheck.exe --status           # WFP: read-only
WinAppGuard.SelfCheck.exe --leave            # 1.x compatibility: create one legacy Windows Firewall rule and keep it
WinAppGuard.SelfCheck.exe --cleanup          # delete all legacy AppGuard_ firewall rules
WinAppGuard.SelfCheck.exe --autostart-test   # auto-start: create → check → delete
WinAppGuard.SelfCheck.exe --audit            # audit the compiled assembly (no admin needed)
```

`--audit` is deliberately the only mode that runs without elevation, so CI can use it.

## FAQ

### Why does my antivirus flag this?

Because of what it legitimately does:

- writes WFP filters,
- creates a scheduled task that runs **at logon with highest privileges** — which is, technically,
  privilege persistence,
- reads the TCP connection table and resolves process paths.

Heuristic engines react to exactly that combination. Everything it creates is visible and
removable: the task is named `WinAppGuard` and is not hidden, and the filters all live in a
dedicated sublayer with a fixed GUID (one command cleans them up). Run `--audit` above if you
want to check the binary's capabilities.

### SmartScreen says "unknown publisher"

The exe is not code-signed — a code-signing certificate costs money and this is a free tool.
Click *More info* → *Run anyway*, or verify the SHA-256 against the release notes first.

### Why does it need administrator rights?

Writing WFP filters and registering a scheduled task both require elevation. The app
declares `requireAdministrator` in its manifest, so Windows prompts for UAC at launch.

### I closed the window but it's still running

By design. Closing the window minimises to the tray; quitting outright would leave WFP
filters active with no visible way to undo them. Use **tray icon → Exit** to really quit.

### Does quitting the app unblock everything?

**No.** Quitting only ends the UI process. The WFP filters stay in force and the blocked
programs stay blocked. To unblock, use *Allow selected program* or *Delete all AppGuard rules*.
The exit confirmation says this explicitly.

### How do I get rid of everything?

```
1. Open WinAppGuard
2. "Rules" tab → Delete all rules (or run: WinAppGuard.exe --recover)
3. "Settings" tab → turn off auto-start
4. Tray icon → Exit
5. Delete WinAppGuard.exe
6. (optional) delete %LOCALAPPDATA%\WinAppGuard
```

Skipping steps 2 and 3 leaves the filter sublayer and a scheduled task behind. If that happens,
run `WinAppGuard.exe --recover` to clear the WFP objects, and delete `WinAppGuard` in
`taskschd.msc`.

### Blocking works on paths, not PIDs

Rules match on program identity (the executable path), so:

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
