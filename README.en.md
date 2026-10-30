# WinAppGuard

**See what's online. Block it in two clicks.**

**An open-source firewall** · WFP-based program network control · **source available for audit and self-build**

[简体中文](README.md) · English

> Source & license: [github.com/lovercyh/winappguard](https://github.com/lovercyh/winappguard) (MIT)

WinAppGuard is a Windows program network-control tool that starts from the opposite end
of most tools in its class. Instead of asking you to browse a list of installed programs,
it shows you **live TCP connections** — so you start with *"what is online right now?"*
and finish with *"blocked."*

> WinAppGuard does not forward or modify traffic itself. The real work is done by an independent
> filtering engine built on WFP: WinAppGuard only creates and removes WFP filters on your
> behalf, while packet matching and blocking happen in the Windows kernel.
> The 4.0 anti-scan reads inbound TCP headers only; it does not read payloads or drop packets inline.
> Since 2.0 it no longer uses Windows Firewall, and it never changes any Windows Firewall setting.
>
> **Since 3.0 the product is split into a protection service and a UI.** Rule writes, the
> strict-mode session and audit collection all live in `WinAppGuardSvc`; the UI runs as a
> normal process and only asks for UAC when it needs to change a rule.
>
> **Since 3.1 the service runs in protected mode.** The account that installs the app becomes
> the **sole owner**. The service only accepts requests signed by that owner, so other accounts
> — including other administrators — cannot change rules through the UI or IPC. The private key
> is encrypted with user-scoped DPAPI; the service only stores the public key. See
> [`docs/受保护模式设计.md`](docs/受保护模式设计.md) for details.
>
> **4.0 adds anti-port-scan.** It uses Npcap to inspect inbound TCP SYNs, detects port
> scans, and can temporarily block the source IP. Automatic blocking is **off by default** and
> only affects new connections. See [`docs/4.0-反端口扫描设计.md`](docs/4.0-反端口扫描设计.md).
>
> **4.1 makes traffic statistics precise and Npcap mandatory.** Traffic is counted per packet
> (TCP + UDP, short-lived and failed connections included), with live rates and a 5-minute chart.
> Declining Npcap aborts the installation without changing the system. See
> [`docs/4.1-精确流量与实时速率设计.md`](docs/4.1-精确流量与实时速率设计.md).
>
> **4.2 adds LAN spoofing detection.** The *Protection* tab now has a *LAN* sub-tab that detects
> ARP spoofing (gateway MAC changes, etc.) and rogue DHCP servers. Detection only by default;
> baselines and events are stored locally, with an optional temporary DHCP block. See
> [`docs/4.2-局域网欺骗检测设计.md`](docs/4.2-局域网欺骗检测设计.md).
>
> **4.3 adds DNS security.** A new *DNS security* sub-tab detects local DNS hijacking/poisoning
> (unexpected response server, transaction/name mismatch, NXDOMAIN with answers, conflicting
> answers, suspicious TTL, DNS server not gateway) and **plaintext DNS bypass**. Alert only,
> never blocks; events reuse the 4.2 store and retention. See
> [`docs/4.3-DNS安全设计.md`](docs/4.3-DNS安全设计.md).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20x64-lightgrey.svg)](#requirements)
[![.NET](https://img.shields.io/badge/.NET-10-512BD4.svg)](#build-from-source)
[![Release](https://img.shields.io/github/v/release/lovercyh/winappguard)](https://github.com/lovercyh/winappguard/releases/latest)
[![Build](https://github.com/lovercyh/winappguard/actions/workflows/build.yml/badge.svg)](https://github.com/lovercyh/winappguard/actions/workflows/build.yml)

![Connections tab](docs/screenshots/01-connections.png)

---

## What it does

- **Lists live TCP connections** — program name, full path, PID, local port, remote IP,
  remote port, state, protocol (IPv4/IPv6), and **the program's digital signature**.
- **Tells you who a connection belongs to** — hover a remote IP to see its country/region
  and network operator (autonomous system).
- **Search and sort** — filter by process name, PID, remote IP or remote port; click a column
  header to sort. Ports and IPs sort **numerically**, not as text.
- **Blocks a program** — creates an outbound rule for that executable, covering TCP and UDP
  over both IPv4 and IPv6. You can choose **how long** the block lasts: permanently, 30 minutes,
  2 hours, or until the next restart. A timed block removes itself when it expires.
- **Unblocks it** — deletes the filters it created for that program.
- **Strict mode (off by default, advanced)** — a **real whitelist**: only listed programs can
  reach the network. It opens a dynamic session **inside the protection service** (allow the
  whitelist at high weight, block everything at low weight), so it **changes no system setting**.
  Closing the UI leaves protection on; stopping, crashing or force-killing the service
  **removes the restriction immediately**. A built-in list of required system programs
  (mostly `svchost.exe`) stays allowed so DNS, time sync and Windows Update keep working.
- **Per-program traffic** — the Connections page shows **upload / download / total** for each
  program since the service started. Since 4.1 the numbers come from Npcap packet counting
  (TCP + UDP, short-lived and failed connections included).
- **Traffic page** — inbound/outbound/down/up per program with a **live 5-minute chart**;
  sort by any column, search, pause collection, or clear everything with one UAC.
  Bytes are IP payload, retransmissions included, loopback excluded; traffic that cannot be
  attributed is listed separately as *Unattributed*.
- **DNS page** — the latest queried **domains, PID, program and result**. Only names seen by the
  Windows DNS client are recorded; **no URLs or response contents**; DoH/DoT may be invisible.
- **Dedicated rules page** — manage every rule the tool has created, even if the program
  is no longer running.
- **Flow IDS (detection only, never blocking)** — the *IDS* page is enabled by default and uses
  connection metadata plus DNS records to flag periodic beaconing, port/host scans, lateral
  movement and DNS anomalies. Alerts stay local for 30 days and can be acknowledged, suppressed
  or cleared. The IDS itself reads no payloads and never blocks.
- **Anti-port-scan (4.0)** — the *Protection → Port scan* tab uses Npcap to inspect inbound TCP SYN
  packets and detect port scans. It can temporarily block the source IP for 5 / 10 / 30 / 60
  minutes; automatic blocking is **off by default**, affects new connections only, and never cuts
  existing sessions. The status bar shows `Npcap: connected / not connected`; clicking it while
  disconnected installs Npcap from the bundled official installer.
- **LAN spoofing detection (4.2)** — the *Protection → LAN* tab detects **ARP spoofing**
  (gateway MAC changes, a MAC claiming many IPs, IP/MAC flapping, …) and **rogue DHCP**
  (unexpected/multiple servers, changed options, very short leases). Detection only by default;
  baselines can be trusted; events are stored locally with 7 / 15 / 30-day retention; an optional
  temporary DHCP server block is available (off by default).
- **DNS security (4.3)** — the *Protection → DNS security* tab detects **local DNS hijacking /
  poisoning** (unexpected response server, transaction/name mismatch, NXDOMAIN with answers,
  conflicting answers, suspicious TTL, DNS server not gateway) and **plaintext DNS bypass**.
  8 rules, a 2-minute quiet baseline, a trust list, and 7 / 15 / 30-day event retention;
  **alert only, never blocks**. It captures IPv4 UDP 53 only; DoH/DoT is out of scope,
  and IPv6 DNS / neighbour security is planned for 4.4.
- **Timed lockdown** — 30 minutes / 2 hours from the strict-mode panel or tray menu. It lifts
  itself when time is up, and is also revoked if the service stops or crashes.
- **Records page** — who connected to what and whether it was blocked: type (connection /
  blocked), program, remote endpoint, **guessed domain**, and **which rule matched**. Search,
  filter to blocked only, or clear everything. Records are local only, enabled by default, and
  retention is configurable (1 / 3 / 7 / 30 days, default 7).
- **Block an IP** — select a connection on the Records page and choose *Block this IP*, or add
  one manually. The rule matches the **remote IP** (IPv4/IPv6) without DNS resolution, so other
  services on that IP are blocked as well.
- **Separate Blocklist and Strict-mode whitelist pages** — the blocklist answers "who may not go
  online" (program blocks + blocked IPs, with a *Type* column); the whitelist answers "who may go
  online while strict mode is on," and the page says whether it is currently in effect. Both pages
  have search and can add a program **by path** (under strict mode, an unlisted program never
  reaches the network, so it never appears on the Connections page).
- **Fine-grained rules** — restrict a rule to a **protocol** (TCP/UDP) and a **remote port**
  (single or range). The rule lists show a *Scope* column.
- **Rule groups** — a *Group* column and group filter on both lists. Groups only affect how rules
  are organised in the UI; they never change whether a rule is active.
- **Rule export / import** — the blocklist and whitelist each have *Export* and *Import*,
  including groups. Import only creates rules and never deletes; invalid files are rejected as a
  whole, and a file exported from the other list is refused instead of silently creating the
  wrong rules.
- **Shortcuts** — `F5` refresh, `Ctrl+F` search, `Esc` clear, `Delete` remove the selected entry.
- **Interface language** — switch between Follow system / 简体中文 / English from the status bar;
  non-Chinese systems default to English, and a restart applies the change.
- **Installer / uninstaller are always bilingual (Chinese + English)** — no language switch there.
  **The CLI follows the language the UI is actually running in**, and `--lang zh|en|auto` overrides
  it for one invocation.
- **Service logs are always English with stable event codes** (for example `WAG-RULE-913`) — they do
  not follow the UI language, which makes them searchable and safe to paste into a bug report.
- **Remembers window size and column widths** — sizes only, no private data. The Records page
  also lets you right-click to copy a remote address, program path, or domain.
- **Optional auto-start at logon**, straight to the system tray.
- **Every rule lives in a dedicated WFP sublayer with a fixed GUID** — manage them on the two
  list pages; `wf.msc` will not show them, because it only lists Windows Firewall's own rules.

## What it does **not** do

This needs to be explicit.

- ❌ It does **not** filter, inspect, or forward any traffic — Windows WFP does all of that.
- ❌ It does **not** change any Windows Firewall setting, disable the firewall, or change the
  default inbound/outbound action. **Strict mode is no exception**: its session lives inside the
  service and is revoked when the service stops.
- ❌ It does **not** touch filters or rules created by anyone else. It only sees and deletes
  filters under its own sublayer GUID.
- ❌ It does **not** block critical system processes (`lsass.exe`, `svchost.exe`, itself, …).
  This guard applies to **blocking** only, never to allowing.
- ❌ Its IDS is **detection only**: it never drops, blocks or rewrites traffic automatically,
  does not decrypt HTTPS, and does not fetch external threat intelligence.
- ❌ It does **not** store packets or payloads and does not do DPI/HTTPS decryption:
  precise traffic reads only IP/TCP/UDP headers (lengths, ports, flags) for accounting;
  DNS stores names only, never URL paths; DNS security parses only DNS headers, the question
  section and A/AAAA/CNAME answers, and never stores packets.
- ❌ DNS security is **alert only** and never blocks; it captures **IPv4 UDP 53** only, so DoH/DoT
  is invisible; an upstream server returning forged data is only caught when it conflicts with
  another response to the same query.
- ❌ Anti-port-scan only inspects **inbound TCP SYN**; no UDP scans, payload inspection or
  permanent automatic blocking. Without Npcap both traffic statistics and anti-scan are
  unavailable (the installer requires Npcap).
- ⚠️ It **does** use the network by default, for exactly three purposes (below). There is
  **no telemetry, no analytics, and no update check**.

### About "no network" — the honest version

**WinAppGuard is not a zero-network program, and the documentation no longer pretends otherwise.**
Up to 1.1 it was: the application itself contained no networking code. 1.2 added the IP ownership
lookup, so that claim was **retired** rather than kept alive with careful wording.

Only three things touch the network. All are on by default, and **all three can be switched off**
in the UI:

| | Initiated by | What is sent | Where it goes | How to turn it off |
|---|---|---|---|---|
| **IP ownership lookup** | WinAppGuard's own code | the **remote IP** only | `whois.cymru.com:43` | Settings → Data & privacy |
| **Certificate revocation check** | Windows' certificate service (Crypt32) | a CRL/OCSP lookup | that certificate's CA | Settings → Data & privacy |
| **Domain guessing** | WinAppGuard's own code | DNS lookups (**only names already in the system cache**) | your configured DNS server | Records page toggle |

With all three off, WinAppGuard makes **no network traffic at all**.

> About domain guessing: it reads the Windows DNS cache. If an entry has just expired, Windows
> may send one lookup to your configured DNS server. With it off, the app sends **no DNS queries**;
> the cost is that domain coverage on the Records page drops noticeably (about 29% → 8% in our
> measurements).

**About the IP ownership lookup** (added in 1.2): it resolves each connection's remote IP to a
country/region and autonomous system, so the connection list can answer *"who am I talking to?"*
rather than just *"which IP?"*:

- Only the **remote IP** is sent — never the process name, path, PID, port, or any other local data.
- LAN / loopback / link-local addresses are **filtered out before sending**; they never leave the machine.
- Connecting by hostname means the .NET runtime performs one DNS lookup for `whois.cymru.com`.
  That is not an HTTP request, but it is a real name resolution, so it is stated rather than hidden.
- Turning it off is **persistent** (stored in `settings.json`); it will not quietly come back on
  the next launch.
- The first launch shows a one-time notice explaining all of this.

**About the revocation check**: the request is always made by **Windows' certificate service**,
not by application code. Nothing about you or your machine is sent — it is a standard CRL/OCSP
lookup. Turn it off and the tool reads only the local cache.

- ❌ It does **not** use the registry for persistence. Auto-start uses Task Scheduler; settings
  are written to a file under `%LOCALAPPDATA%`.

## Command line

For scripting and batch deployment (**administrator rights required**, including `--help`):

```powershell
WinAppGuard.exe --block "C:\Tools\a.exe"   # block a program (idempotent)
WinAppGuard.exe --list-blocked             # list every block rule
WinAppGuard.exe --unblock-all              # preview only; deletes nothing
WinAppGuard.exe --unblock-all --yes        # actually delete
WinAppGuard.exe --migrate                  # migrate 1.x rules and print a report
WinAppGuard.exe --recover                  # remove this tool's WFP objects and 1.x leftovers
WinAppGuard.exe --help                     # usage
WinAppGuard.exe --list-blocked --lang en   # English for this run (default: follow the UI)
```

- **Language**: follows the language the UI is actually running in; `--lang zh|en|auto` affects only
  this invocation and writes no settings.
- **Exit codes**: `0` success / `1` bad arguments or not confirmed / `2` failed / `3` not elevated.
- `--list-blocked` prints **one rule per line**, tab-separated, with `#` comment lines — easy to parse.
- Since 3.1, `--block`, `--list-blocked` and `--unblock-all` go through **signed IPC** to the
  protection service. `--migrate` and `--recover` remain administrator recovery commands that
  work directly with WFP.
- These commands **never show a confirmation dialog** (the command line *is* the instruction).
  Operations in the GUI still ask every time.
- Starting the GUI briefly shows a console window (~0.5 s) — the price of a synchronous CLI —
  then it closes itself.

## Screenshots

| IDS (detection only) | Protection (port scan) |
|---|---|
| ![IDS tab](docs/screenshots/06-ids.png) | ![Protection (port scan)](docs/screenshots/09-protection.png) |
| **Traffic** | **DNS** |
| ![Traffic tab](docs/screenshots/07-traffic.png) | ![DNS tab](docs/screenshots/08-dns.png) |
| **Blocklist** | **Strict-mode whitelist** |
| ![Blocklist tab](docs/screenshots/02-rules.png) | ![Strict-mode whitelist](docs/screenshots/05-whitelist.png) |
| **Settings** | |
| ![Settings tab](docs/screenshots/03-settings.png) | |

![Block confirmation](docs/screenshots/04-confirm-block.png)

Every state-changing action goes through a confirmation dialog that names the exact program,
its full path, the scope of the change, and the rule that is about to be created or deleted.

> The IDS page only raises alerts and never blocks automatically; acknowledging, suppressing,
> clearing and changing its settings each require one UAC prompt.
>
> Since 4.3 the *Protection* tab has four sub-tabs (Port scan / LAN / DNS security / IDS);
> see [`docs/4.3-VM验收.md`](docs/4.3-VM验收.md) for the DNS security page and its acceptance steps.

## Download (only two files from Releases)

Download from [Releases](https://github.com/lovercyh/winappguard/releases):

| File | Purpose |
|---|---|
| **`WinAppGuardSetup.exe`** | Install / repair (**the UI and service are bundled inside**) |
| **`WinAppGuardUninstall.exe`** | Full uninstall |

> ⚠️ **Do not** download or run `WinAppGuard.exe` / `WinAppGuardSvc.exe` on their own.
> They are not standalone products: one is only the UI, the other only the service.
> Without the installer there is no service registration and no shortcut — **they will not work
> by themselves**.

Double-clicking the installer asks for administrator rights once, then copies the files,
registers the service (SYSTEM, automatic start), and creates a desktop shortcut.

- **Since 4.1 Npcap is required**: traffic statistics and anti-port-scan both depend on it.
  The installer explains why and then opens the official GUI; declining aborts the installation
  without changing the system.
- Npcap is installed through its official GUI, never silently; `Npcap-LICENSE.txt` and
  `npcap-1.90.exe` (used by the status-bar install shortcut) are kept in the install directory.
- Neither the installer nor the uninstaller is code-signed; SmartScreen will say "unknown
  publisher" on first run. That is expected.

## Install / uninstall

- **Double-click `WinAppGuardSetup.exe`** — installs if missing, repairs if already installed,
  and creates the desktop shortcut.
- **Double-click `WinAppGuardUninstall.exe`** — full uninstall: service, rules, shortcut,
  auto-start task, records/settings, protected-mode key, and install directory.
- Command line: `WinAppGuardSetup.exe --install|--repair|--start-service|--uninstall`.
- `--keep-data` keeps rules/records on uninstall, but **the protected-mode key is still deleted**.
- The UI runs as a normal process; editing rules raises one UAC prompt, handled by the elevated
  helper (`WinAppGuardSvc.exe --elevated-ipc`).

## Requirements

- Windows 10 or Windows 11, x64
- Administrator rights for installation and the CLI; the UI itself runs as a normal user
- [.NET SDK 10](https://dotnet.microsoft.com/download) or newer, only if building from source
- Npcap (required since 4.1; installed by the setup through its official GUI)

## How it works

| Concern | Implementation |
|---|---|
| Blocking | One outbound rule per executable path, enforced for TCP and UDP over IPv4 and IPv6 (implemented as IPv4 + IPv6 filters) on WFP's `ALE_AUTH_CONNECT` layer |
| Rule naming | `AppGuard_Block_<exe name>_<first 8 hex chars of the path hash>` — deterministic, so re-blocking is idempotent |
| Firewall access | Calls `fwpuclnt.dll` directly (the WFP user-mode API); zero third-party libraries |
| Only its own objects | Every enumeration and deletion is filtered by the **sublayer GUID**; other software and system objects are never touched |
| Connection listing | `GetExtendedTcpTable` via `iphlpapi.dll` |
| Process path lookup | `QueryFullProcessImageNameW` (no `System.Diagnostics.Process` objects, so no handle leak while refreshing every 3 seconds) |
| Auto-start | One Task Scheduler task named `WinAppGuard`, logon trigger, highest privileges, no execution time limit |
| Single instance | Named mutex + a broadcast window message; a second launch brings the existing window to the front |
| IP ownership | Team Cymru WHOIS over plain TCP to `whois.cymru.com:43` — the only endpoint this app actively connects to (DNS lookups and revocation checks are separate, see above); batched and cached in memory; on by default, switchable off |
| Strict mode | A **dynamic WFP session inside the protection service**: whitelist permit (high weight) + block all (low weight). Stopping or crashing the service revokes it; it changes no system setting |
| Timed blocks | The expiry is stored **in the filter's own description field** (`AppGuard\|1\|Block\|C:\path\a.exe\|自动解除=…`), so it survives restarts. The service's 30-second timer removes expired filters and shows a tray notification |
| Traffic accounting | **Npcap** captures TCP/UDP headers at NDIS (BPF-filtered, no payload), attributes local endpoints to PIDs, deduplicates across adapters for 2 s, and keeps counters in memory only |
| Live rates | Server-side 1-second buckets + a 5-minute ring buffer; the UI draws the chart itself; per-program rates are a 3-second moving average |
| DNS records | ETW `Microsoft-Windows-DNS-Client`; only the domain, PID and result code, with the latest 2000 entries kept in memory |
| Flow IDS | Reuses the two ETW sessions and feeds connection tuples / counts / domains into an in-memory rule engine; raises alerts only, never inline blocking (ETW no longer feeds traffic statistics) |
| Anti-port-scan | Npcap captures inbound TCP SYNs at NDIS (BPF-filtered) and counts distinct ports / hosts per source IP; no payload inspection |
| Temporary IP block | A user-mode WFP `ALE_AUTH_RECV_ACCEPT_V4/V6` filter blocks new inbound connections from the source IP; it expires or can be released and never cuts existing connections |
| Service / protected mode | `WinAppGuardSvc` runs as SYSTEM and is the only process that writes WFP. The UI talks to it over the `WinAppGuard.Control.v2` pipe; every request is signed with the owner's ECDSA P-256 key (nonce + request bytes), and the service only stores the public key |
| Records | WFP net events for blocked connections (with filter ID → rule name); 3-second polling + DNS-cache snapshots for normal connections; JSONL files, 8 MB segments, 7-day retention by default |

## Verifiable trust

Most tools ask you to take their word for it. This one ships with the means to check:

```powershell
WinAppGuard.SelfCheck.exe --audit
```

This does **not** grep the source. It reads the **metadata of the compiled assemblies** —
including indirect references and anything the framework drags in — and reports:

- referenced assemblies (all from the .NET framework; zero third-party libraries);
- every networking type (expected: `TcpClient` / `NetworkStream`, used only by the IP ownership lookup);
- **every P/Invoke** with its purpose;
- whether any unregistered network-related native API (`ws2_32`, `winhttp`, `wininet`, …) is used;
- registry access.

The exact counts and the full P/Invoke list are printed by the tool, so they always match the
version you are running.

Two notes on the audit:

- Since 1.2 it **no longer demands "zero networking types."** It demands that every networking
  type is on an expected list, and it adds a check that nobody bypassed the managed types by
  calling network APIs through P/Invoke. An audit that stays green while a network path hides
  behind it would be worse than no audit at all.
- `--audit` needs no administrator rights, so it also runs in CI.

## Safety guards

These are enforced **where rules are written**, not in the UI. Getting the UI logic wrong cannot
bypass them.

| Guard | Where |
|---|---|
| Only filters under its own sublayer GUID may be deleted — everything else is invisible and cannot be deleted | `WfpRuleStore` / `WfpEngine` |
| Critical system processes are refused before a rule is created | `FirewallManager.ValidateProgramPath` |
| Missing files, non-`.exe` paths, and UNC network paths are refused | same |
| Every dangerous action requires confirmation; deleting all rules needs **two** confirmations | `Forms/ConfirmForm.cs` |

Full details, plus copy-pasteable verification steps for each claim, are in
[`docs/安全说明.md`](docs/安全说明.md) (Chinese).

## Build from source

Requires the [.NET SDK 10](https://dotnet.microsoft.com/download) or newer.

```powershell
git clone https://github.com/lovercyh/winappguard.git
cd winappguard

dotnet build WinAppGuard.sln -c Debug

# Produces dist\WinAppGuard.exe, WinAppGuardSvc.exe,
# WinAppGuardSetup.exe and WinAppGuardUninstall.exe
powershell -ExecutionPolicy Bypass -File .\build\publish.ps1
```

The build must produce **0 warnings and 0 errors**. In this project warnings are treated as
defects, not as noise.

## FAQ

### Why does my antivirus flag this?

Because of what it legitimately does:

- writes WFP filters (which needs administrator rights and direct system APIs);
- creates a scheduled task that runs **at logon with highest privileges** — technically privilege persistence;
- reads the TCP connection table and resolves process paths.

Heuristic engines react to exactly that combination. Everything it creates is visible and
removable: the task is named `WinAppGuard` and is not hidden, and every filter lives in a
dedicated sublayer with a fixed GUID (one command cleans them up). Run `--audit` above if you
want to check the binary's capabilities.

### SmartScreen says "unknown publisher"

The exe is not code-signed — a code-signing certificate costs money and this is a free tool.
Click *More info* → *Run anyway*, or verify the SHA-256 against the release notes first.

### Permissions (since 3.1)

- **Owner** — the elevated account that ran the installer. Only the owner can use the UI/service.
- **UI** — `asInvoker`; double-clicking does not raise UAC. Viewing connections, rules and records
  needs no administrator rights for the owner.
- **Rule changes / strict mode / audit settings** — one UAC prompt, forwarded to the service by
  `WinAppGuardSvc.exe --elevated-ipc`; the helper also signs with the owner key.
- **Service `WinAppGuardSvc`** — runs as SYSTEM and is the **only** process that writes WFP.
  It accepts only owner ECDSA signatures.
- **Pipe / service ACL** — the pipe allows only `SYSTEM` + the owner; the service DACL gives
  `Administrators` query/start only, and other accounts nothing. Administrators can still take
  ownership and bypass this, which is documented.
- **WFP object ACL (since 3.4)** — the sublayer and filters allow deletion/ACL changes only to
  `SYSTEM` + the owner; `Administrators` no longer have write access. An administrator with
  `SeTakeOwnership` / `SeRestore` can still take ownership first, so this raises the bar rather
  than making tampering impossible.
- **Key** — `%ProgramData%\WinAppGuard\protected-mode\client-key.dpapi`
  (user-scoped DPAPI); `config.json` contains only the public key, entropy and fingerprint.
  It is always removed on uninstall.
- **Auto-start** — a Task Scheduler task at highest privileges; logon does **not** raise UAC and
  can start the service silently.
- **Command line** — `--block / --list-blocked / --unblock-all` use signed IPC;
  `--migrate / --recover` are administrator recovery commands. The CLI still requires elevation.

> If you are not the owner, the key is unavailable, or protected mode is not initialized, the UI
> says so explicitly and the rules page is read-only.
> To change owners, run `WinAppGuardSetup.exe --reset-owner` as the owner.

### I closed the window but it's still running

By design. Closing the window minimises it to the tray; quitting outright would leave WFP
filters active with no visible way to undo them. Use **tray icon → Exit** to really quit.

### Does quitting the app unblock everything?

**No.** Quitting only ends the UI process. The WFP filters stay in force and blocked programs
stay blocked. Use *Unblock (allow network)* or *Delete all AppGuard rules* to unblock. The exit
confirmation says this explicitly.

### The UI says "current account is not the owner" / "key unavailable"

Since 3.1 only the account that installed the app (the owner) can use the UI and service.

- **Not the owner** — sign in with the installing account. To change owners, run
  `WinAppGuardSetup.exe --reset-owner` as the new owner.
- **Key unavailable** — the key file is missing or DPAPI cannot decrypt it. Run
  `WinAppGuardSetup.exe --rotate-key` as the owner.
- **Not initialized** — a 3.0 upgrade has not generated a key yet. Run
  `WinAppGuardSetup.exe --repair`.

Other administrators can still kill the process, replace binaries or operate WFP directly.
Protected mode raises the bar and leaves a trail; it does **not** claim to stop a determined
local administrator.

### How do I get rid of everything?

1. Double-click `WinAppGuardUninstall.exe` (or run `WinAppGuardSetup.exe --uninstall`).
2. Confirm.

This removes the service, WFP rules/sublayer, shortcut, auto-start task, records, settings,
protected-mode key and install directory. To keep rules/records (the key is still deleted):

```powershell
WinAppGuardUninstall.exe --uninstall --keep-data
```

If you only need to clear this tool's WFP objects after a failure, run as administrator:

```powershell
WinAppGuard.exe --recover
```

### Blocking works on paths, not PIDs

Rules match program identity (the executable path), so:

- all instances of that path are blocked together, regardless of arguments;
- the same program run from a different directory is **not** affected;
- if the program updates and moves, the old rule stops applying — block it again.

### Why do blocked programs vanish from the connections list?

Because they can no longer connect, so they have no connections to list. Use the **Rules** tab
to manage them — that tab is driven by your rules, not by live traffic.

### Where is the log?

UI logs: `%LOCALAPPDATA%\WinAppGuard\logs\`, one file per day, last 7 days kept.
Service logs: `%ProgramData%\WinAppGuard\logs\`, **always English with stable event codes**
(for example `[WAG-SVC-002] Service started.`). They never follow the UI language; exception lines
record only the type, HResult, Win32 error code and stack trace, never a localised system message.
Both are local only — nothing is ever uploaded. The Settings tab shows the UI path and has a
button to open it.

## Documentation

Most project documentation is in Chinese.

| Document | Contents |
|---|---|
| [`docs/安全说明.md`](docs/安全说明.md) | Security model, with a verification method for every claim |
| [`docs/验收清单.md`](docs/验收清单.md) | Full acceptance checklist (automated results + manual items) |
| [`docs/测试用例.md`](docs/测试用例.md) | Per-phase test cases and measured results |
| [`docs/发布手册.md`](docs/发布手册.md) | Build → verify → release workflow |
| [`docs/服务化设计.md`](docs/服务化设计.md) | 3.0 protection service + UI client design (implemented) |
| [`docs/受保护模式设计.md`](docs/受保护模式设计.md) | 3.1 single owner, ECDSA/DPAPI, protocol v2, ACLs and lifecycle |
| [`docs/3.6-流量记录设计.md`](docs/3.6-流量记录设计.md) | 3.6 traffic page aggregation, sorting and clearing |
| [`docs/3.7-用户态FlowIDS设计.md`](docs/3.7-用户态FlowIDS设计.md) | 3.7 user-mode Flow IDS: rules, thresholds, storage and limits |
| [`docs/3.7-VM验收.md`](docs/3.7-VM验收.md) | 3.7 automated acceptance and VM measurements |
| [`docs/4.0-反端口扫描设计.md`](docs/4.0-反端口扫描设计.md) | 4.0 Npcap capture, scan rules, WFP inbound blocking and limits |
| [`docs/4.0-VM验收.md`](docs/4.0-VM验收.md) | 4.0 Npcap install, scan tests and soak acceptance |
| [`docs/4.1-精确流量与实时速率设计.md`](docs/4.1-精确流量与实时速率设计.md) | 4.1 Npcap packet counting, live rates, mandatory Npcap install |
| [`docs/4.1-VM验收.md`](docs/4.1-VM验收.md) | 4.1 install paths, accuracy tests and soak acceptance |
| [`docs/4.2-局域网欺骗检测设计.md`](docs/4.2-局域网欺骗检测设计.md) | 4.2 ARP/DHCP detection, baselines, storage and DHCP blocking |
| [`docs/4.2-VM验收.md`](docs/4.2-VM验收.md) | 4.2 ARP spoof / rogue DHCP tests and 24h false-positive watch |
| [`docs/4.3-DNS安全设计.md`](docs/4.3-DNS安全设计.md) | 4.3 DNS response validation, 8 rules, baseline, storage and limits |
| [`docs/4.3-VM验收.md`](docs/4.3-VM验收.md) | 4.3 dnsspoof/ettercap/Scapy, plaintext bypass and 24h acceptance |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Short version: **code comments and commit messages are
in Chinese**, the build must be warning-free, and behaviour changes should come with an assertion
that would have caught the bug.

## License

[MIT](LICENSE).
