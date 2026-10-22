# Security Policy

## Supported versions

Only the latest release is supported. This project is a single-file desktop tool;
there are no maintained release branches.

| Version | Supported |
| ------- | --------- |
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting instead:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Describe what you found.

If that is not available to you, open a normal issue that says only
*"I found a security issue, please provide a private channel"* — with no details —
and a maintainer will reach out.

Please include:

- What the problem is and how it can be triggered.
- Which version you tested and your Windows build number.
- The relevant lines from `%ProgramData%\WinAppGuard\logs\` (service) or `%LOCALAPPDATA%\WinAppGuard\logs\` (UI), if any.
- Whether the tool had administrator rights at the time.

## What counts as a vulnerability here

> 3.0 note: the service runs as SYSTEM and is the **only** writer of WFP rules.
> Administrators can still stop the service or delete rules — that is an accepted,
> documented capability, not a vulnerability. Ordinary users can read state but must
> pass UAC for any write.


This tool deliberately modifies system state, so the boundary matters.
**Design intent — not a vulnerability:**

| Behaviour | Why it is intended |
| --------- | ------------------ |
| Creating outbound WFP filters in WinAppGuard's own sublayer | That is the entire point of the tool |
| Installing one Windows service `WinAppGuardSvc` (SYSTEM) and one scheduled task `WinAppGuard` (logon, highest privileges) | That is how protection survives closing the UI and how auto-start works |
| Not deleting rules that do not start with `AppGuard_` | Deliberate safety guard |
| Refusing to block `lsass.exe`, `svchost.exe`, WinAppGuard itself, etc. | Deliberate safety guard |
| Blocking applies per executable path, so all instances of that path are affected | WFP filters work on paths, not PIDs |
| Changing no global firewall policy whatsoever | Enforced in code — see below |

**Would be a vulnerability:**

- Any code path that can create, modify, or delete a WFP filter **outside WinAppGuard's
  own sublayer**, or a Windows Firewall rule.
- Any action that lets a non-admin UI token perform a write without a UAC prompt
  (M1.5: rule changes must go through the elevated helper).
- Any code path that changes global firewall policy (enabling/disabling the firewall,
  changing default inbound/outbound actions).
- Any code path that registers persistence other than the `WinAppGuardSvc` service and
  the single scheduled task `WinAppGuard` (for example a registry `Run` key).
- Any network traffic that goes to a destination **other than the IP-ownership WHOIS
  endpoint** (`whois.cymru.com:43`) or certificate revocation endpoints, or that carries
  any data about the user or their machine.
- Sending any user data anywhere, ever.
- Any path traversal / argument injection that makes the tool operate on something
  other than the executable path the user selected.
- Privilege escalation beyond the administrator rights the tool already requests.

## Verifying the claims yourself

Every claim above is checkable without reading all the source:

```powershell
# Reads the compiled assembly's metadata (not the source) and lists
# every referenced assembly, every networking type, and every P/Invoke.
WinAppGuard.SelfCheck.exe --audit
```

The expected result for a released build:

```
Referenced assemblies         all from the .NET framework + own assemblies  → no third-party libraries
Networking types referenced   TcpClient / NetworkStream only                → the IP ownership lookup
Native API calls (P/Invoke)   listed per assembly
Network-related native calls  none outside the documented paths
Registry access               read-only service key (checks whether the service is installed)
Compile-time isolation        UI and Core do NOT reference WinAppGuard.Wfp
```

Since 1.2 this check no longer asserts "zero networking types" — it asserts that every networking
type is **on an expected list** (and that no one bypassed it via a direct `ws2_32` / `winhttp`
P/Invoke). The reason is stated plainly in the README: the IP ownership lookup is real networking
that the app performs itself, and pretending otherwise would make the audit worthless.

3.0 splits the product into UI / Core / Wfp; `--audit` reads all three and fails if the UI or
Core references the WFP assembly. The WFP implementation is still audited (and still lists its
native imports) — it just is not part of the UI binary.

Those native calls are the complete set of non-managed functions the program can reach:

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

You can also watch the process while it runs: open **Resource Monitor → Network** and look for
`WinAppGuard.exe`. If certificate revocation checking is **off** (Settings → Data & privacy) it should
never appear. With it **on** (the default) you will see CA lookups — that is expected, and is Windows'
certificate service, not application code.
Detailed per-claim verification steps are in
[`docs/安全说明.md`](docs/安全说明.md) (Chinese; each claim has a copy-pasteable check).

## Release integrity

Releases are built by GitHub Actions from a tagged commit and are published as a single
file. Each release lists the **SHA-256** of the attached exe so you can confirm your
download was not tampered with:

```powershell
Get-FileHash .\WinAppGuard.exe -Algorithm SHA256
```

Releases are **not code-signed**, so Windows SmartScreen will warn about an unknown
publisher. That is expected; see the FAQ in the README.
