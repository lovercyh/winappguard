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
- The relevant lines from `%LOCALAPPDATA%\WinAppGuard\logs\` if the tool produced any.
- Whether the tool had administrator rights at the time.

## What counts as a vulnerability here

This tool deliberately modifies system state, so the boundary matters.
**Design intent — not a vulnerability:**

| Behaviour | Why it is intended |
| --------- | ------------------ |
| Creating outbound block rules in Windows Firewall | That is the entire point of the tool |
| Creating one scheduled task named `WinAppGuard` that runs at logon with highest privileges | That is how auto-start is implemented (required behaviour) |
| Not deleting rules that do not start with `AppGuard_` | Deliberate safety guard |
| Refusing to block `lsass.exe`, `svchost.exe`, WinAppGuard itself, etc. | Deliberate safety guard |
| Blocking applies per executable path, so all instances of that path are affected | Windows Firewall works on paths, not PIDs |
| Changing no global firewall policy whatsoever | Enforced in code — see below |

**Would be a vulnerability:**

- Any code path that can create, modify, or delete a firewall rule whose name does
  **not** start with `AppGuard_`.
- Any code path that changes global firewall policy (enabling/disabling the firewall,
  changing default inbound/outbound actions).
- Any code path that registers persistence other than the single scheduled task
  named `WinAppGuard` (for example a registry `Run` key).
- Any network traffic that goes to a destination **other than a certificate authority's CRL/OCSP
  endpoint**, or that carries any data about the user or their machine. The default certificate
  revocation lookup is intended and documented; anything beyond it is a vulnerability.
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
Referenced assemblies        22, all from the .NET framework   → no third-party libraries
Networking types referenced  0                                  → no networking code in the app
Native API calls (P/Invoke)  16
Registry access              none
```

Those 16 native calls are the complete set of non-managed functions the program can reach:

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
