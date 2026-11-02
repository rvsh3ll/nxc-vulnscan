# vulnscan

<p align="center">
  <b>One NetExec module. Every Windows vuln <i>check</i>.</b><br>
  Like <code>coerce_plus</code>, for the whole stock check set — and nothing that exploits.
</p>

<p align="center">
  <img alt="NetExec" src="https://img.shields.io/badge/NetExec-module-2ea44f?style=flat-square">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10+-3776ab?style=flat-square">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square">
  <img alt="Opsec" src="https://img.shields.io/badge/mode-check%20only-informational?style=flat-square">
</p>

`vulnscan` is a user module for [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc`). It loads the **stock** Windows vulnerability-check modules and runs them in one pass against each host.

It does **not** reimplement the checks. It does **not** exploit.

| It will | It will not |
| --- | --- |
| Call `zerologon`, `ms17-010`, `smbghost`, `nopac`, `printnightmare`, `coerce_plus`, … | Reset a DC machine password |
| Call `coerce_plus` **without** a listener | PetitPotam / PrinterBug coercion to your IP |
| Call `wdigest` with `ACTION=check` | Enable WDigest, RDP, or remote UAC |
| Print a `[HIT]` / `[----]` summary | Dump NTDS, lsass, or drop files |

Removed NetExec stubs (`petitpotam`, `printerbug`, `dfscoerce`, `shadowcoerce`) are skipped — `coerce_plus` already covers that surface.

---

## Install

Filename **must** be `vulnscan.py`. NetExec refuses a module whose name does not match the file.

```bash
mkdir -p ~/.nxc/modules
curl -fsSL https://raw.githubusercontent.com/rvsh3ll/nxc-vulnscan/main/vulnscan.py \
  -o ~/.nxc/modules/vulnscan.py

nxc smb -L | grep vulnscan
```

Or clone:

```bash
git clone https://github.com/rvsh3ll/nxc-vulnscan.git
cp nxc-vulnscan/vulnscan.py ~/.nxc/modules/vulnscan.py
```

Needs a working NetExec install. The wrapper imports modules from `nxc/modules/` shipped with your copy.

---

## Usage

```bash
# unauthenticated / null session
nxc smb 10.0.0.10 -M vulnscan

# domain user
nxc smb 10.0.0.10 -u jdoe -p 'Password' -d corp.local -M vulnscan

# SOCKS pivot
proxychains -q nxc smb 10.0.0.10 -u jdoe -p 'Password' -M vulnscan

# subset
nxc smb 10.0.0.10 -M vulnscan -o CHECKS=ms17-010,smbghost,zerologon,coerce_plus

# skip the slow Zerologon brute
nxc smb 10.0.0.10 -M vulnscan -o SKIP=zerologon

# list checks, do not scan
nxc smb 10.0.0.10 -M vulnscan -o LIST=1
```

Admin-only checks run only when NetExec already has a privileged session (`Pwn3d!`).

### Options

| Option | Meaning |
| --- | --- |
| `CHECKS` | Comma-separated stock module names. Default: all applicable |
| `SKIP` | Comma-separated names to skip |
| `LIST` | Print the built-in check table and stop |
| `LISTENER` | **Ignored.** This module is check-only |

---

## Example output

Hosts, domains, and accounts below are placeholders.

```text
SMB         10.0.0.10   445   DC01   [*] Windows Server 2016 Standard (name:DC01) (domain:CORP.LOCAL) (signing:True)
SMB         10.0.0.10   445   DC01   [+] CORP.LOCAL\jdoe:Password
VULNSCAN    10.0.0.10   445   DC01   [*] Running 14 stock check modules (no exploit)
VULNSCAN    10.0.0.10   445   DC01   [*] --- ms17-010 ---
VULNSCAN    10.0.0.10   445   DC01   [*] --- smbghost ---
VULNSCAN    10.0.0.10   445   DC01   [*] --- zerologon ---
ZEROLOGON   10.0.0.10   445   DC01   VULNERABLE
ZEROLOGON   10.0.0.10   445   DC01   Next step: https://github.com/dirkjanm/CVE-2020-1472
VULNSCAN    10.0.0.10   445   DC01   [*] --- coerce_plus ---
COERCE_PLUS 10.0.0.10   445   DC01   VULNERABLE, DFSCoerce
COERCE_PLUS 10.0.0.10   445   DC01   VULNERABLE, PetitPotam
COERCE_PLUS 10.0.0.10   445   DC01   VULNERABLE, Printerbug
VULNSCAN    10.0.0.10   445   DC01   [*] --- spooler ---
SPOOLER     10.0.0.10   445   DC01   Spooler service enabled
VULNSCAN    10.0.0.10   445   DC01   ======== vulnscan summary ========
VULNSCAN    10.0.0.10   445   DC01   [HIT]  zerologon          VULNERABLE
VULNSCAN    10.0.0.10   445   DC01   [HIT]  coerce_plus        VULNERABLE, DFSCoerce | VULNERABLE, PetitPotam
VULNSCAN    10.0.0.10   445   DC01   [HIT]  spooler            Spooler service enabled
VULNSCAN    10.0.0.10   445   DC01   [*] [----] ms17-010           no highlight (not vulnerable / no signal)
VULNSCAN    10.0.0.10   445   DC01   [*] [----] smbghost           no highlight (not vulnerable / no signal)
VULNSCAN    10.0.0.10   445   DC01   =================================
```

Child modules keep their own name in the first column. `vulnscan` prints a roll-up at the end.

---

## Checks

### Login (works without local admin)

| Module | Check |
| --- | --- |
| `ms17-010` | EternalBlue |
| `smbghost` | SMBGhost (CVE-2020-0796) |
| `zerologon` | Zerologon (CVE-2020-1472) — **check only**, does not set an empty password |
| `ntlm_reflection` | NTLM reflection (CVE-2025-33073) |
| `remove-mic` | Drop-the-MIC (CVE-2019-1040) |
| `printnightmare` | PrintNightmare |
| `spooler` | Print Spooler reachable |
| `webdav` | WebClient / DAV RPC (WebDAV coerce) |
| `coerce_plus` | PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, MS-EVEN — **no listener** |
| `nopac` | noPac (CVE-2021-42278 / 42287) — needs a domain user |
| `enum_av` | Endpoint protection |
| `enum_ca` | ADCS CA via RPC |
| `sccm-recon6` | SCCM site / distribution point |
| `ioxidresolver` | Extra network interfaces |

### Admin (`Pwn3d!` session)

| Module | Check |
| --- | --- |
| `ntlmv1` | `LmCompatibilityLevel` (NTLMv1 allowed) |
| `runasppl` | LSA RunAsPPL |
| `uac` | UAC `EnableLUA` |
| `install_elevated` | AlwaysInstallElevated |
| `bitlocker` | BitLocker status |
| `wdigest` | WDigest `UseLogonCredential` — **`ACTION=check` only** |
| `wcc` | Windows security configuration |
| `presence` | Domain / Enterprise Admin sessions |

Not included on purpose: credential dump (`lsassy`, `ntdsutil`, …), exec (`web_delivery`, `met_inject`), file drops (`slinky`, `scuffy`), and enable/disable modules (`rdp`, `remote-uac`).

---

## How it works

```
nxc smb TARGET -M vulnscan
        │
        ▼
  ~/.nxc/modules/vulnscan.py
        │  importlib-load each stock module
        ▼
  nxc/modules/ms17-010.py
  nxc/modules/zerologon.py
  nxc/modules/coerce_plus.py
  ...
        │  on_login / on_admin_login
        ▼
  per-check output + [HIT] summary
```

Each child is instantiated from NetExec’s own tree with a unique `importlib` spec (so they do not clobber each other). `LISTENER` is never forwarded. `wdigest` always gets `ACTION=check`.

---

## Notes

- **Zerologon is slow** (up to ~2000 Netlogon attempts). Skip it with `-o SKIP=zerologon` when you want the rest of the pack first.
- **`wcc` is noisy** and talks to RemoteRegistry. Skip with `-o SKIP=wcc` if you only want CVE checks.
- This is a convenience wrapper, not a replacement for a proper vulnerability scanner.
- To actually coerce, run `-M coerce_plus -o LISTENER=<your-ip>` yourself. `vulnscan` will not do that.
- Authorized assessments only. You are responsible for how you use this.

## License

MIT © rvsh3ll
