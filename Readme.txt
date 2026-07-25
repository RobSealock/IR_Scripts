# IR_Scripts

A collection of standalone, **PowerShell 5.1–compatible** incident-response and triage scripts for Windows hosts and Active Directory domain controllers. Each tool is self-contained, read-only/collection-focused, and produces analyst-friendly **HTML / CSV / JSON** output. They are grouped below by investigative task.

> **Before you run anything**
> - Most script files are committed with a `.txt` suffix (e.g. `LocalLogons.ps1.txt`) so they render/download safely from GitHub. **Rename `*.ps1.txt` → `*.ps1` and `*.psm1.txt` → `*.psm1` before use.** (The `WinHostBaseline*` files are already correctly named.)
> - Several scripts require an **elevated** session (`Run as Administrator`).
> - DC-facing scripts need the **RSAT ActiveDirectory** module (see Requirements) and rights to read the Security log on each DC.
> - You may need to unblock downloaded files (`Unblock-File`) and run with an appropriate `-ExecutionPolicy`.
> - Keep each module (`.psm1`) in the **same folder** as the script that imports it.

---

## Overall use

The repo covers five common IR/triage workflows:

1. **Host baselining & drift detection** — snapshot a system and diff it against a known-good baseline.
2. **Logon & authentication-failure investigation** — local and cross-DC logon activity, failed-logon analysis, spray/lockout heuristics.
3. **Persistence & browser-extension review** — Chrome/Edge extension enumeration with store lookups; autoruns via Sysinternals.
4. **Firewall change review** — timeline of firewall-rule modifications with risk scoring.
5. **Live triage & Sysinternals orchestration** — Living-off-the-Land indicators and repeatable Sysinternals collection.

---

## Requirements

**PowerShell:** Windows PowerShell **5.1** (built into Windows 10 / Server 2016 and later — no install).

**Elevation:** many scripts require `Run as Administrator`.

**Modules that ship in this repo** (no install — keep them in the same folder as the script that imports them, and rename `.psm1.txt` → `.psm1`):

- Baseline suite → `WinHostBaselineCore.psm1`, `WinHostBaseline.Collectors.psm1`
- Auth-failure suite → `AuthEventParser.psm1`, `AuthHeuristics.psm1`, `AuthExport.psm1`

**Built into Windows** (required but nothing to install): `Get-WinEvent`, `Get-CimInstance`, `Get-FileHash`, `Get-AuthenticodeSignature`, `Get-ScheduledTask`, and the **NetSecurity** firewall cmdlets used by `Get-FirewallModificationTimeline.ps1`.

**The only module that must be installed: RSAT ActiveDirectory** — used solely by the three DC-facing scripts (`Test-DCLogAccess.ps1`, `Get-DomainLogons.ps1`, `DC-FailedLogons-Report.ps1`) to enumerate domain controllers.

Online install:
```powershell
# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Windows Server (already present on a DC)
Install-WindowsFeature RSAT-AD-PowerShell
```

### Installing RSAT-AD offline (air-gapped range)

`Rsat.ActiveDirectory` is a Windows **Feature on Demand (FoD)**, not a PowerShell Gallery module, so `Save-Module` does not apply. For hosts with no internet, use one of the following.

**Windows Server:** the payload is usually already in the local component store, so this works offline with no media:
```powershell
Install-WindowsFeature RSAT-AD-PowerShell
# If payload was stripped from the image, point at the matching Server ISO:
Install-WindowsFeature RSAT-AD-PowerShell -Source E:\sources\sxs
```

**Windows 10/11 clients — Features on Demand offline ISO.** Download the FoD ISO that matches the target build on an internet-connected machine, carry it into the range, mount it, and install with a local source.

| Windows build | FoD ISO |
|---|---|
| 24H2 / 25H2 (26100) | https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1.240331-1435.ge_release_amd64fre_CLIENT_LOF_PACKAGES_OEM.iso |
| 22H2 / 23H2 (22621) | https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/22621.2501.231009-1937.ni_release_svc_prod3_amd64fre_InboxApps.iso |

> **Verify before staging:** match the ISO to the target's exact build (`winver`). The 24/25H2 link is a `CLIENT_LOF_PACKAGES` (Language & Optional Features) ISO and contains RSAT. The 22/23H2 link above is an **`InboxApps`** ISO, which typically holds provisioned Store apps rather than FoD capabilities — if `Add-WindowsCapability -Source` can't find the RSAT payload on it, obtain the matching 22621 **FoD / LOF** ISO instead. Confirm each URL resolves before relying on it.

Install from the mounted ISO:
```powershell
# 1. Mount the FoD ISO (already copied into the range)
$iso   = Mount-DiskImage -ImagePath 'C:\ISO\26100_CLIENT_LOF_PACKAGES.iso' -PassThru
$drive = ($iso | Get-Volume).DriveLetter + ':'

# 2. Install RSAT AD from the ISO. -LimitAccess prevents any fallback to Windows Update.
Add-WindowsCapability -Online `
    -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 `
    -Source "$drive\" -LimitAccess

# 3. Verify
Get-WindowsCapability -Online -Name Rsat.ActiveDirectory* | Select-Object Name, State
Import-Module ActiveDirectory
Get-ADDomainController -Discover

# 4. Unmount when done
Dismount-DiskImage -ImagePath 'C:\ISO\26100_CLIENT_LOF_PACKAGES.iso'
```

DISM equivalent (if you prefer, or for imaging pipelines), where `D:` is the mounted ISO:
```
DISM /Online /Add-Capability /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 /Source:D:\ /LimitAccess
```

**Alternatives if staging the ISO is impractical:**

- **Copy the module folder** from a machine that already has RSAT-AD (or from a DC): copy `C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ActiveDirectory\` into the same path on the target (match x64 architecture and a close OS build), then `Import-Module ActiveDirectory`. The module still needs **ADWS on a DC reachable (TCP 9389)**.
- **Skip RSAT entirely** — the three scripts use the AD module only to discover DCs. Replacing that call with the built-in .NET method removes the dependency on a domain-joined host:
  ```powershell
  $dcs = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).DomainControllers
  ```

---

## A. Host baseline & drift detection

Snapshot a host's persistence/attack surface (autoruns & Run keys, services, listening sockets, browser extensions) with Authenticode signer classification (Microsoft / Sysinternals / user-writable) and SHA-256 hashes, then compare against a saved baseline.

| Script | Purpose |
|---|---|
| `Generate-OSBaseline.ps1` | Produce a reference baseline JSON for a clean OS (`-Profile Auto/Server/Desktop`). |
| `WinHostBaseline.ps1` | Snapshot the current host and compare to a baseline; flags new/changed items. |
| `WinHostBaselineCore.psm1` | Core classes (`HostItem`/`HostIdentity`/`HostSignature`) and helpers. |
| `WinHostBaseline.Collectors.psm1` | The individual collectors (autoruns, services, sockets, extensions, signatures). |

**Options:** `-AllProfiles` (scan all user hives — admin), `-Firefox`, `-IncludeRemoteSockets`, `-ResolveNetworkPaths`, `-DebugLog`. Default paths under `C:\Temp\Scan\`.
**Included baselines:** Windows 11 (`Win11_10.0.26200_7840.json`) and Windows Server 2025 (`Server2025_10.0.26100_32230.json`). See **`ReadMe.pdf`** for the full baseline methodology.

---

## B. Browser extension review

Enumerate Chrome and Edge extensions across all user profiles, resolve localized names, and look up metadata from the Chrome Web Store / Edge Add-ons store; output an HTML report.

| Script | Purpose |
|---|---|
| `BrowserExtenstion-Scan-Resolve.ps1` | Single-pass **online** scan + store lookup → HTML (optional `-JsonOutput`). |
| `OfflineBrowserExtenstion-Scan-Resolve.ps1` | **Two-stage**: (1) offline collect to JSON on the target, (2) online enrich + HTML on a connected host. Use when the target has no internet. |

---

## C. Logon activity

| Script | Purpose | Requires |
|---|---|---|
| `Get-DomainLogons.ps1` | Consolidates logon activity **across all DCs** (4624). Interactive prompts, high-risk account detection, Top-N, HTML/CSV/JSON. | RSAT AD, DC log access |
| `LocalLogons.ps1` | Rich **local** logon/logoff review (4624/4634/4647): reboot annotations, session correlation, risk scoring, group membership, gap analysis. | Admin |

**`LocalLogons.ps1` options:** `-Window 1h/24h/Max`, `-IncludeNoiseAccounts`, `-IncludeComputerAccounts`, `-OutputCsv`, `-OutputHtml`, `-DebugLogPath`.

---

## D. Failed-logon / authentication-failure investigation

Investigate authentication failures locally and across DCs, with password-spray and lockout heuristics. The three `Auth*` modules are shared helpers.

| Script / Module | Purpose |
|---|---|
| `DC-FailedLogons-Report.ps1` | Queries **all DCs** for 4625 / 4771 / 4776 over MAX/48h/24h/1h windows (RPC first, WinRM fallback, per-DC timeout). |
| `Local-FailedLogons-Report.ps1` | Local failed-logon HTML report (4625, optional 4771/4776) across the same four windows. |
| `Test-DCLogAccess.ps1` | Pre-flight check: can the current account read 4625/4771/4776 on local/remote DCs? Run this first. |
| `AuthEventParser.psm1` | Logon-type and NTSTATUS failure-code maps; event parsing. |
| `AuthHeuristics.psm1` | Detections incl. password spray (4771 `0x18` grouped by source IP), account-based patterns. |
| `AuthExport.psm1` | Timestamped report naming and `reports/` output handling. |

**Workflow:** run `Test-DCLogAccess.ps1` → then `DC-FailedLogons-Report.ps1` (domain) and/or `Local-FailedLogons-Report.ps1` (host).

---

## E. Firewall change review

| Script | Purpose |
|---|---|
| `Get-FirewallModificationTimeline.ps1` | Timeline of Windows Firewall rule modifications with risk scoring by time/direction/port. Options: `-MaxEvents`, `-SuspiciousDays`, `-MinRisk`, `-OnlySuspicious`, `-CriticalOnly`, `-OutputHtmlPath`, `-OutputCsvPath`. Requires admin. |

---

## F. Live host / DC triage (work in progress)

| Script | Purpose |
|---|---|
| `Invoke-IRLocalTriage.ps1` | Living-off-the-Land triage. DC-focused detections include group-membership changes (4728/4729/4732/4733/4756/4757) and a **DCSync indicator** (4662 with `DS-Replication-Get-Changes` GUIDs). Options: `-HoursBack`, `-OutPath`, `-Verbose`, `-DebugLogPath`. Requires admin. **Status: WIP.** |

---

## G. Sysinternals orchestration

| File | Purpose |
|---|---|
| `Invoke-SysinternalsIR.ps1` | Orchestrates CLI Sysinternals tools (`autorunsc`, `sigcheck`, `tcpvcon`, `pslist`, `psinfo`, `psloggedon`, `psservice`) into CSV/JSON/HTML with a deterministic folder layout. Point `-SysinternalsPath` at your tools folder; `-RunAll` or select tools individually. Requires the Sysinternals **executables** on disk (not a PS module). |
| `SysInternals_IR` | Reference table mapping Sysinternals tools to IR use cases (process/memory, network, persistence, disk, rootkit detection). |

---

## Output

Most scripts emit **HTML** (analyst review) plus optional **CSV** and **JSON** (pipeline/AI ingestion). Auth-suite reports are timestamped into a `reports/` folder.

## External IR tools referenced

- **Velociraptor** — endpoint DFIR/visibility: https://docs.velociraptor.app/downloads/
- **KAPE** (Kroll Artifact Parser and Extractor): https://www.kroll.com/en/services/cyber/incident-response-recovery/kroll-artifact-parser-and-extractor-kape
- **AADInternals** — Entra/AAD tooling: https://github.com/Gerenios/AADInternals
- Sysinternals **TCPView**, **Autoruns**

## Notes

- All scripts target **PowerShell 5.1** for maximum compatibility on stock Windows/Server hosts.
- Scripts are collection/reporting-focused and non-destructive; review output before acting.
- `Readme.txt` is the original quick index; `ReadMe.pdf` documents the baseline suite in depth.
