# Generate-OSBaseline.ps1
<#+
.SYNOPSIS
    Generate a host baseline JSON snapshot.

.PARAMETER AllProfiles
    Opt-in. Load and scan all local user profile hives for HKU Run/RunOnce keys.

.PARAMETER ResolveNetworkPaths
    Opt-in. Attempt to resolve UNC and mapped-drive paths (may hang if unreachable).

.PARAMETER Firefox
    Opt-in. Enumerate Firefox profile extensions.
#>

param(
    [string]$OutputDir = 'C:\Temp\Scan\Ref\',
    [ValidateSet('Auto','Server','Desktop')]
    [string]$Profile   = 'Auto',
    # Opt-in: scan Run/RunOnce for ALL local profiles by loading user hives (admin required).
    [switch]$AllProfiles,
    # Opt-in: allow Normalize-PathSafe to resolve UNC / mapped drives (may hang if unreachable).
    [switch]$ResolveNetworkPaths,
    # Opt-in: also enumerate Firefox profiles/extensions.
    [switch]$Firefox,
    # When set, collectors log each skipped item (per-item catch) to host for debugging.
    [switch]$CollectorDebug
)


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'

if (-not (Get-Module WinHostBaselineCore)) {
    Import-Module "$PSScriptRoot\WinHostBaselineCore.psm1" -ErrorAction Stop -DisableNameChecking
}
if (-not (Get-Module WinHostBaseline.Collectors)) {
    Import-Module "$PSScriptRoot\WinHostBaseline.Collectors.psm1" -ErrorAction Stop -DisableNameChecking
}

Set-WinHostBaselineOptions -ResolveNetworkPaths:$ResolveNetworkPaths
# Let the Collectors module know if per-item debug is requested
if ($CollectorDebug) { $env:WinHostBaselineCollectorDebug = '1' } else { $env:WinHostBaselineCollectorDebug = '' }

function Get-OSProfile {
    param([string]$Profile)
    if ($Profile -ne 'Auto') { return $Profile }
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.Caption -match 'Server') { return 'Server' }
    return 'Desktop'
}

function Get-OSBaselineName {
    $os  = Get-CimInstance Win32_OperatingSystem
    $cv  = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $ubr = $cv.UBR
    $ver = $os.Version
    $prod = $os.Caption

    if ($prod -match 'Windows 11')          { return "Win11_${ver}_$ubr" }
    if ($prod -match 'Windows Server 2022') { return "Server2022_${ver}_$ubr" }
    if ($prod -match 'Windows Server 2025') { return "Server2025_${ver}_$ubr" }

    return "$($prod -replace '\s','_')_${ver}_$ubr"
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Invoke-Collector {
    param(
        [string]$Name,
        [scriptblock]$Block,
        [ref]$Errors
    )
    try {
        $res = & $Block
        if ($null -eq $res) { return @() }
        return @($res)
    } catch {
        $msg = $_.Exception.Message
        $Errors.Value += [pscustomobject]@{
            Collector = $Name
            Error     = $msg
        }
        Write-Host "  [!] Collector '$Name' error: $msg" -ForegroundColor Red
        if ($CollectorDebug -and $_.ScriptStackTrace) {
            Write-Host "      $($_.ScriptStackTrace -replace "`n", "`n      ")" -ForegroundColor DarkGray
        }
        return @()
    }
}

try {
$osProfile    = Get-OSProfile -Profile $Profile
$baselineName = Get-OSBaselineName

Ensure-Directory $OutputDir

Write-Host "[*] Generating baseline: $baselineName (Profile: $osProfile)"
Write-Host "[*] NOTE: Network sockets baseline defaults to LISTEN-only (low noise)."

$collectorErrors = @()

Write-Host "[*] Collecting Services..."
$services = Invoke-Collector 'Services'  { Get-ServicesHostItems }         ([ref]$collectorErrors)
Write-Host "[*] Collecting Drivers..."
$drivers  = Invoke-Collector 'Drivers'   { Get-DriversHostItems }          ([ref]$collectorErrors)
Write-Host "[*] Collecting Processes..."
$procs    = Invoke-Collector 'Processes' { Get-ProcessesHostItems }        ([ref]$collectorErrors)
Write-Host "[*] Collecting Scheduled Tasks..."
$tasks    = Invoke-Collector 'Tasks'     { Get-ScheduledTasksHostItems }   ([ref]$collectorErrors)
Write-Host "[*] Collecting Startup..."
$startup  = Invoke-Collector 'Startup'   { Get-StartupHostItems -AllProfiles:$AllProfiles } ([ref]$collectorErrors)
Write-Host "[*] Collecting Network Sockets..."
# Run Sockets in a job so a crash/exit in the collector doesn't kill the whole script
$sockets = @()
try {
    $job = Start-Job -ScriptBlock {
        param($scriptRoot)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $WarningPreference = 'SilentlyContinue'
        if (-not (Get-Module WinHostBaselineCore)) { Import-Module "$scriptRoot\WinHostBaselineCore.psm1" -Force -DisableNameChecking }
        if (-not (Get-Module WinHostBaseline.Collectors)) { Import-Module "$scriptRoot\WinHostBaseline.Collectors.psm1" -Force -DisableNameChecking }
        Get-NetworkSocketsHostItems
    } -ArgumentList $PSScriptRoot
    $sockets = Receive-Job -Job $job -Wait
    if ($job.State -eq 'Failed') {
        $errMsg = ($job.ChildJobs[0].Error | ForEach-Object { $_.ToString() }) -join '; '
        $collectorErrors += [pscustomobject]@{ Collector = 'Sockets'; Error = $errMsg }
    }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    if ($null -eq $sockets) { $sockets = @() }
    $sockets = @($sockets)
} catch {
    $collectorErrors += [pscustomobject]@{ Collector = 'Sockets'; Error = $_.Exception.Message }
}
Write-Host "[*] Sockets collected: $($sockets.Count) item(s)."
Write-Host "[*] Collecting Browser Extensions..."
$browser  = Invoke-Collector 'Browser'   { Get-BrowserExtensionsHostItems -Firefox:$Firefox } ([ref]$collectorErrors)
Write-Host "[*] Collecting WMI Persistence..."
$wmi      = Invoke-Collector 'WMI'       { Get-WmiPersistenceHostItems }   ([ref]$collectorErrors)

# Optional/extended collectors - include only if present in module
# (kept minimal in this build; add more as needed)

Write-Host "[*] Building baseline object..."
try {
    $baseline = [pscustomobject]@{
        Meta = @{
            CollectedAtUtc  = (Get-Date).ToUniversalTime().ToString('o')
            ComputerName    = $env:COMPUTERNAME
            OS              = (Get-CimInstance Win32_OperatingSystem).Caption
            Version         = (Get-CimInstance Win32_OperatingSystem).Version
            BaselineName    = $baselineName
            Profile         = $osProfile
            CollectorErrors = $collectorErrors
            Options         = @{ AllProfiles = [bool]$AllProfiles; ResolveNetworkPaths = [bool]$ResolveNetworkPaths; Firefox = [bool]$Firefox }
        }
        Services       = $services | ForEach-Object { Normalize-HostItem $_ }
        Drivers        = $drivers  | ForEach-Object { Normalize-HostItem $_ }
        Processes      = $procs    | ForEach-Object { Normalize-HostItem $_ }
        ScheduledTasks = $tasks    | ForEach-Object { Normalize-HostItem $_ }
        Startup        = $startup  | ForEach-Object { Normalize-HostItem $_ }
        NetworkSockets = $sockets  | ForEach-Object { Normalize-HostItem $_ }
        WmiPersistence = $wmi      | ForEach-Object { Normalize-HostItem $_ }
        BrowserExtensions = $browser | ForEach-Object { Normalize-HostItem $_ }
    }
} catch {
    Write-Host "[!] Failed to build baseline object: $($_.Exception.Message)" -ForegroundColor Red
    throw
}

$outFile = Join-Path $OutputDir "$baselineName.json"
Write-Host "[*] Writing baseline file: $outFile"
try {
    $json = $baseline | ConvertTo-Json -Depth 16
    $json | Out-File -FilePath $outFile -Encoding UTF8 -Force
    if (-not (Test-Path -LiteralPath $outFile)) {
        throw "File was not created after Out-File."
    }
} catch {
    Write-Host "[!] Failed to write baseline: $($_.Exception.Message)" -ForegroundColor Red
    Write-Error ("Failed to write baseline JSON to {0}: {1}" -f $outFile, $_.Exception.Message)
    throw
}

Write-Host "[+] Baseline written to: $outFile"
Write-Output $outFile
if ($collectorErrors.Count -gt 0) {
    $names = ($collectorErrors | ForEach-Object { $_.Collector }) -join ', '
    Write-Host "[!] $($collectorErrors.Count) collector error(s) in Meta.CollectorErrors: $names" -ForegroundColor Yellow
}
} catch {
    Write-Host "[!] BASELINE SCRIPT ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    at line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -ForegroundColor Red
    if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed }
    throw
}
