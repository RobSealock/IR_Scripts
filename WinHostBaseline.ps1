# WinHostBaseline.ps1
<#+
.SYNOPSIS
    Generate a host snapshot and compare it to a saved baseline.

.PARAMETER AllProfiles
    Opt-in. Load and scan all local user profile hives for HKU Run/RunOnce keys.

.PARAMETER ResolveNetworkPaths
    Opt-in. Attempt to resolve UNC and mapped-drive paths (may hang if unreachable).

.PARAMETER Firefox
    Opt-in. Enumerate Firefox profile extensions.

.NOTES
    Use -DebugLog for debug output without confirmation prompts.
    -Debug triggers Write-Debug which can prompt on each message; use -DebugLog instead.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)][string]$Mode,
    [string]$OutputDir = 'C:\Temp\Scan\Output\',
    [string]$RefDir    = 'C:\Temp\Scan\Ref\',

    # Debug logging to host (no confirmation prompts). Prefer over -Debug.
    [switch]$DebugLog,

    # Include established TCP connections and UDP remote endpoints (not just LISTEN).
    [switch]$IncludeRemoteSockets,

    # Opt-in: scan Run/RunOnce for ALL local profiles by loading user hives (admin required).
    [switch]$AllProfiles,

    # Opt-in: allow Normalize-PathSafe to resolve UNC / mapped drives (may hang if unreachable).
    [switch]$ResolveNetworkPaths,

    # Opt-in: also enumerate Firefox profiles/extensions.
    [switch]$Firefox
)


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$script:DebugLogEnabled = $DebugLog

function Write-DebugLog {
    param([string]$Message)
    if (-not $script:DebugLogEnabled) { return }
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    Write-Host "DEBUG: [$ts] $Message" -ForegroundColor DarkGray
}

if (-not (Get-Module WinHostBaselineCore)) {
    Write-DebugLog "Loading WinHostBaselineCore from $PSScriptRoot"
    Import-Module "$PSScriptRoot\WinHostBaselineCore.psm1" -ErrorAction Stop -DisableNameChecking
}
if (-not (Get-Module WinHostBaseline.Collectors)) {
    Write-DebugLog "Loading WinHostBaseline.Collectors from $PSScriptRoot"
    Import-Module "$PSScriptRoot\WinHostBaseline.Collectors.psm1" -ErrorAction Stop -DisableNameChecking
}
Write-DebugLog "Modules loaded; setting ResolveNetworkPaths=$ResolveNetworkPaths"
Set-WinHostBaselineOptions -ResolveNetworkPaths:$ResolveNetworkPaths

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-InteractiveUserName {
    $u = $null
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs -and $cs.UserName) { $u = ($cs.UserName -split '\\')[-1] }
    } catch { }
    if (-not $u) {
        try {
            $ex = Get-CimInstance -Class Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($ex) { $o = Invoke-CimMethod -InputObject $ex -MethodName GetOwner -ErrorAction SilentlyContinue; if ($o -and $o.User) { $u = $o.User } }
        } catch { }
    }
    return $u
}

function Invoke-BrowserScanAsInteractiveUser {
    param([string]$ScriptRoot, [string]$OutputDir)
    $interactive = Get-InteractiveUserName
    Write-DebugLog "Browser fallback: interactive user='$interactive', process user='$env:USERNAME'"
    if (-not $interactive -or $interactive -eq $env:USERNAME) {
        Write-DebugLog "Browser fallback: skipped (no interactive user or same as process)"
        return $null
    }
    $scanScript = Join-Path $ScriptRoot 'Scan-BrowserExtensions.ps1'
    if (-not (Test-Path -LiteralPath $scanScript)) {
        Write-DebugLog "Browser fallback: Scan-BrowserExtensions.ps1 not found at $scanScript"
        return $null
    }
    $usersDir = Join-Path $env:SystemDrive "\Users"
    $interactiveTemp = Join-Path $usersDir "$interactive\AppData\Local\Temp"
    if (-not (Test-Path -LiteralPath $interactiveTemp)) { $interactiveTemp = $OutputDir }
    $tempJson = Join-Path $interactiveTemp ("WinHostBaseline_browser_" + [guid]::NewGuid().ToString("n") + ".json")
    $taskName = "WinHostBaseline_BrowserScan_" + [guid]::NewGuid().ToString("n").Substring(0,8)
    $userId = ".\$interactive"
    try {
        Write-DebugLog "Browser fallback: running scan as $interactive, output $tempJson"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scanScript`" -JsonOutput `"$tempJson`""
        $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
        $deadline = (Get-Date).AddSeconds(45)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 1
            if (Test-Path -LiteralPath $tempJson) { break }
            $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
            if ($info -and $info.LastTaskResult -ne 267009) { break }
        }
        if (Test-Path -LiteralPath $tempJson) {
            Start-Sleep -Milliseconds 500
            $json = Get-Content -LiteralPath $tempJson -Raw -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $tempJson -Force -ErrorAction SilentlyContinue
            if ($json) {
                $objs = $json | ConvertFrom-Json -ErrorAction SilentlyContinue
                $count = @($objs).Count
                Write-DebugLog "Browser fallback: read $count item(s) from task output"
                return @($objs)
            }
        }
        Write-DebugLog "Browser fallback: no output file or empty (task may have failed)"
    } catch {
        Write-DebugLog "Browser fallback failed: $($_.Exception.Message)"
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    return $null
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Filter-ByCategory {
    param([object[]]$Items, [string]$Category)
    if (-not $Items) { return @() }
    return @($Items | Where-Object { $_.Category -eq $Category })
}

function Invoke-Collector {
    param(
        [string]$Name,
        [scriptblock]$Block,
        [ref]$Errors
    )
    try {
        Write-DebugLog "Collector '$Name' starting."
        $res = & $Block
        $count = if ($null -eq $res) { 0 } else { (@($res)).Length }
        Write-DebugLog "Collector '$Name' finished: $count item(s)."
        if ($null -eq $res) { return @() }
        return @($res)
    } catch {
        Write-DebugLog "Collector '$Name' failed: $($_.Exception.Message)"
        $Errors.Value += [pscustomobject]@{
            Collector = $Name
            Error     = $_.Exception.Message
        }
        return @()
    }
}

function Ensure-NormalizedForScore {
    param([object]$Item)
    if (-not $Item) { return $null }
    if ($Item.PSObject.Properties['Key'] -and $Item.PSObject.Properties['Identity'] -and $Item.PSObject.Properties['Signature']) {
        return (Normalize-HostItem $Item)
    }
    return $Item
}

$admin = Test-IsAdmin
Write-DebugLog "IsAdministrator=$admin"
if (-not $admin) {
    Write-Host "[!] Recommended to run as Administrator for full coverage." -ForegroundColor Yellow
    $ans = Read-Host "Continue anyway? (Y/N) [N]"
    if ($ans.ToUpper() -ne 'Y') { exit 1 }
}

Write-DebugLog "Ensuring directories: OutputDir=$OutputDir, RefDir=$RefDir"
Ensure-Directory $OutputDir
Ensure-Directory $RefDir

$runMode = if ($Mode) {
    if ($Mode -eq '1') { 'Baseline' }
    elseif ($Mode -eq '2') { 'Compare' }
    else { $Mode }
} else {
    $choice = Read-Host "Select Mode: [1] Generate Baseline, [2] Compare State [2]"
    switch ($choice) {
        '1'        { 'Baseline' }
        'Baseline' { 'Baseline' }
        '2'        { 'Compare' }
        'Compare'  { 'Compare' }
        default    { 'Compare' }
    }
}
Write-DebugLog "RunMode=$runMode"

if ($runMode -eq 'Baseline') {
    Write-DebugLog "Invoking Generate-OSBaseline.ps1 (RefDir=$RefDir, AllProfiles=$AllProfiles, ResolveNetworkPaths=$ResolveNetworkPaths, Firefox=$Firefox)"
    $outFile = & "$PSScriptRoot\Generate-OSBaseline.ps1" -OutputDir $RefDir -AllProfiles:$AllProfiles -ResolveNetworkPaths:$ResolveNetworkPaths -Firefox:$Firefox -CollectorDebug:$DebugLog
    return
}

$files = Get-ChildItem $RefDir -Filter *.json -ErrorAction SilentlyContinue
$filesArray = @($files)
Write-DebugLog "Found $($filesArray.Length) baseline file(s) in $RefDir"
if ($filesArray.Length -eq 0) { throw "No baseline files found in $RefDir" }

Write-Host "Select Reference:"
for ($i = 0; $i -lt $filesArray.Length; $i++) {
    Write-Host " [$($i+1)] $($filesArray[$i].Name)"
}

$sel = Read-Host "Choice [1]"
if ([string]::IsNullOrWhiteSpace($sel)) { $sel = '1' }
$idx = [int]$sel - 1
if ($idx -lt 0 -or $idx -ge $filesArray.Length) { throw "Invalid selection." }

$baselinePath = $filesArray[$idx].FullName
Write-DebugLog "Selected baseline: $baselinePath"
$baseJson     = Get-Content $baselinePath -Raw | ConvertFrom-Json
Write-DebugLog "Baseline JSON loaded."
# Backward-compat: tolerate older baselines that don't include newer sections
if (-not ($baseJson.PSObject.Properties.Name -contains 'BrowserExtensions')) { $baseJson | Add-Member -NotePropertyName BrowserExtensions -NotePropertyValue @(); Write-DebugLog "Added backward-compat property: BrowserExtensions" }
if (-not ($baseJson.PSObject.Properties.Name -contains 'WmiPersistence'))     { $baseJson | Add-Member -NotePropertyName WmiPersistence -NotePropertyValue @(); Write-DebugLog "Added backward-compat property: WmiPersistence" }
if (-not ($baseJson.PSObject.Properties.Name -contains 'NetworkSockets'))     { $baseJson | Add-Member -NotePropertyName NetworkSockets -NotePropertyValue @(); Write-DebugLog "Added backward-compat property: NetworkSockets" }


Write-Host "[*] Running current snapshot..."
if (-not $IncludeRemoteSockets) {
    Write-Host "[*] NOTE: Sockets collection is LISTEN-only (low noise). Use -IncludeRemoteSockets to include full TCP connections."
}

$collectorErrors = @()
if ($DebugLog) { $env:WinHostBaselineCollectorDebug = '1' }
Write-DebugLog "Running snapshot collectors (IncludeRemoteSockets=$IncludeRemoteSockets, AllProfiles=$AllProfiles, Firefox=$Firefox)."

$current = [pscustomobject]@{
    Services       = (Invoke-Collector 'Services'  { Get-ServicesHostItems }       ([ref]$collectorErrors)) | ForEach-Object { Normalize-HostItem $_ }
    Drivers        = (Invoke-Collector 'Drivers'   { Get-DriversHostItems }        ([ref]$collectorErrors)) | ForEach-Object { Normalize-HostItem $_ }
    Processes      = (Invoke-Collector 'Processes' { Get-ProcessesHostItems }      ([ref]$collectorErrors)) | ForEach-Object { Normalize-HostItem $_ }
    ScheduledTasks = (Invoke-Collector 'Tasks'     { Get-ScheduledTasksHostItems } ([ref]$collectorErrors)) | ForEach-Object { Normalize-HostItem $_ }
    Startup        = (Invoke-Collector 'Startup'   { Get-StartupHostItems -AllProfiles:$AllProfiles }        ([ref]$collectorErrors)) | ForEach-Object { Normalize-HostItem $_ }
    NetworkSockets = (Invoke-Collector 'Sockets'   { Get-NetworkSocketsHostItems -IncludeRemoteSockets:$IncludeRemoteSockets } ([ref]$collectorErrors)) | ForEach-Object { Normalize-HostItem $_ }
    WmiPersistence = (Invoke-Collector 'WMI'       { Get-WmiPersistenceHostItems } ([ref]$collectorErrors)) | ForEach-Object { Normalize-HostItem $_ }
    BrowserExtensions = (Invoke-Collector 'Browser' { Get-BrowserExtensionsHostItems -Firefox:$Firefox } ([ref]$collectorErrors)) | ForEach-Object { Normalize-HostItem $_ }
}
$browserCount = @($current.BrowserExtensions).Count
Write-DebugLog "BrowserExtensions collected: $browserCount item(s)."
if ($browserCount -eq 0) {
    $fallback = $null
    if (Test-IsAdmin) {
        $fallback = Invoke-BrowserScanAsInteractiveUser -ScriptRoot $PSScriptRoot -OutputDir $OutputDir
    }
    if (-not $fallback -or (@($fallback).Count -eq 0)) {
        $scanScript = Join-Path $PSScriptRoot 'Scan-BrowserExtensions.ps1'
        $tempJson = Join-Path ([System.IO.Path]::GetTempPath()) ("WinHostBaseline_browser_" + [guid]::NewGuid().ToString("n") + ".json")
        if (Test-Path -LiteralPath $scanScript) {
            try {
                & $scanScript -JsonOutput $tempJson
                if (Test-Path -LiteralPath $tempJson) {
                    $json = Get-Content -LiteralPath $tempJson -Raw -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath $tempJson -Force -ErrorAction SilentlyContinue
                    if ($json) { $fallback = @($json | ConvertFrom-Json -ErrorAction SilentlyContinue) }
                }
            } catch { Write-DebugLog "Browser in-process fallback failed: $($_.Exception.Message)" }
        }
    }
    if ($fallback -and (@($fallback).Count -gt 0)) {
        $current.BrowserExtensions = @($fallback | ForEach-Object { Normalize-HostItem $_ })
        Write-DebugLog "BrowserExtensions fallback: $(@($current.BrowserExtensions).Count) item(s)."
    }
}

$results = @(
    Compare-HostCategory -Category 'Services'       -Baseline $baseJson.Services       -Current $current.Services
    Compare-HostCategory -Category 'Drivers'        -Baseline $baseJson.Drivers        -Current $current.Drivers
    Compare-HostCategory -Category 'Processes'      -Baseline $baseJson.Processes      -Current $current.Processes      -IgnoreMetadataKeys @('ProcessIds','ParentProcessIds','Count')
    Compare-HostCategory -Category 'ScheduledTasks' -Baseline $baseJson.ScheduledTasks -Current $current.ScheduledTasks -IgnoreMetadataKeys @('LastRunTime','NextRunTime')
    Compare-HostCategory -Category 'Startup'        -Baseline $baseJson.Startup        -Current $current.Startup
    Compare-HostCategory -Category 'BrowserExtensions' -Baseline $baseJson.BrowserExtensions -Current $current.BrowserExtensions
    Compare-HostCategory -Category 'NetworkSockets' -Baseline $baseJson.NetworkSockets -Current $current.NetworkSockets

    Compare-HostCategory -Category 'WMI.Filter'     -Baseline (Filter-ByCategory $baseJson.WmiPersistence 'WMI.Filter')   -Current (Filter-ByCategory $current.WmiPersistence 'WMI.Filter')
    Compare-HostCategory -Category 'WMI.Consumer'   -Baseline (Filter-ByCategory $baseJson.WmiPersistence 'WMI.Consumer') -Current (Filter-ByCategory $current.WmiPersistence 'WMI.Consumer')
    Compare-HostCategory -Category 'WMI.Consumer.ActiveScript' -Baseline (Filter-ByCategory $baseJson.WmiPersistence 'WMI.Consumer.ActiveScript') -Current (Filter-ByCategory $current.WmiPersistence 'WMI.Consumer.ActiveScript')
    Compare-HostCategory -Category 'WMI.Binding'    -Baseline (Filter-ByCategory $baseJson.WmiPersistence 'WMI.Binding')  -Current (Filter-ByCategory $current.WmiPersistence 'WMI.Binding')
)
Write-DebugLog "Compare-HostCategory completed for all categories."

$findings = New-Object System.Collections.Generic.List[object]

foreach ($cat in $results) {
    foreach ($x in $cat.Added) {
        $nx = Ensure-NormalizedForScore $x
        $findings.Add([pscustomobject]@{
            Category = $cat.Category
            Type     = 'Added'
            Key      = $x.Key
            Score    = Score-HostItem $nx
            Item     = $x
        })
    }
    foreach ($x in $cat.Changed) {
        $nx = Ensure-NormalizedForScore $x.Current
        $findings.Add([pscustomobject]@{
            Category = $cat.Category
            Type     = 'Changed'
            Key      = $x.Key
            Score    = Score-HostItem $nx
            Item     = $x
        })
    }
}
Write-DebugLog "Findings: $($findings.Count) total (Added/Changed)."

$report = [pscustomobject]@{
    Meta = @{
        ComparedAtUtc        = (Get-Date).ToUniversalTime().ToString('o')
        BaselinePath         = $baselinePath
        ComputerName         = $env:COMPUTERNAME
        IncludeRemoteSockets = [bool]$IncludeRemoteSockets
        CollectorErrors      = $collectorErrors
    }
    Results        = $results
    RankedFindings = ($findings.ToArray() | Sort-Object Score -Descending)
}

$ts = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$reportPath = Join-Path $OutputDir "compare-report-$($env:COMPUTERNAME)-$ts.json"
Write-DebugLog "Writing report to $reportPath"
$report | ConvertTo-Json -Depth 16 | Out-File $reportPath -Encoding UTF8

function Get-FindingDetailsHtml {
    param([string]$Category, [object]$Item)
    if (-not $Item -or -not $Item.Metadata) { return '' }
    $m = $Item.Metadata
    $parts = @()
    if ($Category -eq 'BrowserExtensions') {
        $n = ''; $a = ''; try { $n = $m.ExtensionName } catch { }; try { $a = $m.Author } catch { }
        if ($n) { $parts += "Name: $n" }; if ($a) { $parts += "Author: $a" }
    } elseif ($Category -eq 'Drivers') {
        $d = ''; $v = ''; try { $d = $m.DisplayName } catch { }; try { $v = $m.Vendor } catch { }
        if ($d) { $parts += "DisplayName: $d" }; if ($v) { $parts += "Vendor: $v" }
    } elseif ($Category -eq 'Services') {
        $st = ''; $pn = ''; $sn = ''; try { $st = $m.State } catch { }; try { $pn = $m.PathName } catch { }; try { $sn = $m.StartName } catch { }
        if ($st) { $parts += "State: $st" }; if ($sn) { $parts += "RunAs: $sn" }; if ($pn) { $parts += "Path: $pn" }
    }
    $txt = ($parts -join ' | ')
    return [System.Net.WebUtility]::HtmlEncode($txt)
}

# Build HTML report (differences only, table format) in same location
$htmlPath = Join-Path $OutputDir "compare-report-$($env:COMPUTERNAME)-$ts.html"
$ranked = $findings.ToArray() | Sort-Object Score -Descending
$tableRows = foreach ($f in $ranked) {
    $path = ''
    $item = if ($f.Type -eq 'Changed' -and $f.Item -and $f.Item.Current) { $f.Item.Current } else { $f.Item }
    try { if ($item -and $item.Identity) { $path = [string]$item.Identity.Path } } catch { }
    $detailsEsc = Get-FindingDetailsHtml -Category $f.Category -Item $item
    $keyEsc = [System.Net.WebUtility]::HtmlEncode($f.Key)
    $pathEsc = [System.Net.WebUtility]::HtmlEncode($path)
    $typeClass = if ($f.Type -eq 'Added') { 'added' } else { 'changed' }
    "<tr class=`"$typeClass`"><td>$([System.Net.WebUtility]::HtmlEncode($f.Category))</td><td>$([System.Net.WebUtility]::HtmlEncode($f.Type))</td><td>$keyEsc</td><td>$($f.Score)</td><td title=`"$pathEsc`">$pathEsc</td><td title=`"$detailsEsc`">$detailsEsc</td></tr>"
}
$rowsHtml = if ($tableRows) { $tableRows -join "`n" } else { "<tr><td colspan=`"6`">None.</td></tr>" }

# Added (not present in reference): items in reference/baseline but not in current snapshot
$addedFromRefRows = foreach ($cat in $results) {
    foreach ($x in $cat.Removed) {
        $path = ''
        $keyVal = ''
        try { if ($x -and $x.Identity) { $path = [string]$x.Identity.Path } } catch { }
        try { $keyVal = $x.Key } catch { }
        $detailsEsc = Get-FindingDetailsHtml -Category $x.Category -Item $x
        $keyEsc = [System.Net.WebUtility]::HtmlEncode($keyVal)
        $pathEsc = [System.Net.WebUtility]::HtmlEncode($path)
        "<tr class=`"added`"><td>$([System.Net.WebUtility]::HtmlEncode($x.Category))</td><td>Added</td><td>$keyEsc</td><td>-</td><td title=`"$pathEsc`">$pathEsc</td><td title=`"$detailsEsc`">$detailsEsc</td></tr>"
    }
}
$addedFromRefRowsHtml = if ($addedFromRefRows) { $addedFromRefRows -join "`n" } else { "<tr><td colspan=`"6`">None.</td></tr>" }

# Scheduled task exports (XML) for current snapshot tasks
$taskExportsHtml = ''
$taskList = @($current.ScheduledTasks)
if ($taskList.Count -gt 0) {
    $taskBlocks = foreach ($t in $taskList) {
        $keyVal = $null; try { $keyVal = $t.Key } catch { }
        if (-not $keyVal -or $keyVal -notmatch '^Task:(.+)\|(.+)$') { continue }
        $taskPath = $matches[1]
        $taskName = $matches[2]
        $xml = ''
        try {
            $out = Export-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop 2>&1
            if ($out) { $xml = [string]$out }
        } catch { $xml = "Export failed: $($_.Exception.Message)" }
        $summaryEsc = [System.Net.WebUtility]::HtmlEncode("$taskPath$taskName")
        $xmlEsc = [System.Net.WebUtility]::HtmlEncode($xml)
        "<details><summary>$summaryEsc</summary><pre>$xmlEsc</pre></details>"
    }
    $taskExportsHtml = if ($taskBlocks) { $taskBlocks -join "`n" } else { "<p>No tasks exported.</p>" }
} else {
    $taskExportsHtml = "<p>No scheduled tasks in current snapshot.</p>"
}

$metaHtml = "Baseline: $([System.Net.WebUtility]::HtmlEncode($baselinePath)) | Computer: $([System.Net.WebUtility]::HtmlEncode($env:COMPUTERNAME)) | Compared: $($report.Meta.ComparedAtUtc)"
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Baseline Compare - $([System.Net.WebUtility]::HtmlEncode($env:COMPUTERNAME))</title>
<style>
body { font-family: Segoe UI, sans-serif; margin: 20px; background: #1e1e1e; color: #d4d4d4; }
h1 { font-size: 1.25rem; margin-bottom: 4px; }
h2 { font-size: 1rem; margin: 24px 0 8px 0; color: #cccccc; }
.meta { font-size: 0.8rem; color: #858585; margin-bottom: 16px; }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; margin-bottom: 8px; }
th { text-align: left; padding: 8px 12px; background: #2d2d2d; border: 1px solid #404040; }
td { padding: 6px 12px; border: 1px solid #404040; }
tr.added { background: #1a2e1a; }
tr.changed { background: #2e2a1a; }
tr:hover { background: #333; }
td:nth-child(4) { text-align: right; }
td:nth-child(5) { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
td:nth-child(6) { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.85rem; color: #b0b0b0; }
details { margin: 8px 0; }
details summary { cursor: pointer; }
details pre { margin: 4px 0 0 0; padding: 8px; background: #252525; border: 1px solid #404040; overflow-x: auto; font-size: 0.75rem; white-space: pre-wrap; word-break: break-all; }
</style>
</head>
<body>
<h1>Baseline comparison - differences only</h1>
<p class="meta">$metaHtml</p>
<h2>Added / Changed (in current, not in reference or modified)</h2>
<table>
<thead><tr><th>Category</th><th>Type</th><th>Key</th><th>Score</th><th>Path</th><th>Details (name/vendor/state/runas)</th></tr></thead>
<tbody>
$rowsHtml
</tbody>
</table>
<h2>Added (not present in reference)</h2>
<table>
<thead><tr><th>Category</th><th>Type</th><th>Key</th><th>Score</th><th>Path</th><th>Details</th></tr></thead>
<tbody>
$addedFromRefRowsHtml
</tbody>
</table>
<h2>Scheduled task exports (XML)</h2>
$taskExportsHtml
</body>
</html>
"@
$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-DebugLog "HTML report written to $htmlPath"

Write-Host "[+] Comparison complete. Report: $reportPath"
Write-Host "[+] HTML report (differences): $htmlPath"
if ((@($collectorErrors)).Length -gt 0) {
    Write-Host "[!] Collector warnings/errors were recorded in report Meta.CollectorErrors" -ForegroundColor Yellow
}
