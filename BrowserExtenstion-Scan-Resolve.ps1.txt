<#
.SYNOPSIS
    Scan Chrome and Edge extensions for all user profiles.
    Perform online lookup of extension metadata from the Chrome Web Store AND Edge Add-ons Store.
    Resolves localized names (e.g., __MSG_appName__) from local files.
    
    * UPDATED: Saves HTML report to the script's directory.

.PARAMETER JsonOutput
    If set, write HostItem-shaped JSON to this path.

.EXAMPLE
    .\BrowserExtenstion-Scan-Resolve.ps1
#>

[CmdletBinding()]
param(
    [string]$JsonOutput = ''
)

$ErrorActionPreference = 'Continue'
$quiet = [string]::IsNullOrWhiteSpace($JsonOutput) -eq $false

if (-not $quiet) {
    Write-Host "=== Browser extension scan ===" -ForegroundColor Cyan
    Write-Host "Process user: $env:USERNAME" -ForegroundColor Gray
    Write-Host ""
}

$all = [System.Collections.ArrayList]@()

# Common headers to mimic a real browser
$Global:Headers = @{
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
}

function Get-ExtensionStoreMetadata {
    param([string]$ExtId)

    # Result object template
    $result = [pscustomobject]@{
        Name          = $null
        Description   = $null
        Developer     = $null
        Rating        = $null
        RatingCount   = $null
        UserCount     = $null
        Category      = $null
        Version       = $null
        LastUpdated   = $null
        HomepageUrl   = $null
        SupportUrl    = $null
        PrivacyPolicy = $null
        IconUrl       = $null
        StoreUrl      = $null
        Source        = $null
    }

    $resolved = $false

    # --- 1. Chrome Web Store (AJAX) ---
    try {
        $url = "https://chrome.google.com/webstore/ajax/detail?hl=en&gl=US&pv=202402&id=$ExtId"
        $resp = Invoke-WebRequest -Uri $url -Headers $Global:Headers -ErrorAction Stop
        $json = $resp.Content | ConvertFrom-Json

        if ($json -and $json.Count -ge 2 -and $json[1][1][0]) {
            $root = $json[1][1][0]
            $result.Name          = $root[23] # Name
            $result.Description   = $root[6]  # Desc
            $result.Version       = $root[3]  # Version
            $result.IconUrl       = $root[1]  # Icon
            $result.StoreUrl      = "https://chrome.google.com/webstore/detail/$ExtId"
            $result.Source        = "Chrome Web Store"
            
            if ($result.Name) { $resolved = $true }
        }
    }
    catch { }

    # --- 2. Microsoft Edge Add-ons (HTML Scrape) ---
    # Many system extensions (like 'cnlefm...') are only here.
    if (-not $resolved) {
        try {
            $urlEdge = "https://microsoftedge.microsoft.com/addons/detail/$ExtId"
            $respEdge = Invoke-WebRequest -Uri $urlEdge -Headers $Global:Headers -ErrorAction SilentlyContinue
            
            if ($respEdge.StatusCode -eq 200) {
                $html = $respEdge.Content
                
                # Simple regex scrape for Edge Store (Metadata is often in <meta> tags)
                if ($html -match '<meta property="og:title" content="([^"]+)"') {
                    $result.Name = $matches[1] -replace ' - Microsoft Edge Addons',''
                }
                if ($html -match '<meta property="og:description" content="([^"]+)"') {
                    $result.Description = $matches[1]
                }
                
                $result.StoreUrl = $urlEdge
                $result.Source   = "Edge Add-ons"
                
                if ($result.Name) { $resolved = $true }
            }
        }
        catch { }
    }

    return $result
}

function Get-ExtensionNameLocal {
    param([string]$manifestPath)

    if (-not (Test-Path -LiteralPath $manifestPath)) { return $null }

    try {
        $content = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop 
        # Handle BOM or encoding issues if necessary
        $json = $content | ConvertFrom-Json

        $name = $null
        if ($json.name) {
            if ($json.name -is [string]) { $name = $json.name }
        }

        # Handle Localization (e.g., __MSG_appName__)
        if ($name -and $name.StartsWith("__MSG_")) {
            $msgKey = $name -replace "__MSG_(.+?)__", '$1'
            $baseDir = Split-Path -Parent $manifestPath
            
            # 1. Check default_locale from manifest
            $checkLocales = @()
            if ($json.default_locale) { $checkLocales += $json.default_locale }
            $checkLocales += @("en_US", "en", "en_GB")

            foreach ($loc in $checkLocales) {
                $msgPath = Join-Path $baseDir "_locales\$loc\messages.json"
                if (Test-Path -LiteralPath $msgPath) {
                    try {
                        $msgJson = Get-Content -LiteralPath $msgPath -Raw | ConvertFrom-Json
                        if ($msgJson.$msgKey.message) {
                            return $msgJson.$msgKey.message
                        }
                    } catch {}
                }
            }
        }

        return $name
    }
    catch { return $null }
}

function Scan-ChromiumUserData {
    param(
        [string]$BrowserName,
        [string]$UserDataRoot,
        [string]$UserLabel = ''
    )

    if (-not (Test-Path -LiteralPath $UserDataRoot)) { return }

    $profiles = Get-ChildItem -LiteralPath $UserDataRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }

    foreach ($prof in $profiles) {
        $extRoot = Join-Path $prof.FullName "Extensions"
        if (-not (Test-Path -LiteralPath $extRoot)) { continue }

        $dirs = Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue

        foreach ($d in $dirs) {
            $extId = $d.Name

            # Get latest version folder
            $verDirs = Get-ChildItem -LiteralPath $d.FullName -Directory -ErrorAction SilentlyContinue
            if (-not $verDirs) { continue }
            
            # Sort by version number logic
            $latestDir = $verDirs | Sort-Object { [version]($_.Name -replace '[^0-9.]','') } -Descending | Select-Object -First 1
            $latestVer = $latestDir.Name
            
            $manifestPath = Join-Path $latestDir.FullName "manifest.json"

            # 1. Resolve Local Name (checking _locales)
            $localName = Get-ExtensionNameLocal $manifestPath

            # 2. Resolve Online Metadata
            $storeMeta = Get-ExtensionStoreMetadata $extId

            # 3. Determine Final "Best" Name
            $finalName = $extId
            if ($storeMeta.Name) { 
                $finalName = $storeMeta.Name 
            } elseif ($localName) { 
                $finalName = "$localName (Local)" 
            } else {
                $finalName = "$extId (Unknown)"
            }

            [void]$all.Add([pscustomobject]@{
                User        = $UserLabel
                Browser     = $BrowserName
                Profile     = $prof.Name
                ExtId       = $extId
                Version     = $latestVer
                Name        = $finalName
                StoreUrl    = if ($storeMeta.StoreUrl) { $storeMeta.StoreUrl } else { "" }
                Source      = if ($storeMeta.Source) { $storeMeta.Source } else { "Local Only" }
                Path        = $manifestPath
                Description = if ($storeMeta.Description) { $storeMeta.Description } else { "" }
            })
        }
    }
}

if (-not $quiet) { Write-Host "--- Scanning Current User ---" -ForegroundColor Yellow }

$chromePath = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data"
$edgePath   = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data"

Scan-ChromiumUserData -BrowserName 'Chrome' -UserDataRoot $chromePath -UserLabel $env:USERNAME
Scan-ChromiumUserData -BrowserName 'Edge'   -UserDataRoot $edgePath   -UserLabel $env:USERNAME

# --- Scan Other Users (Admin Only) ---
$usersDir = Join-Path $env:SystemDrive "\Users"
if (Test-Path -LiteralPath $usersDir) {
    Get-ChildItem -LiteralPath $usersDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $un = $_.Name
        if ($un -in @('Public','Default','Default User','All Users',$env:USERNAME)) { return }

        Scan-ChromiumUserData -BrowserName 'Chrome' -UserDataRoot "$($_.FullName)\AppData\Local\Google\Chrome\User Data" -UserLabel $un
        Scan-ChromiumUserData -BrowserName 'Edge'   -UserDataRoot "$($_.FullName)\AppData\Local\Microsoft\Edge\User Data" -UserLabel $un
    }
}

# --- Output HTML to Script Directory ---
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
$htmlPath = Join-Path $scriptDir "BrowserExtensionsReport.html"

$htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<style>
body { font-family: Segoe UI, sans-serif; font-size: 13px; }
table { border-collapse: collapse; width: 100%; margin-top: 10px; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
tr:nth-child(even) { background-color: #f9f9f9; }
a { text-decoration: none; color: #0078D7; }
</style>
</head>
<body>
<h2>Browser Extensions Report</h2>
<small>Generated: $(Get-Date)</small>
<table>
<thead>
<tr>
    <th>User</th>
    <th>Browser</th>
    <th>Profile</th>
    <th>Extension Name</th>
    <th>Version</th>
    <th>Source</th>
    <th>ID / Link</th>
</tr>
</thead>
<tbody>
"@

$rows = foreach ($r in $all) {
    $link = if ($r.StoreUrl) { "<a href='$($r.StoreUrl)' target='_blank'>$($r.ExtId)</a>" } else { $r.ExtId }
    
    "<tr>" +
    "<td>$($r.User)</td>" +
    "<td>$($r.Browser)</td>" +
    "<td>$($r.Profile)</td>" +
    "<td><b>$($r.Name)</b><br><small>$($r.Description)</small></td>" +
    "<td>$($r.Version)</td>" +
    "<td>$($r.Source)</td>" +
    "<td>$link</td>" +
    "</tr>"
}

$htmlFooter = "</tbody></table></body></html>"
$htmlContent = $htmlHeader + ($rows -join "`r`n") + $htmlFooter
$htmlContent | Set-Content -LiteralPath $htmlPath -Encoding UTF8

if (-not $quiet) {
    Write-Host "Found $($all.Count) extensions." -ForegroundColor Green
    Write-Host "Report saved to: $htmlPath" -ForegroundColor Cyan
    Invoke-Item $htmlPath
}