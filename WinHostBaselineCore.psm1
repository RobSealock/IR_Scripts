# WinHostBaselineCore.psm1
Set-StrictMode -Version Latest

class HostSignature {
    [string]$Status
    [string]$Signer
    [string]$Thumbprint
    [bool]  $IsMicrosoft
    [bool]  $IsSysinternals
    [bool]  $IsUserWritable
}

class HostIdentity {
    [string]$Path
    [string]$CommandLine
    [string]$Sha256
}

class HostItem {
    [string]        $Key
    [string]        $Category
    [HostIdentity]  $Identity
    [HostSignature] $Signature
    [hashtable]     $Metadata
}



function New-HostSignature {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Props)
    $o = [pscustomobject]$Props
    $o.PSObject.TypeNames.Insert(0, 'WinHostBaseline.HostSignature')
    return $o
}

function New-HostIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Props)
    $o = [pscustomobject]$Props
    $o.PSObject.TypeNames.Insert(0, 'WinHostBaseline.HostIdentity')
    return $o
}

function New-HostItem {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Props)
    $o = [pscustomobject]$Props
    $o.PSObject.TypeNames.Insert(0, 'WinHostBaseline.HostItem')
    return $o
}

$script:ResolveNetworkPathsDefault = $false

$script:SigCache  = @{}
$script:HashCache = @{}

function Normalize-PathSafe {
    <#
    .SYNOPSIS
        Normalizes a filesystem path without hanging on unreachable network shares by default.

    .PARAMETER Path
        Path to normalize.

    .PARAMETER ResolveNetworkPaths
        Opt-in. If set, attempt to resolve UNC and mapped-drive paths (may hang if offline/unreachable).
    #>
    param(
        [string]$Path,
        [switch]$ResolveNetworkPaths
    )

    $resolve = $ResolveNetworkPaths
    if (-not $PSBoundParameters.ContainsKey('ResolveNetworkPaths')) { $resolve = $script:ResolveNetworkPathsDefault }

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $p = $Path.Trim().Trim('"')
    $p = [Environment]::ExpandEnvironmentVariables($p)
    $p = $p -replace '/', '\'

    # Avoid long timeouts on dead UNC paths or disconnected mapped drives unless explicitly opted in.
    if (-not $resolve) {
        if ($p -match '^\\\\') { return $p }

        # Detect mapped drives (DisplayRoot is UNC) and skip resolution unless opted in.
        if ($p -match '^[A-Za-z]:\\') {
            $driveName = $p.Substring(0,1)
            try {
                $drv = Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue
                if ($drv -and $drv.DisplayRoot -and ($drv.DisplayRoot -match '^\\\\')) {
                    return $p
                }
            } catch { }
        }
    }

    try {
        if (Test-Path -LiteralPath $p) {
            return (Get-Item -LiteralPath $p -ErrorAction Stop).FullName
        }
        return $p
    } catch {
        return $p
    }
}


function Set-WinHostBaselineOptions {
    <#
    .SYNOPSIS
        Sets module-wide defaults (PowerShell 5.1 compatible).

    .PARAMETER ResolveNetworkPaths
        If set, Normalize-PathSafe will attempt to resolve UNC and mapped-drive paths by default.
    #>
    param(
        [switch]$ResolveNetworkPaths
    )
    $script:ResolveNetworkPathsDefault = [bool]$ResolveNetworkPaths
}


function Extract-ExePath {
    param([string]$CommandOrPath)

    if ([string]::IsNullOrWhiteSpace($CommandOrPath)) { return $null }
    $s = $CommandOrPath.Trim()

    # 1) Quoted path: "C:\Program Files\App\app.exe" args...
    if ($s.StartsWith('"')) {
        $m = [regex]::Match($s, '^"([^"]+)"')
        if ($m.Success) { return Normalize-PathSafe $m.Groups[1].Value }
    }

    # 2) Drive-rooted or UNC path, possibly unquoted and containing spaces.
    # Non-greedy consume until the first .exe word boundary.
    $m3 = [regex]::Match($s, '^(?:[a-zA-Z]:\\|\\\\).*?\.exe\b', 'IgnoreCase')
    if ($m3.Success) { return Normalize-PathSafe $m3.Value }

    # 3) Token-walk fallback for odd commandline structures.
    $tokens = $s -split '\s+'
    if ($tokens.Count -gt 1) {
        $candidate = $tokens[0]
        for ($i = 1; $i -lt $tokens.Count; $i++) {
            $candidate = "$candidate $($tokens[$i])"

            if ($candidate -match '\.exe\b') {
                $mm = [regex]::Match($candidate, '^(.*?\.exe)\b', 'IgnoreCase')
                if ($mm.Success) {
                    $p2 = Normalize-PathSafe $mm.Groups[1].Value
                    if ($p2 -and (Test-Path -LiteralPath $p2)) { return $p2 }
                }
            }
        }
    }

    return $null
}


function Is-UserWritablePath {
    param([string]$Path)

    $p = Normalize-PathSafe $Path
    if (-not $p) { return $false }
    $pl = $p.ToLower()

    $patterns = @(
        '\appdata\',
        '\temp\',
        '\windows\temp\',
        '\downloads\',
        '\users\public\',
        '\perflogs\',
        '\onedrive\'
    )

    foreach ($pat in $patterns) {
        if ($pl.Contains($pat)) { return $true }
    }
    return $false
}

function Is-MicrosoftSigner {
    param([string]$Subject)

    if (-not $Subject) { return $false }
    foreach ($a in 'CN=Microsoft Windows','CN=Microsoft Corporation') {
        if ($Subject -like "$a*") { return $true }
    }
    return $false
}

function Is-SysinternalsFile {
    param([string]$Path)

    $p = Normalize-PathSafe $Path
    if (-not $p -or -not (Test-Path -LiteralPath $p)) { return $false }

    $fn = [System.IO.Path]::GetFileName($p).ToLower()
    $names = @(
        'psexec.exe','psexesvc.exe','procexp.exe','procexp64.exe','procmon.exe','procmon64.exe',
        'autoruns.exe','autoruns64.exe','autorunsc.exe','autorunsc64.exe','pslist.exe','pskill.exe',
        'psservice.exe','psshutdown.exe','psinfo.exe','psloggedon.exe','tcpview.exe','tcpview64.exe',
        'handle.exe','handle64.exe','sigcheck.exe','sigcheck64.exe','streams.exe','strings.exe',
        'accesschk.exe','accessenum.exe','sdelete.exe','sdelete64.exe','du.exe','du64.exe','psping.exe',
        'whois.exe','dbgview.exe','rammap.exe','diskmon.exe','portmon.exe','sysmon.exe','sysmon64.exe'
    )
    if ($names -contains $fn) { return $true }

    try {
        $vi = (Get-Item -LiteralPath $p).VersionInfo
        $fields = @($vi.CompanyName,$vi.ProductName,$vi.FileDescription,$vi.OriginalFilename) -join ' '
        if ($fields.ToLower() -match 'sysinternals') { return $true }
    } catch {}

    return $false
}

function Get-FileHashSafe {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    # Avoid hangs on unreachable network shares / disconnected mapped drives unless explicitly allowed.
    if (-not $script:ResolveNetworkPathsDefault) {
        if ($Path -match '^\\\\') { return $null }

        # If the path uses a drive letter that maps to a UNC root, treat as network.
        if ($Path -match '^[A-Za-z]:\\') {
            $dl = $Path.Substring(0,1)
            try {
                $d = Get-PSDrive -Name $dl -ErrorAction Stop
                if ($d -and $d.Provider -and $d.Provider.Name -eq 'FileSystem' -and $d.DisplayRoot -and ($d.DisplayRoot -match '^\\\\')) {
                    return $null
                }
            } catch {
                # ignore
            }
        }
    }

    $p = Normalize-PathSafe $Path
    if (-not $p -or -not (Test-Path -LiteralPath $p)) { return $null }

    if ($script:HashCache.ContainsKey($p)) { return $script:HashCache[$p] }

    try {
        # Directory fingerprinting (Get-FileHash does not accept directories)
        if (Test-Path -LiteralPath $p -PathType Container) {
            $h = Get-DirectoryFingerprintSafe -Path $p
            $script:HashCache[$p] = $h
            return $h
        }

        $fh = Get-FileHash -Algorithm SHA256 -LiteralPath $p
        $script:HashCache[$p] = $fh.Hash
        return $fh.Hash
    } catch {
        return $null
    }
}

function Get-DirectoryFingerprintSafe {
    <#
    .SYNOPSIS
        Compute a stable SHA256 fingerprint for a directory (recursive).

    .DESCRIPTION
        Enumerates files under the directory, hashes each file, then hashes the ordered
        list of (relative path + hash) entries to produce a stable directory fingerprint.

        This is used when a collector's best available artifact is a folder (e.g., an extension root
        without a manifest.json).

    .NOTES
        PowerShell 5.1 compatible. Best-effort: unreadable files are skipped.
    #>
    param([Parameter(Mandatory=$true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }

    try {
        $root = (Get-Item -LiteralPath $Path -ErrorAction Stop).FullName.TrimEnd('\')
    } catch {
        return $null
    }

    $pairs = New-Object System.Collections.Generic.List[string]

    # Truncation limits to prevent extremely large folders from causing long runtimes.
    # These affect only the directory fingerprinting fallback.
    $maxFiles = 5000
    $maxTotalBytes = 50MB
    $fileCount = 0
    $totalBytes = 0

    foreach ($f in (Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue)) {
        # Truncation checks
        $fileCount++
        $totalBytes += [int64]$f.Length
        if ($fileCount -gt $maxFiles -or $totalBytes -gt $maxTotalBytes) {
            $pairs.Add("__TRUNCATED__:${fileCount}:${totalBytes}")
            break
        }

        # Hash individual file
        $hash = $null
        try {
            $hh = Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName -ErrorAction Stop
            $hash = $hh.Hash
        } catch {
            $hash = ''
        }

        $rel = $f.FullName.Substring($root.Length).TrimStart('\')
        $pairs.Add( ($rel.ToLowerInvariant()) + ':' + $hash )
    }

    # Stable ordering
    $ordered = $pairs | Sort-Object

    $text = [string]::Join("\n", $ordered)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)

    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $digest = $sha.ComputeHash($bytes)
        ($digest | ForEach-Object { $_.ToString('x2') }) -join ''
    } catch {
        return $null
    } finally {
        if ($sha) { $sha.Dispose() }
    }
}


function Get-SignatureSafe {
    param([string]$Path)

    $p = Normalize-PathSafe $Path
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
        return [HostSignature]@{
            Status='Missing';Signer='';Thumbprint='';
            IsMicrosoft=$false;IsSysinternals=$false;IsUserWritable=(Is-UserWritablePath $p)
        }
    }

    if ($script:SigCache.ContainsKey($p)) { return $script:SigCache[$p] }

    $raw = $null
    try {
        $raw = Get-AuthenticodeSignature -FilePath $p -ErrorAction Stop
    } catch {
        $sig = [HostSignature]@{
            Status='Error';Signer='';Thumbprint='';
            IsMicrosoft=$false;IsSysinternals=$false;IsUserWritable=(Is-UserWritablePath $p)
        }
        $script:SigCache[$p] = $sig
        return $sig
    }

    $subj  = if ($raw.SignerCertificate) { $raw.SignerCertificate.Subject } else { '' }
    $thumb = if ($raw.SignerCertificate) { $raw.SignerCertificate.Thumbprint } else { '' }

    $isMs = ($subj -match 'O=Microsoft Corporation')
    $isSi = ($subj -match 'Sysinternals') -or ($subj -match 'O=Microsoft Corporation' -and $subj -match 'Sysinternals')

    $sig = [HostSignature]@{
        Status       = $raw.Status.ToString()
        Signer       = $subj
        Thumbprint   = $thumb
        IsMicrosoft  = [bool]$isMs
        IsSysinternals = [bool]$isSi
        IsUserWritable = (Is-UserWritablePath $p)
    }

    $script:SigCache[$p] = $sig
    return $sig
}


function ConvertTo-HashtableSafe {
    param([object]$Obj)

    if (-not $Obj) { return @{} }
    if ($Obj -is [hashtable]) { return (@{} + $Obj) }

    $ht = @{}
    foreach ($p in $Obj.PSObject.Properties) {
        $ht[$p.Name] = $p.Value
    }
    return $ht
}

function Normalize-HostItem {
    param([psobject]$Item)

    return @{
        Key      = $Item.Key
        Category = $Item.Category
        Identity = @{
            Path        = $Item.Identity.Path
            CommandLine = $Item.Identity.CommandLine
            Sha256      = $Item.Identity.Sha256
        }
        Signature = @{
            Status        = $Item.Signature.Status
            Signer        = $Item.Signature.Signer
            Thumbprint    = $Item.Signature.Thumbprint
            IsMicrosoft   = $Item.Signature.IsMicrosoft
            IsSysinternals= $Item.Signature.IsSysinternals
            IsUserWritable= $Item.Signature.IsUserWritable
        }
        # Clone metadata to avoid accidental mutation coupling
        Metadata = (ConvertTo-HashtableSafe $Item.Metadata)
    }
}

function ConvertTo-OrderedHashtableSafe {
    <#
    .SYNOPSIS
        Creates a deterministic, JSON-friendly ordered hashtable for comparison.
        PowerShell 5.1-compatible.

    .PARAMETER InputObject
        Object to convert.
    #>
    param([object]$InputObject)

    if ($null -eq $InputObject) { return $null }

    # Preserve strings
    if ($InputObject -is [string]) { return $InputObject }

    # Convert dictionaries / hashtables
    if ($InputObject -is [hashtable] -or $InputObject -is [System.Collections.IDictionary]) {
        $keys = @($InputObject.Keys) | Sort-Object
        $o = [ordered]@{}
        foreach ($k in $keys) {
            $o[$k] = ConvertTo-OrderedHashtableSafe $InputObject[$k]
        }
        return $o
    }

    # PSCustomObject
    if ($InputObject -is [pscustomobject]) {
        $props = $InputObject.PSObject.Properties.Name | Sort-Object
        $o = [ordered]@{}
        foreach ($p in $props) {
            $o[$p] = ConvertTo-OrderedHashtableSafe $InputObject.$p
        }
        return $o
    }

    # Arrays / enumerables (avoid treating string as enumerable)
    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $arr = @()
        foreach ($x in $InputObject) { $arr += ,(ConvertTo-OrderedHashtableSafe $x) }
        return $arr
    }

    return $InputObject
}

function Get-ComparableHostItemString {
    <#
    .SYNOPSIS
        Produces a stable compact string representation of a HostItem for comparison.

    .PARAMETER Item
        HostItem to compare.

    .PARAMETER IgnoreMetadataKeys
        Metadata keys to remove before comparison.
    #>
    param(
        [object]$Item,
        [string[]]$IgnoreMetadataKeys = @()
    )

    # Clone metadata safely and remove ignore keys
    $meta = ConvertTo-HashtableSafe $Item.Metadata
    foreach ($ik in $IgnoreMetadataKeys) {
        if ($meta.ContainsKey($ik)) { $null = $meta.Remove($ik) }
    }

    $snap = [ordered]@{
        Key      = $Item.Key
        Category = $Item.Category
        Identity = [ordered]@{
            Path        = $Item.Identity.Path
            CommandLine = $Item.Identity.CommandLine
            Sha256      = $Item.Identity.Sha256
        }
        Signature = [ordered]@{
            Status         = $Item.Signature.Status
            Signer         = $Item.Signature.Signer
            Thumbprint     = $Item.Signature.Thumbprint
            IsMicrosoft    = $Item.Signature.IsMicrosoft
            IsSysinternals = $Item.Signature.IsSysinternals
            IsUserWritable = $Item.Signature.IsUserWritable
        }
        Metadata = (ConvertTo-OrderedHashtableSafe $meta)
    }

    return ($snap | ConvertTo-Json -Depth 16 -Compress)
}


function Compare-HostCategory {
    param(
        [string]$Category,
        [object[]]$Baseline,
        [object[]]$Current,
        [string[]]$IgnoreMetadataKeys = @()
    )

    $b = @{}
    $c = @{}
    $collisions = @()

    foreach ($x in $Baseline) {
        $key = $null
        if ($x) {
            try {
                if ($x -is [hashtable]) { $key = $x['Key'] }
                elseif ($x.PSObject.Properties['Key']) { $key = $x.PSObject.Properties['Key'].Value }
            } catch { }
        }
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        if ($b.ContainsKey($key)) { $collisions += "Baseline:$key"; continue }
        $b[$key] = $x
    }
    foreach ($x in $Current) {
        $key = $null
        if ($x) {
            try {
                if ($x -is [hashtable]) { $key = $x['Key'] }
                elseif ($x.PSObject.Properties['Key']) { $key = $x.PSObject.Properties['Key'].Value }
            } catch { }
        }
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        if ($c.ContainsKey($key)) { $collisions += "Current:$key"; continue }
        $c[$key] = $x
    }

    $added=@(); $removed=@(); $changed=@()

    foreach ($k in $c.Keys) {
        if (-not $b.ContainsKey($k)) { $added += $c[$k]; continue }

        $bObj = $b[$k]
        $cObj = $c[$k]

        $bStr = Get-ComparableHostItemString -Item $bObj -IgnoreMetadataKeys $IgnoreMetadataKeys
        $cStr = Get-ComparableHostItemString -Item $cObj -IgnoreMetadataKeys $IgnoreMetadataKeys

        if ($bStr -ne $cStr) {
            # Provide normalized forms for stable output, but do not require JSON stringify for comparison again.
            $bNorm = $bObj.PSObject.Copy()
            $cNorm = $cObj.PSObject.Copy()
            $bNorm.Metadata = (ConvertTo-HashtableSafe $bNorm.Metadata)
            $cNorm.Metadata = (ConvertTo-HashtableSafe $cNorm.Metadata)
            foreach ($ik in $IgnoreMetadataKeys) {
                if ($bNorm.Metadata.ContainsKey($ik)) { $null = $bNorm.Metadata.Remove($ik) }
                if ($cNorm.Metadata.ContainsKey($ik)) { $null = $cNorm.Metadata.Remove($ik) }
            }

            $changed += [pscustomobject]@{ Key=$k; Baseline=$bNorm; Current=$cNorm }
        }
    }

    foreach ($k in $b.Keys) { if (-not $c.ContainsKey($k)) { $removed += $b[$k] } }

    return [pscustomobject]@{
        Category   = $Category
        Added      = $added
        Removed    = $removed
        Changed    = $changed
        Collisions = $collisions
    }
}


function Score-HostItem {
    # Accept normalized hashtable OR PSCustomObject
    param([object]$Item)

    if (-not $Item) { return 0 }

    $ht = ConvertTo-HashtableSafe $Item
    $id = $ht['Identity']
    $sig = $ht['Signature']
    $meta = $ht['Metadata']

    $idHt   = ConvertTo-HashtableSafe $id
    $sigHt  = ConvertTo-HashtableSafe $sig
    $metaHt = ConvertTo-HashtableSafe $meta

    $path = [string]$idHt['Path']
    $cmd  = [string]$idHt['CommandLine']

    $metaText = if ($metaHt.Count -gt 0) { ($metaHt.Values -join ' ') } else { '' }
    $x = (@($path,$cmd,$metaText) -join ' ').ToLower()

    $s = 0    # User-writable indicators (heuristic). If signature already provides IsUserWritable, prefer that.
    if (-not $sigHt.ContainsKey('IsUserWritable')) {
        if ($x -match '\\appdata\\|\\temp\\|\\windows\\temp\\|\\downloads\\|\\programdata\\|\\users\\public\\|\\perflogs\\|\\onedrive\\') { $s += 2 }
    }
    # LoLBins
    if ($x -match '\b(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|installutil|msiexec|wmic|schtasks|reg|bitsadmin|certutil)(\.exe)?\b') { $s += 3 }

    # Argument-level abuse signals
    if ($x -match '-enc\b|-encodedcommand\b|frombase64string|iex\b|invoke-expression|downloadstring|\biwr\b|invoke-webrequest|\bcurl\b|\bwget\b') { $s += 3 }
    if ($x -match 'http://|https://') { $s += 2 }

    $status = [string]$sigHt['Status']
    $isSysinternals = [bool]$sigHt['IsSysinternals']
    $isUserWritable = [bool]$sigHt['IsUserWritable']

    if ($status -and $status -match 'NotSigned|UnknownError|HashMismatch|NotTrusted') { $s += 3 }
    if ($status -eq 'Missing') { $s += 2 }

    if ($path -and ($path.ToLower() -match '\\windows\\(system32|syswow64)\\') -and ($status -and $status -match 'NotSigned|UnknownError|HashMismatch|NotTrusted')) {
        $s += 2
    }

    if ($isSysinternals) { $s += 4 }
    if ($isSysinternals -and $isUserWritable) { $s += 10 }

    return $s
}

Export-ModuleMember -Function *
