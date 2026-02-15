using module .\WinHostBaselineCore.psm1

# WinHostBaseline.Collectors.psm1
Set-StrictMode -Version Latest
Import-Module "$PSScriptRoot\WinHostBaselineCore.psm1" -ErrorAction Stop

function Write-CollectorItemDebug {
    param([string]$CollectorName, [string]$Message)
    if ($env:WinHostBaselineCollectorDebug -eq '1' -and $Message) {
        Write-Host "  [Skip $CollectorName] $Message" -ForegroundColor DarkYellow
    }
}

function Resolve-DllPath {
    param([string]$NameOrPath)

    if ([string]::IsNullOrWhiteSpace($NameOrPath)) { return $null }

    $raw = $NameOrPath.Trim().Trim('"')
    $p = Normalize-PathSafe $raw

    if ($p -and ($p -match '\\')) {
        if (Test-Path -LiteralPath $p) { return $p }
        $rawName = [System.IO.Path]::GetFileName($p)
        if ($rawName) { $raw = $rawName }
    }

    $name = $raw
    if (-not $name.ToLower().EndsWith('.dll')) { $name = "$name.dll" }

    $candidates = @(
        (Join-Path $env:SystemRoot "System32\$name"),
        (Join-Path $env:SystemRoot "SysWOW64\$name"),
        (Join-Path $env:SystemRoot $name)
    )

    foreach ($c in $candidates) {
        try {
            if (Test-Path -LiteralPath $c) { return (Get-Item -LiteralPath $c).FullName }
        } catch {}
    }

    return Normalize-PathSafe $raw
}

function Get-ServicesHostItems {
    Get-CimInstance Win32_Service | ForEach-Object {
        $exe = Extract-ExePath $_.PathName
        $pathName = ''; $state = ''; $startName = ''
        try { $pathName = [string]$_.PathName } catch { }
        try { $state = [string]$_.State } catch { }
        try { $startName = [string]$_.StartName } catch { }
        New-HostItem @{
            Key      = "Service:$($_.Name)"
            Category = 'Services'
            Identity = New-HostIdentity @{
                Path        = $exe
                CommandLine = $pathName
                Sha256      = Get-FileHashSafe $exe
            }
            Signature = Get-SignatureSafe $exe
            Metadata  = @{
                Name        = $_.Name
                DisplayName = $_.DisplayName
                State       = $state
                PathName    = $pathName
                StartName   = $startName
                StartMode   = $_.StartMode
                ServiceType = $_.ServiceType
            }
        }
    }
}

function Get-DriversHostItems {
    Get-CimInstance Win32_SystemDriver | ForEach-Object {
        $exe = Extract-ExePath $_.PathName
        $vendor = ''
        if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
            try {
                $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
                if ($vi -and $vi.CompanyName) { $vendor = $vi.CompanyName.Trim() }
            } catch { }
        }
        $disp = ''; $desc = ''
        if ($_.PSObject.Properties['DisplayName']) { try { $disp = [string]$_.DisplayName } catch { } }
        if ($_.PSObject.Properties['Description']) { try { $desc = [string]$_.Description } catch { } }
        New-HostItem @{
            Key      = "Driver:$($_.Name)"
            Category = 'Drivers'
            Identity = New-HostIdentity @{
                Path        = $exe
                CommandLine = $_.PathName
                Sha256      = Get-FileHashSafe $exe
            }
            Signature = Get-SignatureSafe $exe
            Metadata  = @{
                Name        = $_.Name
                DisplayName = $disp
                Description = $desc
                Vendor      = $vendor
                State       = $_.State
                StartMode   = $_.StartMode
                ServiceType = $_.ServiceType
            }
        }
    }
}

function Get-ProcessesHostItems {
    <#
    .SYNOPSIS
        Collect running processes. Keys are stable and collision-resistant.

    .NOTES
        Key is based on Name + normalized executable path + SHA256(CommandLine).
        Multiple instances with the same Name/Path/CommandLine are aggregated into one item.
    #>

    $items = @()

    # Local helper: SHA256 hash of a string (PowerShell 5.1 compatible)
    function Get-StringSha256 {
        param([string]$InputString)
        if ($null -eq $InputString) { return '<null>' }
        $s = $InputString.Trim()
        if ($s.Length -eq 0) { return '<empty>' }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($s)
            $hash  = $sha.ComputeHash($bytes)
            return -join ($hash | ForEach-Object { $_.ToString('x2') })
        } finally {
            if ($sha) { $sha.Dispose() }
        }
    }

    $groups = @{}

    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $p = $_
            $path = Normalize-PathSafe $p.ExecutablePath
            $keyPath = if ($path) { $path } else { '<noimage>' }
            $cmd = [string]$p.CommandLine
            $cmdHash = Get-StringSha256 $cmd
            $key = "Process:$($p.Name)|$keyPath|$cmdHash"
            if (-not $groups.ContainsKey($key)) { $groups[$key] = @() }
            $groups[$key] += $p
        } catch { Write-CollectorItemDebug 'Processes' $_.Exception.Message }
    }

    foreach ($k in $groups.Keys) {
        try {
            $plist = @($groups[$k])
            $plistLen = @($plist).Count
            if ($plistLen -lt 1) { continue }

            $first = $plist[0]
            $path = Normalize-PathSafe $first.ExecutablePath
            $cmd  = [string]$first.CommandLine
            $cmdHash = Get-StringSha256 $cmd

            $pids = @($plist | ForEach-Object { [int]$_.ProcessId } | Sort-Object -Unique)
            $ppids = @($plist | ForEach-Object { [int]$_.ParentProcessId } | Sort-Object -Unique)
            $pidsCount = @($pids).Count

            $items += New-HostItem @{
                Key      = $k
                Category = 'Processes'
                Identity = New-HostIdentity @{
                    Path        = $path
                    CommandLine = $cmd
                    Sha256      = Get-FileHashSafe $path
                }
                Signature = Get-SignatureSafe $path
                Metadata  = @{
                    Name            = $first.Name
                    CommandLineHash = $cmdHash
                    ProcessIds      = $pids
                    ParentProcessIds= $ppids
                    Count           = $pidsCount
                }
            }
        } catch { Write-CollectorItemDebug 'Processes' $_.Exception.Message }
    }

    $items
}


function Get-ScheduledTasksHostItems {
    $items = @()
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $tinfo   = $_ | Get-ScheduledTaskInfo -ErrorAction Stop
            if (-not $tinfo) { return }
            $actions = @()

            foreach ($a in $_.Actions) {
                $exec = ''
                if ($a.PSObject.Properties['Execute']) { try { $exec = Normalize-PathSafe $a.Execute } catch { } }
                $exe  = Extract-ExePath $exec
                $argsVal = ''; if ($a.PSObject.Properties['Arguments']) { try { $argsVal = $a.Arguments } catch { } }
                $workDir = ''; if ($a.PSObject.Properties['WorkingDirectory']) { try { $workDir = $a.WorkingDirectory } catch { } }
                $actions += @{
                    Type       = $a.GetType().Name
                    Execute    = $exec
                    Arguments  = $argsVal
                    WorkingDir = $workDir
                    ExePath    = $exe
                    Signature  = Get-SignatureSafe $exe
                }
            }

            $primary = $actions | Where-Object { $_.ExePath -and (Test-Path -LiteralPath $_.ExePath) } | Select-Object -First 1
            $primaryPath = if ($primary) { $primary.ExePath } else { '' }
            $primaryCmd  = if ($primary) {
                if ($primary.Arguments) { "$($primary.ExePath) $($primary.Arguments)" } else { "$($primary.ExePath)" }
            } else { '' }

            $stateStr = 'Unknown'
            if ($tinfo.PSObject.Properties['State']) { try { $stateStr = $tinfo.State.ToString() } catch { } }
            $principalId = ''; if ($_.Principal) { try { $principalId = $_.Principal.UserId } catch { } }
            $runLevelStr = ''; if ($_.Principal) { try { $runLevelStr = $_.Principal.RunLevel.ToString() } catch { } }
            $lastRun = $null; if ($tinfo.PSObject.Properties['LastRunTime']) { try { $lastRun = $tinfo.LastRunTime } catch { } }
            $nextRun = $null; if ($tinfo.PSObject.Properties['NextRunTime']) { try { $nextRun = $tinfo.NextRunTime } catch { } }
            $author = ''; if ($_.PSObject.Properties['Author']) { try { $author = $_.Author } catch { } }
            $desc = ''; if ($_.PSObject.Properties['Description']) { try { $desc = $_.Description } catch { } }
            $items += New-HostItem @{
                Key      = "Task:$($_.TaskPath)|$($_.TaskName)"
                Category = 'ScheduledTasks'
                Identity = New-HostIdentity @{
                    Path        = $primaryPath
                    CommandLine = $primaryCmd
                    Sha256      = Get-FileHashSafe $primaryPath
                }
                Signature = Get-SignatureSafe $primaryPath
                Metadata  = @{
                    TaskName    = $_.TaskName
                    TaskPath    = $_.TaskPath
                    State       = $stateStr
                    LastRunTime = $lastRun
                    NextRunTime = $nextRun
                    Author      = $author
                    Description = $desc
                    Principal   = $principalId
                    RunLevel    = $runLevelStr
                    Actions     = $actions
                }
            }
        } catch { Write-CollectorItemDebug 'Tasks' $_.Exception.Message }
    }
    $items
}

function Get-StartupHostItems {
    <#
    .SYNOPSIS
        Collect common startup persistence locations (Run/RunOnce + Startup folders).

    .PARAMETER AllProfiles
        Opt-in. If set, attempts to scan Run/RunOnce for ALL local user profiles by loading user hives.
        Default behavior scans HKLM plus HKCU and any currently LOADED user hives under HKEY_USERS.

        NOTE: Loading user hives requires administrative rights and may fail for locked profiles.
    #>
    param(
        [switch]$AllProfiles
    )

    $items = [System.Collections.ArrayList]::new()

    function Add-RunKeyItems {
        param(
            [System.Collections.ArrayList]$ItemList,
            [string]$RunKeyPath,
            [string]$Sid = '',
            [string]$HiveSource = ''
        )
        if (-not $ItemList) { return }

        try { $props = Get-ItemProperty -Path $RunKeyPath -ErrorAction Stop } catch { return }

        foreach ($p in $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
            try {
                $val = [string]$p.Value
                if ([string]::IsNullOrWhiteSpace($val)) { continue }

                $exe = Extract-ExePath $val
                $null = $ItemList.Add((New-HostItem @{
                    Key      = "Startup:REG:$RunKeyPath\$($p.Name)"
                    Category = 'Startup'
                    Identity = New-HostIdentity @{
                        Path        = $exe
                        CommandLine = $val
                        Sha256      = Get-FileHashSafe $exe
                    }
                    Signature = Get-SignatureSafe $exe
                    Metadata  = @{
                        Source        = 'Registry'
                        RegistryPath  = $RunKeyPath
                        ValueName     = $p.Name
                        CollectedFromSid = $Sid
                        HiveSource    = $HiveSource
                    }
                }))
            } catch { Write-CollectorItemDebug 'Startup' $_.Exception.Message }
        }
    }

    # 1) HKLM Run keys
    $hklmKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($rk in $hklmKeys) { Add-RunKeyItems -ItemList $items -RunKeyPath $rk -HiveSource 'HKLM' }

    # 2) Current token HKCU (note: elevated HKCU refers to the elevated identity)
    $hkcuKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $curSid = ''
    try { $curSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { $curSid = '' }
    foreach ($rk in $hkcuKeys) { Add-RunKeyItems -ItemList $items -RunKeyPath $rk -Sid $curSid -HiveSource 'HKCU' }

    # 3) Scan currently LOADED user hives under HKU (covers other logged-on users)
    try {
        $loadedSids = Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'HKEY_USERS\\S-1-5-21-' } |
            ForEach-Object { $_.PSChildName } | Sort-Object -Unique

        foreach ($sid in $loadedSids) {
            foreach ($sub in @(
                "Software\Microsoft\Windows\CurrentVersion\Run",
                "Software\Microsoft\Windows\CurrentVersion\RunOnce"
            )) {
                $rk = "Registry::HKEY_USERS\$sid\$sub"
                Add-RunKeyItems -ItemList $items -RunKeyPath $rk -Sid $sid -HiveSource 'HKU(loaded)'
            }
        }
    } catch { Write-CollectorItemDebug 'Startup' $_.Exception.Message }

    # 4) Optional: scan ALL local profiles by loading NTUSER.DAT (admin required)
    if ($AllProfiles) {
        try {
            $profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalPath -and $_.SID -and (-not $_.Special) }

            foreach ($prof in $profiles) {
                $sid = [string]$prof.SID
                if ([string]::IsNullOrWhiteSpace($sid)) { continue }

                $hkuPath = "Registry::HKEY_USERS\$sid"
                $isLoaded = $false
                try { $isLoaded = Test-Path $hkuPath } catch { $isLoaded = $false }

                $didLoad = $false
                if (-not $isLoaded) {
                    $ntuser = Join-Path $prof.LocalPath "NTUSER.DAT"
                    if (Test-Path -LiteralPath $ntuser) {
                        # reg.exe is used for compatibility and simplicity in PS 5.1
                        $null = & reg.exe load "HKU\$sid" "$ntuser" 2>$null
                        $didLoad = $true
                    } else {
                        continue
                    }
                }

                try {
                    foreach ($sub in @(
                        "Software\Microsoft\Windows\CurrentVersion\Run",
                        "Software\Microsoft\Windows\CurrentVersion\RunOnce"
                    )) {
                        $rk = "Registry::HKEY_USERS\$sid\$sub"
                        Add-RunKeyItems -ItemList $items -RunKeyPath $rk -Sid $sid -HiveSource 'HKU(loaded-via-AllProfiles)'
                    }
                } finally {
                    if ($didLoad) {
                        $null = & reg.exe unload "HKU\$sid" 2>$null
                    }
                }
            }
        } catch { Write-CollectorItemDebug 'Startup' $_.Exception.Message }
    }

    # 5) Startup folders (existing behavior)
    $startupFolders = @(
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\StartUp"),
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup")
    )

    foreach ($sf in $startupFolders) {
        if (-not (Test-Path $sf)) { continue }
        Get-ChildItem $sf -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $null = $items.Add((New-HostItem @{
                    Key      = "Startup:Folder:$sf\$($_.Name)"
                    Category = 'Startup'
                    Identity = New-HostIdentity @{
                        Path        = $_.FullName
                        CommandLine = $_.FullName
                        Sha256      = Get-FileHashSafe $_.FullName
                    }
                    Signature = Get-SignatureSafe $_.FullName
                    Metadata  = @{
                        Source   = 'StartupFolder'
                        Location = $sf
                        Name     = $_.Name
                    }
                }))
            } catch { Write-CollectorItemDebug 'Startup' $_.Exception.Message }
        }
    }

    $items
}


function Get-NetworkSocketsHostItems {
    param([switch]$IncludeRemoteSockets)

    $procs = @{}
    Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }

    $items = @()

    Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            if (-not $IncludeRemoteSockets) {
                if ($_.State.ToString() -ne 'Listen') { return }
            }

            $procId = [int]$_.OwningProcess
            $p   = $procs[$procId]
            $img = if ($p) { Normalize-PathSafe $p.ExecutablePath } else { $null }
            $exeKey = if ($img) { $img } else { '<noimage>' }

            $key =
                if ($IncludeRemoteSockets) {
                    "TCP:$($_.LocalAddress):$($_.LocalPort)->$($_.RemoteAddress):$($_.RemotePort)|$exeKey"
                } else {
                    "TCP-LISTEN:$($_.LocalAddress):$($_.LocalPort)|$exeKey"
                }

            $items += New-HostItem @{
                Key      = $key
                Category = 'NetworkSockets'
                Identity = New-HostIdentity @{
                    Path        = $img
                    CommandLine = if ($p) { $p.CommandLine } else { '' }
                    Sha256      = Get-FileHashSafe $img
                }
                Signature = Get-SignatureSafe $img
                Metadata  = @{
                    Protocol    = 'TCP'
                    Local       = "$($_.LocalAddress):$($_.LocalPort)"
                    Remote      = if ($IncludeRemoteSockets) { "$($_.RemoteAddress):$($_.RemotePort)" } else { '' }
                    State       = $_.State.ToString()
                    ProcessId   = $procId
                    ProcessName = if ($p) { $p.Name } else { '' }
                }
            }
        } catch {
            # Skip this socket so one bad path doesn't stop the whole collector
        }
    }

    Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $procId = [int]$_.OwningProcess
            $p   = $procs[$procId]
            $img = if ($p) { Normalize-PathSafe $p.ExecutablePath } else { $null }
            $exeKey = if ($img) { $img } else { '<noimage>' }

            $items += New-HostItem @{
                Key      = "UDP:$($_.LocalAddress):$($_.LocalPort)|$exeKey"
                Category = 'NetworkSockets'
                Identity = New-HostIdentity @{
                    Path        = $img
                    CommandLine = if ($p) { $p.CommandLine } else { '' }
                    Sha256      = Get-FileHashSafe $img
                }
                Signature = Get-SignatureSafe $img
                Metadata  = @{
                    Protocol    = 'UDP'
                    Local       = "$($_.LocalAddress):$($_.LocalPort)"
                    Remote      = ''
                    State       = ''
                    ProcessId   = $procId
                    ProcessName = if ($p) { $p.Name } else { '' }
                }
            }
        } catch {
            # Skip this endpoint so one bad path doesn't stop the whole collector
        }
    }

    $items
}

function Get-WmiPersistenceHostItems {
    $ns = "root\subscription"
    $items = @()

    Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
        $items += New-HostItem @{
            Key      = "WMI.Filter:$($_.Name)"
            Category = 'WMI.Filter'
            Identity = New-HostIdentity @{ Path=''; CommandLine=''; Sha256='' }
            Signature = New-HostSignature @{
                Status='N/A';Signer='';Thumbprint='';
                IsMicrosoft=$false;IsSysinternals=$false;IsUserWritable=$false
            }
            Metadata  = @{
                Name           = $_.Name
                Query          = $_.Query
                QueryLanguage  = $_.QueryLanguage
                EventNamespace = $_.EventNamespace
            }
        }
    }

    Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
        $cmd = $_.CommandLineTemplate
        $exe = Extract-ExePath $cmd
        $items += New-HostItem @{
            Key      = "WMI.Consumer:$($_.Name)"
            Category = 'WMI.Consumer'
            Identity = New-HostIdentity @{
                Path        = $exe
                CommandLine = $cmd
                Sha256      = Get-FileHashSafe $exe
            }
            Signature = Get-SignatureSafe $exe
            Metadata  = @{ Name = $_.Name }
        }
    }

    
    # ActiveScriptEventConsumer (common fileless persistence)
    Get-CimInstance -Namespace $ns -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
        $scriptText = [string]$_.ScriptText
        $engine = [string]$_.ScriptingEngine

        $items += New-HostItem @{
            Key      = "WMI.Consumer.ActiveScript:$($_.Name)"
            Category = 'WMI.Consumer.ActiveScript'
            Identity = New-HostIdentity @{ Path=''; CommandLine=''; Sha256='' }
            Signature = New-HostSignature @{
                Status='N/A';Signer='';Thumbprint='';
                IsMicrosoft=$false;IsSysinternals=$false;IsUserWritable=$false
            }
            Metadata  = @{
                Name           = $_.Name
                ScriptingEngine= $engine
                ScriptText     = $scriptText
            }
        }
    }

Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
        $items += New-HostItem @{
            Key      = "WMI.Binding:$($_.Filter)->$($_.Consumer)"
            Category = 'WMI.Binding'
            Identity = New-HostIdentity @{ Path=''; CommandLine=''; Sha256='' }
            Signature = New-HostSignature @{
                Status='N/A';Signer='';Thumbprint='';
                IsMicrosoft=$false;IsSysinternals=$false;IsUserWritable=$false
            }
            Metadata  = @{
                Filter   = $_.Filter.ToString()
                Consumer = $_.Consumer.ToString()
            }
        }
    }

    $items
}

function Get-COMHostItems {
    $items = @()

    $roots = @(
        "HKCR:\CLSID",
        "HKCU:\Software\Classes\CLSID"
    )

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }

        Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
            $clsid = $_.PSChildName
            $inproc = Join-Path $_.PSPath "InprocServer32"
            $local  = Join-Path $_.PSPath "LocalServer32"

            foreach ($pathKey in @($inproc, $local)) {
                if (-not (Test-Path $pathKey)) { continue }

                try { $val = (Get-ItemProperty -Path $pathKey -ErrorAction Stop)."(default)" }
                catch { continue }

                $exe = Extract-ExePath $val
                $exeKey = if ($exe) { $exe } else { '<noexe>' }

                $items += New-HostItem @{
                    Key      = "COM:$clsid"
                    Category = 'COM'
                    Identity = New-HostIdentity @{
                        Path        = $exe
                        CommandLine = $val
                        Sha256      = Get-FileHashSafe $exe
                    }
                    Signature = Get-SignatureSafe $exe
                    Metadata  = @{
                        CLSID      = $clsid
                        Registry   = $pathKey
                        RawValue   = $val
                        Type       = if ($pathKey -like '*Inproc*') { 'InprocServer32' } else { 'LocalServer32' }
                    }
                }
            }
        }
    }

    $items
}

function Get-LSAHostItems {
    $items = @()
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    try { $props = Get-ItemProperty -Path $key -ErrorAction Stop }
    catch { return @() }

    foreach ($field in @("Authentication Packages","Security Packages","Notification Packages")) {
        $vals = $props.$field
        if (-not $vals) { continue }

        foreach ($dll in $vals) {
            $resolved = Resolve-DllPath $dll

            $items += New-HostItem @{
                Key      = "LSA:$field|$dll"
                Category = 'LSA'
                Identity = New-HostIdentity @{
                    Path        = $resolved
                    CommandLine = [string]$dll
                    Sha256      = Get-FileHashSafe $resolved
                }
                Signature = Get-SignatureSafe $resolved
                Metadata  = @{
                    Field        = $field
                    Raw          = [string]$dll
                    ResolvedPath = $resolved
                }
            }
        }
    }

    $items
}

function Get-WinsockHostItems {
    $items = @()

    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9"
    if (-not (Test-Path $key)) { return @() }

    try { $entries = Get-ItemProperty -Path $key -ErrorAction Stop }
    catch { return @() }

    if (-not $entries.Catalog_Entries) { return @() }

    foreach ($entry in $entries.Catalog_Entries) {
        try {
            if (-not $entry) { continue }
            if (-not ($entry.PSObject.Properties.Name -contains 'LibraryPath')) { continue }

            $dll = [string]$entry.LibraryPath
            if ([string]::IsNullOrWhiteSpace($dll)) { continue }

            $exe = Normalize-PathSafe $dll

            $items += New-HostItem @{
                Key      = "Winsock:$dll"
                Category = 'Winsock'
                Identity = New-HostIdentity @{
                    Path        = $exe
                    CommandLine = $dll
                    Sha256      = Get-FileHashSafe $exe
                }
                Signature = Get-SignatureSafe $exe
                Metadata  = @{
                    EntryId     = $entry.CatalogEntryId
                    DisplayName = $entry.DisplayString
                }
            }
        } catch {
            continue
        }
    }

    $items
}

function Get-BrowserExtensionsHostItems {
    <#
    .SYNOPSIS
        Enumerate browser extensions.

    .DESCRIPTION
        By default, enumerates Chrome and Edge extensions across ALL Chromium profiles
        under each browser's "User Data" directory (e.g., Default, Profile 1, Profile 2).

    .PARAMETER Firefox
        Opt-in. If set, also enumerates Firefox profiles/extensions.

    .NOTES
        For Chromium extensions, the Identity.Path points to manifest.json (when present) for hashing.
    #>
    param(
        [switch]$Firefox
    )

    $items = [System.Collections.ArrayList]@()

    function Get-ExtensionManifestInfo {
        param([string]$ManifestPath)
        if (-not (Test-Path -LiteralPath $ManifestPath)) { return @{ Name = ''; Author = '' } }
        try {
            $json = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $name = ''
            if ($json.name) {
                if ($json.name -is [string]) { $name = $json.name }
                elseif ($json.name.PSObject.Properties['default']) { $name = $json.name.'default' }
            }
            $author = ''
            if ($json.author) { $author = [string]$json.author }
            elseif ($json.developer -and $json.developer.name) { $author = [string]$json.developer.name }
            return @{ Name = $name; Author = $author }
        } catch { return @{ Name = ''; Author = '' } }
    }

    function Add-ChromiumExtensions {
        param(
            [string]$BrowserName,
            [string]$UserDataRoot,
            [string]$UserLabel = ''
        )

        if (-not (Test-Path -LiteralPath $UserDataRoot)) { return }

        $profiles = Get-ChildItem -LiteralPath $UserDataRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' -or $_.Name -like 'Guest Profile' }

        foreach ($prof in $profiles) {
            $extRoot = Join-Path $prof.FullName "Extensions"
            if (-not (Test-Path -LiteralPath $extRoot)) { continue }

            Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $extId = $_.Name

                    # Versions are subfolders of extension id (e.g. 25.5.4.2_0); strip suffix for [version] parse
                    $versionFolders = @(Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue)
                    $verDirs = $versionFolders | Sort-Object { try { $v = [version]($_.Name -replace '_.*$',''); $v } catch { [version]'0.0.0.0' } } -Descending
                    $latestVer = ''
                    if ($verDirs) {
                        $first = $verDirs | Select-Object -First 1
                        if ($first) { $latestVer = $first.Name }
                    }
                    $manifestPath = $null
                    if ($latestVer) {
                        $mp = Join-Path (Join-Path $_.FullName $latestVer) "manifest.json"
                        if (Test-Path -LiteralPath $mp) { $manifestPath = $mp }
                    }

                    $key = "Browser:$BrowserName|Profile:$($prof.Name)|Ext:$extId"
                    if ($UserLabel) { $key = "Browser:$BrowserName|User:$UserLabel|Profile:$($prof.Name)|Ext:$extId" }
                    if ($latestVer) { $key = "$key|Ver:$latestVer" }

                    if ($manifestPath) { $hashTarget = $manifestPath } else { $hashTarget = $_.FullName }
                    if ($manifestPath) { $sig = Get-SignatureSafe $hashTarget } else { $sig = New-HostSignature @{ Status='N/A';Signer='';Thumbprint='';IsMicrosoft=$false;IsSysinternals=$false;IsUserWritable=(Is-UserWritablePath $hashTarget) } }
                    $manifestInfo = if ($manifestPath) { Get-ExtensionManifestInfo $manifestPath } else { @{ Name = ''; Author = '' } }
                    [void]$items.Add((New-HostItem @{
                        Key      = $key
                        Category = 'Browser'
                        Identity = New-HostIdentity @{
                            Path        = $hashTarget
                            CommandLine = ''
                            Sha256      = Get-FileHashSafe $hashTarget
                        }
                        Signature = $sig
                        Metadata  = @{
                            Browser       = $BrowserName
                            Profile       = $prof.Name
                            ExtensionId   = $extId
                            ExtensionName = $manifestInfo.Name
                            Author        = $manifestInfo.Author
                            LatestVersion = $latestVer
                            Versions      = @($verDirs | ForEach-Object { $_.Name })
                            Manifest      = $manifestPath
                            Root          = $_.FullName
                        }
                    }))
                } catch { Write-CollectorItemDebug 'Browser' $_.Exception.Message }
            }
        }
    }

    # 1) Current user (same as Scan-BrowserExtensions.ps1)
    $chromeUserData = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data"
    $edgeUserData   = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data"
    Add-ChromiumExtensions -BrowserName 'Chrome' -UserDataRoot $chromeUserData
    Add-ChromiumExtensions -BrowserName 'Edge'   -UserDataRoot $edgeUserData

    # 2) All other user profiles under C:\Users (same flow as Scan-BrowserExtensions.ps1)
    $usersDir = Join-Path $env:SystemDrive "\Users"
    $currentProcessUser = $env:USERNAME
    if (Test-Path -LiteralPath $usersDir) {
        Get-ChildItem -LiteralPath $usersDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $userName = $_.Name
            if ($userName -in @('Public','Default','Default User','All Users')) { return }
            if ($userName -eq $currentProcessUser) { return }
            Write-CollectorItemDebug 'Browser' ("Scanning user profile: $userName")
            $userChrome = Join-Path $_.FullName "AppData\Local\Google\Chrome\User Data"
            $userEdge   = Join-Path $_.FullName "AppData\Local\Microsoft\Edge\User Data"
            try {
                if (Test-Path -LiteralPath $userChrome) { Add-ChromiumExtensions -BrowserName 'Chrome' -UserDataRoot $userChrome -UserLabel $userName }
                if (Test-Path -LiteralPath $userEdge)   { Add-ChromiumExtensions -BrowserName 'Edge'   -UserDataRoot $userEdge   -UserLabel $userName }
            } catch { Write-CollectorItemDebug 'Browser' ("User " + $userName + ": " + $_.Exception.Message) }
        }
    }

    if ($Firefox) {
        <#
            Firefox enumeration (opt-in):
            - Parses extensions.json per profile to list installed add-ons.
            - Attempts to locate the backing XPI on disk for per-addon hashing.
        #>
        $ffProfiles = Join-Path $env:APPDATA "Mozilla\Firefox\Profiles"
        if (Test-Path -LiteralPath $ffProfiles) {
            Get-ChildItem -LiteralPath $ffProfiles -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $prof = $_
                    $extJson = Join-Path $prof.FullName "extensions.json"

                    if (-not (Test-Path -LiteralPath $extJson)) {
                        return
                    }

                    $jsonObj = $null
                    try {
                        $jsonObj = (Get-Content -LiteralPath $extJson -Raw -ErrorAction Stop) | ConvertFrom-Json -ErrorAction Stop
                    } catch {
                        # Fall back to a profile integrity item if parsing fails
                        [void]$items.Add((New-HostItem @{
                            Key      = "Browser:Firefox|Profile:$($prof.Name)|ExtensionsJson"
                            Category = 'Browser'
                            Identity = New-HostIdentity @{
                                Path        = $extJson
                                CommandLine = ''
                                Sha256      = Get-FileHashSafe $extJson
                            }
                            Signature = Get-SignatureSafe $extJson
                            Metadata  = @{
                                Browser = 'Firefox'
                                Profile = $prof.Name
                                ExtensionsJson = $extJson
                                Root    = $prof.FullName
                                ParseError = $true
                            }
                        }))
                        return
                    }

                    $addons = @()
                    try { $addons = @($jsonObj.addons) } catch { $addons = @() }

                    foreach ($a in $addons) {
                        try {
                            if (-not $a) { continue }
                            $id = $a.id
                            if ([string]::IsNullOrWhiteSpace($id)) { continue }

                            $name = $a.defaultLocale.name
                            $ver  = $a.version
                            $type = $a.type

                            # Try to locate backing XPI (best-effort)
                            $xpi = $null
                            if ($a.path -and (Test-Path -LiteralPath $a.path)) {
                                $xpi = $a.path
                            } else {
                                $cand1 = Join-Path (Join-Path $prof.FullName "extensions") ($id + ".xpi")
                                $cand2 = Join-Path (Join-Path $prof.FullName "extensions") $id
                                if (Test-Path -LiteralPath $cand1) { $xpi = $cand1 }
                                elseif (Test-Path -LiteralPath $cand2) { $xpi = $cand2 }
                            }

                            $key = "Browser:Firefox|Profile:$($prof.Name)|Addon:$id"
                            if ($ver) { $key = "$key|Ver:$ver" }

                            if ($xpi) { $hashTarget = $xpi } else { $hashTarget = $extJson }
                            if ($xpi) { $addonSig = Get-SignatureSafe $hashTarget } else { $addonSig = Get-SignatureSafe $extJson }
                            [void]$items.Add((New-HostItem @{
                                Key      = $key
                                Category = 'Browser'
                                Identity = New-HostIdentity @{
                                    Path        = $hashTarget
                                    CommandLine = ''
                                    Sha256      = Get-FileHashSafe $hashTarget
                                }
                                Signature = $addonSig
                                Metadata  = @{
                                    Browser = 'Firefox'
                                    Profile = $prof.Name
                                    ExtensionId = $id
                                    Name    = $name
                                    Version = $ver
                                    Type    = $type
                                    Active  = $a.active
                                    AppDisabled = $a.appDisabled
                                    UserDisabled = $a.userDisabled
                                    SignedState = $a.signedState
                                    SourceUri = $a.sourceURI
                                    Root    = $prof.FullName
                                    ExtensionsJson = $extJson
                                    Artifact = $xpi
                                }
                            }))
                        } catch { Write-CollectorItemDebug 'Browser' $_.Exception.Message }
                    }
                } catch { Write-CollectorItemDebug 'Browser' $_.Exception.Message }
            }
        }
    }

    $items
}


function Get-ETWHostItems {
    $items = @()
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers"
    if (-not (Test-Path $key)) { return @() }

    Get-ChildItem $key -ErrorAction SilentlyContinue | ForEach-Object {
        $guid = $_.PSChildName
        $dll  = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ResourceFileName
        $exe  = Normalize-PathSafe $dll

        $items += New-HostItem @{
            Key      = "ETW:$guid"
            Category = 'ETW'
            Identity = New-HostIdentity @{
                Path        = $exe
                CommandLine = $dll
                Sha256      = Get-FileHashSafe $exe
            }
            Signature = Get-SignatureSafe $exe
            Metadata  = @{
                GUID = $guid
                Raw  = $dll
            }
        }
    }

    $items
}

function Get-DLLHostItems {
    $items = @()

    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $proc = $_
        try { $modules = $proc.Modules } catch { continue }

        foreach ($m in $modules) {
            $dll = Normalize-PathSafe $m.FileName
            $items += New-HostItem @{
                Key      = "DLL:$($proc.ProcessName)|$dll"
                Category = 'DLL'
                Identity = New-HostIdentity @{
                    Path        = $dll
                    CommandLine = ''
                    Sha256      = Get-FileHashSafe $dll
                }
                Signature = Get-SignatureSafe $dll
                Metadata  = @{
                    ProcessName = $proc.ProcessName
                    ProcessId   = $proc.Id
                }
            }
        }
    }

    $items
}

function Get-AppInitHostItems {
    $items = @()

    $keys = @(
        "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )

    foreach ($k in $keys) {
        try { $val = (Get-ItemProperty -Path $k -ErrorAction Stop).AppInit_DLLs }
        catch { continue }

        if (-not $val) { continue }

        foreach ($dll in $val.Split(' ')) {
            if (-not $dll) { continue }
            $exe = Resolve-DllPath $dll

            $items += New-HostItem @{
                Key      = "AppInit:$dll"
                Category = 'AppInit'
                Identity = New-HostIdentity @{
                    Path        = $exe
                    CommandLine = $dll
                    Sha256      = Get-FileHashSafe $exe
                }
                Signature = Get-SignatureSafe $exe
                Metadata  = @{
                    Registry     = $k
                    Raw          = $dll
                    ResolvedPath = $exe
                }
            }
        }
    }

    $items
}

function Get-ShellExtHostItems {
    $items = @()

    $roots = @(
        "HKCR:\*\shellex\ContextMenuHandlers",
        "HKCR:\Directory\shellex\ContextMenuHandlers",
        "HKCR:\Drive\shellex\ContextMenuHandlers",
        "HKCR:\AllFileSystemObjects\shellex\ContextMenuHandlers"
    )

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }

        Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
            $name = $_.PSChildName
            try { $clsid = (Get-ItemProperty $_.PSPath -ErrorAction Stop)."(default)" }
            catch { continue }

            $clsKey = "HKCR:\CLSID\$clsid\InprocServer32"
            if (-not (Test-Path $clsKey)) { continue }

            try { $dll = (Get-ItemProperty $clsKey -ErrorAction Stop)."(default)" }
            catch { continue }

            $exe = Resolve-DllPath $dll

            $items += New-HostItem @{
                Key      = "ShellExt:$clsid"
                Category = 'ShellExt'
                Identity = New-HostIdentity @{
                    Path        = $exe
                    CommandLine = $dll
                    Sha256      = Get-FileHashSafe $exe
                }
                Signature = Get-SignatureSafe $exe
                Metadata  = @{
                    CLSID        = $clsid
                    Handler      = $name
                    Registry     = $_.PSPath
                    ResolvedPath = $exe
                }
            }
        }
    }

    $items
}

Export-ModuleMember -Function *
