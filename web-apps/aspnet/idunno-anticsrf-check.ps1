# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PrivacySafe Security Patches: Idunno.AntiCsrf deserialization, Windows and IIS  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Idunno.AntiCsrf unauthenticated remote code execution (exploited, November 2026)
# CVE-2026-131914 (CVSS 4.0 9.3, Mandiant MNDT-2026-0048)
#
# The rest of this collection is for GNU/Linux. This flaw lives in an ASP.NET WebForms
# module that runs inside IIS on Windows, so this tool is PowerShell. For Mono hosts on
# GNU/Linux (mod_mono, XSP, fastcgi-mono-server) use idunno-anticsrf-check.sh from this
# folder. This script also runs under PowerShell 7 on GNU/Linux, pointed with -Roots at a
# share, a backup or a deployment tree from a Windows server.
#
# Idunno.AntiCsrf (Idunno.AntiCsrf.dll 0.9.1.0, "0.9.1 Beta", last released December
# 2008, no maintainer, no fix) is a double-submit-cookie CSRF module. On every POST to a
# WebForms page it passes the CSRF form field to an unkeyed ObjectStateFormatter, with no
# MAC and no type restriction, before the page runs. Any non-empty CSRF cookie and a
# Base64 .NET gadget chain in the form field run code as the IIS worker process (w3wp.exe).
# One request, no login, no valid token. Mandiant has seen it exploited.
#
# Usage (PowerShell; Windows PowerShell 5.1 or PowerShell 7):
#   powershell -ExecutionPolicy Bypass -File .\idunno-anticsrf-check.ps1 [command] [options]
#
#   check (default)  find the module: the DLL by name, by its published hashes and by its
#                    module code inside any DLL in a bin folder; the Web.config files that
#                    register it (site, application, machine-wide); the GAC; and the ASP.NET
#                    shadow copies that show an application loaded it. Sites come from IIS
#                    (following shared configuration) and IIS Express; each site's application
#                    pool, pipeline mode and .NET version are shown. Read only.
#                    Exit 0 = not found, 1 = found, 2 = something could not be read.
#   hunt             read the IIS logs for what Mandiant describes: POST requests to .aspx
#                    pages answered with 302 or 500 and a large request body (cs-bytes, where
#                    logged); ASP.NET event 1309 errors from the module or ObjectStateFormatter;
#                    shells and tools started by w3wp.exe, running now or in event 4688; and
#                    files changed recently in the sites, marking pages that run commands. Read
#                    only.
#                    Exit 0 = nothing found, 1 = requests to look at, 2 = no log could be read.
#   mitigate         take the module out of every Web.config that registers it. Each file is
#                    copied first, edited, read back, and restored if it no longer parses.
#                    The DLL stays, because pages may reference its attributes. -DryRun shows
#                    the changes and writes nothing. Needs Administrator on Windows.
#                    Exit 0 = done or nothing to do, 1 = a file could not be changed, 2 = bad
#                    arguments or no rights.
#   rollback         put back the Web.config files saved by the last mitigate (-BackupDir to
#                    pick another). -DryRun shows what it would restore.
#                    Exit 0 = restored, 1 = a file could not be restored, 2 = no backup.
#   version          print the script version.
#
# IIS restarts an application by itself when its Web.config changes, so mitigate and rollback
# take effect at once, and the sites they touch restart (sessions held in process are lost).
# Taking the module out closes the hole and removes its CSRF protection: replace it with a
# supported one (System.Web.Helpers.AntiForgery, or ViewStateUserKey with MAC-checked
# ViewState). See the README.
#
# Options:
#   -Roots D:\www,E:\apps       more folders to search, beside the IIS sites (on GNU/Linux:
#                               the only folders searched)
#   -ApplicationHostConfig <p>  IIS configuration to read sites and log folders from
#                               (default %windir%\System32\inetsrv\config\applicationHost.config)
#   -WindowsDir <p>             Windows folder for the machine-wide web.config and the GAC
#                               (default %windir%)
#   -LogDirs D:\logs            more folders holding IIS W3C logs, for hunt
#   -Days 60                    how far back hunt reads logs and lists changed files
#   -MinBytes 3000              request size from which a POST counts as large
#   -StateDir <p>               where backups and the lock live
#                               (default %ProgramData%\PrivacySafe\idunno-anticsrf)
#   -BackupDir <p>              the backup rollback restores (default: the newest)
#   -LockWait 30                seconds to wait for another run's lock
#   -ExtraSha256 <h>,<h>        more SHA-256 hashes of the DLL, as they are published
#   -IisExpressRoots <p>        IISExpress folders to read (default: each profile's
#                               Documents\IISExpress)
#   -DryRun                     mitigate and rollback: show, change nothing
#
# Plain ASCII on purpose.
#
# Assisted-by: Claude Opus 5.5
# =============================================================================
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = 'check',
    [string[]]$Roots = @(),
    [string]$ApplicationHostConfig = '',
    [string]$WindowsDir = '',
    [string[]]$LogDirs = @(),
    [int]$Days = 60,
    [int]$MinBytes = 3000,
    [string]$StateDir = '',
    [string]$BackupDir = '',
    [int]$LockWait = 30,
    [string[]]$ExtraSha256 = @(),
    [string[]]$IisExpressRoots = @(),
    [switch]$DryRun,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$ScriptName = 'idunno-anticsrf-check.ps1'
$ScriptVersion = '1.0.0'
$ScriptDate = '2026-11-23'
$Cve = 'CVE-2026-131914'
$Ref = 'https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0048.md'

# Mandiant's three known builds of Idunno.AntiCsrf.dll 0.9.1.0: the official 2008 release, and
# release and debug rebuilds of the CodePlex source. A recompiled copy has another hash, which is
# why the assembly name is also searched for inside every DLL in a bin folder.
$DllSha256 = @(
    'da1efcfed182597ee946a9ef2895dfdfeab2bdff16855aeef01656d8158ead06',
    'c5c994891783453ae85f3ef8efb48592b7c560aeb56f531ee9ea5736518246eb',
    'aa7bbad4a7ebc38519955ac65517716569508ee4f61fc2f1276086940501e9bf'
) + @($ExtraSha256 | ForEach-Object { $_.ToLowerInvariant() })
$DllName = 'Idunno.AntiCsrf.dll'
$ModuleRegex = [regex]'(?i)Idunno\.AntiCsrf'

# ---------- counters and output ----------------------------------------------
$script:NFound = 0      # the module is registered or its DLL is on disk
$script:NUnread = 0     # something could not be read or listed
$script:NReview = 0     # needs a look by hand
$script:NWebShell = 0   # recently changed pages that run commands

function Step([string]$m) { Write-Host ''; Write-Host "===== $m =====" -ForegroundColor Cyan }
function Info([string]$m) { Write-Host "[+] $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Bad([string]$m) { Write-Host "  [BAD] $m" -ForegroundColor Red }
function Caution([string]$m) { Write-Host "  [!]   $m" -ForegroundColor Yellow }
function Inf([string]$m) { Write-Host "  [.]   $m" }
function Unread([string]$m) { $script:NUnread++; Caution $m }
function Fatal([string]$m) { Write-Host "[-] FATAL: $m" -ForegroundColor Red; exit 2 }

$OnWindows = [IO.Path]::DirectorySeparatorChar -eq '\'
if ($WindowsDir -eq '' -and $env:windir) { $WindowsDir = $env:windir }
if ($ApplicationHostConfig -eq '' -and $WindowsDir -ne '') {
    $ApplicationHostConfig = Join-Path (Join-Path (Join-Path (Join-Path $WindowsDir 'System32') 'inetsrv') 'config') 'applicationHost.config'
}
if ($IisExpressRoots.Count -eq 0 -and $OnWindows) {
    $IisExpressRoots = @()
    $usersDir = Join-Path $env:SystemDrive 'Users'
    if (Test-Path -LiteralPath $usersDir) { foreach ($u in @(Get-ChildItem -LiteralPath $usersDir -Directory -ErrorAction SilentlyContinue)) { $IisExpressRoots += (Join-Path (Join-Path $u.FullName 'Documents') 'IISExpress') } }
}
if ($StateDir -eq '') {
    $pd = $env:ProgramData
    if (-not $pd) { $pd = Join-Path ([IO.Path]::GetTempPath()) 'ProgramData' }
    $StateDir = Join-Path (Join-Path $pd 'PrivacySafe') 'idunno-anticsrf'
}

function Test-Elevated {
    if (-not $OnWindows) { return $true }
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-Sha256Of([string]$path) {
    try { return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { return '' }
}

function Expand-PathText([string]$p) {
    if (-not $p) { return '' }
    $p = [Environment]::ExpandEnvironmentVariables($p)
    if ($env:SystemDrive) { $p = $p -ireplace '%SystemDrive%', $env:SystemDrive }
    return $p
}

# ---------- IIS configuration ------------------------------------------------
# Sites, applications and virtual directories, and the log folders, from applicationHost.config.
# Read as XML; nothing is loaded from IIS's own modules, so it works without them.
function Read-XmlFile([string]$path) {
    $doc = New-Object Xml.XmlDocument
    $doc.PreserveWhitespace = $true
    $doc.XmlResolver = $null
    $doc.Load($path)
    return $doc
}

$script:Sites = @()        # objects: Name, Id, Path
$script:LogFolders = @()
$script:Pools = @{}       # application pool name -> pipeline mode and .NET version
$script:IisRead = $false
function Get-ConfigFiles {
    $list = @()
    if ($ApplicationHostConfig) {
        # IIS shared configuration: redirection.config points at the real applicationHost.config
        $redir = Join-Path (Split-Path $ApplicationHostConfig -Parent) 'redirection.config'
        if (Test-Path -LiteralPath $redir -PathType Leaf) {
            try {
                $r = (Read-XmlFile $redir).SelectSingleNode('//configurationRedirection')
                if ($r -and $r.GetAttribute('enabled') -eq 'true' -and $r.GetAttribute('path')) {
                    $shared = Join-Path (Expand-PathText $r.GetAttribute('path')) 'applicationHost.config'
                    Inf "IIS shared configuration is on: reading $shared"
                    $list += $shared
                }
            } catch { Unread "cannot read ${redir}: $($_.Exception.Message)" }
        }
        $list += $ApplicationHostConfig
    }
    # IIS Express on developer machines: the user's own configuration and each Visual Studio solution's
    foreach ($p in $IisExpressRoots) {
        if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Container)) { continue }
        $list += @(Get-ChildItem -LiteralPath $p -Recurse -File -Filter 'applicationhost.config' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -imatch 'IISExpress|[\\/]\.vs[\\/]' } | ForEach-Object { $_.FullName })
    }
    return , $list
}
function Read-IisConfig {
    if ($script:IisRead) { return }
    $script:IisRead = $true
    foreach ($cfg in (Get-ConfigFiles)) { Read-OneIisConfig $cfg }
}
function Read-OneIisConfig([string]$ApplicationHostConfig) {
    if (-not $ApplicationHostConfig -or -not (Test-Path -LiteralPath $ApplicationHostConfig -PathType Leaf)) { return }
    try { $doc = Read-XmlFile $ApplicationHostConfig }
    catch { Unread "cannot read ${ApplicationHostConfig}: $($_.Exception.Message)"; return }
    $pd = $doc.SelectSingleNode('//applicationPools/applicationPoolDefaults')
    $defMode = 'Integrated'; $defRt = 'v4.0'
    if ($pd) { if ($pd.GetAttribute('managedPipelineMode')) { $defMode = $pd.GetAttribute('managedPipelineMode') }; if ($pd.HasAttribute('managedRuntimeVersion')) { $defRt = $pd.GetAttribute('managedRuntimeVersion') } }
    foreach ($ap in $doc.SelectNodes('//applicationPools/add')) {
        $m = $defMode; $rt = $defRt
        if ($ap.GetAttribute('managedPipelineMode')) { $m = $ap.GetAttribute('managedPipelineMode') }
        if ($ap.HasAttribute('managedRuntimeVersion')) { $rt = $ap.GetAttribute('managedRuntimeVersion') }
        $script:Pools[$ap.GetAttribute('name')] = [pscustomobject]@{ Mode = $m; Runtime = $rt }
    }
    $defLog = '%SystemDrive%\inetpub\logs\LogFiles'
    $d = $doc.SelectSingleNode('//sites/siteDefaults/logFile')
    if ($d -and $d.GetAttribute('directory')) { $defLog = $d.GetAttribute('directory') }
    $script:LogFolders += (Expand-PathText $defLog)
    foreach ($site in $doc.SelectNodes('//sites/site')) {
        $name = $site.GetAttribute('name'); $id = $site.GetAttribute('id')
        $lf = $site.SelectSingleNode('logFile')
        if ($lf -and $lf.GetAttribute('directory')) { $script:LogFolders += (Expand-PathText $lf.GetAttribute('directory')) }
        $siteAppPool = ''
        $ad = $site.SelectSingleNode('applicationDefaults'); if ($ad) { $siteAppPool = $ad.GetAttribute('applicationPool') }
        foreach ($app in $site.SelectNodes('application')) {
            $pool = $app.GetAttribute('applicationPool'); if (-not $pool) { $pool = $siteAppPool }; if (-not $pool) { $pool = 'DefaultAppPool' }
            foreach ($vd in $app.SelectNodes('virtualDirectory')) {
                $p = Expand-PathText $vd.GetAttribute('physicalPath')
                if ($p) { $script:Sites += [pscustomobject]@{ Name = $name; Id = $id; Path = $p; Pool = $pool; App = $app.GetAttribute('path') } }
            }
        }
    }
}

function Get-SearchRoots {
    $list = @()
    foreach ($s in $script:Sites) { $list += $s.Path }
    foreach ($r in $Roots) { if ($r) { $list += $r } }
    $seen = @{}; $out = @()
    foreach ($p in $list) {
        $k = $p.TrimEnd('\', '/').ToLowerInvariant()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true; $out += $p
    }
    return , $out
}

# Every file under a root, or $null if the root cannot be listed. Errors on single folders are
# counted, so a partial listing is not taken for a clean one.
function Get-FilesUnder([string]$root) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { Unread "cannot read ${root}: not a folder or not reachable"; return $null }
    $errs = $null
    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue -ErrorVariable errs)
    if ($errs -and $errs.Count -gt 0) { Unread "${root}: $($errs.Count) folder(s) could not be listed (run as Administrator)" }
    return , $files
}

$script:ConfigHits = @()   # Web.config files that register the module
function Test-IsLink([string]$path) {
    try { return [bool]((Get-Item -LiteralPath $path -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) } catch { return $false }
}
function Test-ConfigFile([string]$path, [string]$where) {
    # A symbolic link or junction is reported and never read or written through.
    if (Test-IsLink $path) { $script:NReview++; Caution "${path}${where}: a symbolic link: read the file it points to by hand"; return }
    try { $text = [IO.File]::ReadAllText($path) }
    catch { Unread "cannot read ${path}: $($_.Exception.Message)"; return }
    if (-not $ModuleRegex.IsMatch($text)) { return }
    $registered = $false
    try {
        $doc = Read-XmlFile $path
        foreach ($n in (Get-ModuleNodes $doc)) { $registered = $true }
    } catch {
        Caution "${path}: names Idunno.AntiCsrf but is not well-formed XML ($($_.Exception.Message)); read it by hand"
        $script:NReview++; return
    }
    if ($registered) {
        $script:NFound++; $script:ConfigHits += $path
        Bad "${path}${where}: registers Idunno.AntiCsrf.AntiCsrfModule. POST requests to its pages reach the unsafe deserializer"
    } else {
        $script:NFound++
        Caution "${path}${where}: names Idunno.AntiCsrf (a csrfSettings section or an assembly reference) but registers no module. Remove what is left"
    }
}

# The <add> elements that register the module, under httpModules (classic pipeline) or modules
# (integrated pipeline), wherever they sit, including inside <location>.
function Get-ModuleNodes([Xml.XmlDocument]$doc) {
    $out = @()
    foreach ($n in $doc.SelectNodes("//*[local-name()='add']")) {
        $parent = $n.ParentNode
        if (-not $parent -or ($parent.LocalName -ne 'httpModules' -and $parent.LocalName -ne 'modules')) { continue }
        $t = $n.GetAttribute('type')
        if ($ModuleRegex.IsMatch($t) -or $t -imatch 'AntiCsrfModule') { $out += $n }
    }
    return , $out
}

function Test-DllFile([IO.FileInfo]$f) {
    $h = Get-Sha256Of $f.FullName
    if ($f.Name -ieq $DllName -or ($h -and $DllSha256 -contains $h)) {
        $script:NFound++
        $how = 'by name'
        if ($DllSha256 -contains $h) { $how = 'by one of the hashes Mandiant published' }
        Bad "$($f.FullName): Idunno.AntiCsrf.dll, found $how"
        return
    }
    # A renamed or recompiled copy keeps its assembly name in its metadata.
    if ($f.Length -gt 0 -and $f.Length -lt 8MB -and $f.DirectoryName -imatch '[\\/]bin([\\/]|$)') {
        try {
            $bytes = [IO.File]::ReadAllBytes($f.FullName)
            $text = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
            if ($text.Contains('Idunno.AntiCsrf')) {
                # The module's own code, not an application that only uses its attributes.
                if ($text.Contains('AntiCsrfModule') -and $text.Contains('ObjectStateFormatter') -and $text.Contains('PreRequestHandlerExecute')) {
                    $script:NFound++
                    Bad "$($f.FullName): carries the Idunno.AntiCsrf module under another name or build"
                } else {
                    Inf "$($f.FullName): refers to Idunno.AntiCsrf (pages that use its attributes): change those pages when you remove the module"
                }
            }
        } catch { Unread "cannot read $($f.FullName): $($_.Exception.Message)" }
    }
}

function Invoke-Check {
    Write-Host "$ScriptName $ScriptVersion ($ScriptDate) - check on $([Environment]::MachineName) at $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    Write-Host "$Cve; Idunno.AntiCsrf has no fix: the remedy is to take it out"
    if ($OnWindows -and -not (Test-Elevated)) { Caution 'not running as Administrator: sites and configuration this account cannot read are not checked, so a clean result covers only what it could see. Open PowerShell with Run as Administrator.' }

    Step 'IIS sites'
    Read-IisConfig
    if ($script:Sites.Count -gt 0) {
        foreach ($s in $script:Sites) {
            $poolInfo = ''
            if ($script:Pools.ContainsKey($s.Pool)) {
                $pi = $script:Pools[$s.Pool]
                if ($pi.Runtime -eq '') { $poolInfo = "; pool $($s.Pool): No Managed Code, so ASP.NET modules do not run" }
                else { $poolInfo = "; pool $($s.Pool): $($pi.Mode) pipeline, .NET $($pi.Runtime) (an Integrated pool runs modules from system.webServer/modules, a Classic one from system.web/httpModules)" }
            }
            Inf "site $($s.Name) (id $($s.Id)) $($s.App): $($s.Path)$poolInfo"
        }
    }
    elseif ($OnWindows) { Inf 'no IIS site found (IIS not installed, or its configuration is not readable)' }
    else { Inf 'not Windows: only the folders given with -Roots are searched' }

    $roots = Get-SearchRoots
    Step 'Sites and folders'
    if ($roots.Count -eq 0 -and -not $OnWindows) { Fatal 'not Windows and no -Roots given: nothing to search. Name the folders with -Roots' }
    if ($roots.Count -eq 0) { Inf 'no site folder to search; give more with -Roots' }
    $seenFiles = @{}   # a site nested in another is listed once
    foreach ($r in $roots) {
        $files = Get-FilesUnder $r
        if ($null -eq $files) { continue }
        $n0 = $script:NFound
        foreach ($f in $files) {
            $k = $f.FullName.ToLowerInvariant()
            if ($seenFiles.ContainsKey($k)) { continue }
            $seenFiles[$k] = $true
            if ($f.Name -ieq 'web.config') { Test-ConfigFile $f.FullName '' }
            elseif ($f.Extension -ieq '.dll') { Test-DllFile $f }
        }
        if ($script:NFound -eq $n0) { Inf "${r}: no trace of Idunno.AntiCsrf ($($files.Count) files)" }
    }

    Step 'Machine-wide configuration and the GAC'
    if ($WindowsDir -and (Test-Path -LiteralPath $WindowsDir -PathType Container)) {
        $net = Join-Path $WindowsDir 'Microsoft.NET'
        foreach ($fw in @('Framework', 'Framework64')) {
            $base = Join-Path $net $fw
            if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }
            foreach ($v in @(Get-ChildItem -LiteralPath $base -Directory -Filter 'v*' -ErrorAction SilentlyContinue)) {
                $wc = Join-Path (Join-Path $v.FullName 'Config') 'web.config'
                if (Test-Path -LiteralPath $wc -PathType Leaf) { Test-ConfigFile $wc ' (machine-wide: every application on this .NET version)' }
            }
        }
        foreach ($g in @((Join-Path (Join-Path (Join-Path $net 'assembly') 'GAC_MSIL') 'Idunno.AntiCsrf'), (Join-Path (Join-Path (Join-Path $WindowsDir 'assembly') 'GAC_MSIL') 'Idunno.AntiCsrf'))) {
            if (Test-Path -LiteralPath $g) { $script:NFound++; Bad "${g}: Idunno.AntiCsrf is installed in the Global Assembly Cache, where any application can load it" }
        }
        # ASP.NET copies the assemblies an application loads into Temporary ASP.NET Files: a copy there
        # means an application loaded the module at some point, even if it is gone now.
        foreach ($fw in @('Framework', 'Framework64')) {
            $base = Join-Path $net $fw
            if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }
            foreach ($v in @(Get-ChildItem -LiteralPath $base -Directory -Filter 'v*' -ErrorAction SilentlyContinue)) {
                $tmpRoot = Join-Path $v.FullName 'Temporary ASP.NET Files'
                if (-not (Test-Path -LiteralPath $tmpRoot -PathType Container)) { continue }
                foreach ($c in @(Get-ChildItem -LiteralPath $tmpRoot -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq $DllName })) {
                    $script:NReview++
                    Caution "$($c.FullName): an ASP.NET shadow copy (written $($c.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))): an application loaded Idunno.AntiCsrf. Find which, and run hunt"
                }
            }
        }
        Inf "read the machine-wide web.config files, the GAC and the ASP.NET shadow copies under $WindowsDir"
    } else { Inf 'no Windows folder: machine-wide configuration and the GAC not checked' }

    Step 'Verdict'
    if ($script:NFound -gt 0) {
        Warn "FOUND: $($script:NFound) trace(s) of Idunno.AntiCsrf. Where a Web.config registers it, any anonymous POST to a page can run code on this server ($Cve, exploited)."
        if ($script:ConfigHits.Count -gt 0) { Warn "Run 'mitigate -DryRun', then 'mitigate', to take the module out of those Web.config files now. Then run 'hunt', and replace it with a supported anti-CSRF mechanism (see the README)." }
        else { Warn 'No Web.config registers it, so it is not active. Delete the DLL and the leftover configuration.' }
        if ($script:NReview -gt 0) { Warn "$($script:NReview) item(s) need a look by hand (marked above)." }
        exit 1
    }
    if ($script:NReview -gt 0) { Warn "$($script:NReview) item(s) need a look by hand (marked above)."; exit 1 }
    if ($script:NUnread -gt 0) { Warn "Not found, but $($script:NUnread) thing(s) could not be read, so this is not a clean result."; exit 2 }
    Info 'Idunno.AntiCsrf was not found where this could read.'
    exit 0
}

# ---------- hunt -------------------------------------------------------------
function Invoke-Hunt {
    Write-Host "$ScriptName $ScriptVersion ($ScriptDate) - hunt on $([Environment]::MachineName) at $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    Write-Host "$Cve; looking for POST requests to .aspx pages answered with 302 or 500, of $MinBytes bytes or more"
    Read-IisConfig
    $since = (Get-Date).AddDays(-$Days)
    $dirs = @($script:LogFolders) + @($LogDirs)
    $files = @()
    foreach ($d in $dirs) {
        if (-not $d -or -not (Test-Path -LiteralPath $d -PathType Container)) { continue }
        $files += @(Get-ChildItem -LiteralPath $d -Recurse -File -Filter '*.log' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $since })
    }
    Step "IIS logs from the last $Days days"
    if ($files.Count -eq 0) {
        Warn 'No IIS log could be read. Give the log folder with -LogDirs, or run as Administrator.'
        exit 2
    }
    $hits = 0; $nosize = 0; $read = 0; $shown = 0
    foreach ($f in $files) {
        $read++
        $cols = @{}
        # IIS keeps today's log open for writing; share it rather than wait for it.
        try { $reader = [IO.StreamReader]::new([IO.FileStream]::new($f.FullName, 'Open', 'Read', 'ReadWrite')) } catch { Unread "cannot read $($f.FullName)"; continue }
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                if ($line.StartsWith('#Fields:', [StringComparison]::Ordinal)) {
                    $cols = @{}; $i = 0
                    foreach ($c in ($line.Substring(8).Trim() -split ' ')) { $cols[$c] = $i; $i++ }
                    continue
                }
                if ($line.StartsWith('#') -or -not $cols.ContainsKey('cs-method')) { continue }
                $v = $line -split ' '
                if ($v.Count -le $cols['cs-method'] -or $v[$cols['cs-method']] -ne 'POST') { continue }
                if (-not $cols.ContainsKey('cs-uri-stem') -or $v[$cols['cs-uri-stem']] -inotmatch '\.aspx$') { continue }
                if (-not $cols.ContainsKey('sc-status')) { continue }
                $st = $v[$cols['sc-status']]
                if ($st -ne '302' -and $st -ne '500') { continue }
                if (-not $cols.ContainsKey('cs-bytes')) { $nosize++; continue }
                $size = 0
                if (-not [int]::TryParse($v[$cols['cs-bytes']], [ref]$size) -or $size -lt $MinBytes) { continue }
                $hits++
                if ($shown -lt 40) { $shown++; Bad "$($f.Name): $line" }
            }
        } finally { $reader.Dispose() }
    }
    Inf "$read log file(s) read"
    if ($nosize -gt 0) { Caution "$nosize POST(s) to .aspx pages answered 302 or 500 in logs that do not record cs-bytes, so their size is unknown. Turn on the 'Bytes Received' field in IIS logging to see it next time" }

    Step 'Windows event logs and processes'
    $evHits = 0
    if ($OnWindows) {
        # ASP.NET writes event 1309 (unhandled exception) for each request the module rejects or that throws
        # while deserializing: every exploitation attempt leaves one when health monitoring is on (the default).
        try {
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1309; StartTime = $since } -ErrorAction Stop |
                    Where-Object { $_.Message -match 'PotentialCsrfException|Idunno\.AntiCsrf|ObjectStateFormatter' })
            foreach ($e in ($ev | Select-Object -First 30)) { Bad "event 1309 at $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')): $((($e.Message -split "`n") | Where-Object { $_ -match 'Exception type|Request URL|User host address' }) -join ' | ')" }
            $evHits += $ev.Count
            if ($ev.Count -eq 0) { Inf 'no ASP.NET event 1309 that names the module or ObjectStateFormatter' }
        } catch { if ($_.Exception.Message -match 'No events were found') { Inf 'no ASP.NET event 1309 in the period' } else { Unread "cannot read the Application event log: $($_.Exception.Message)" } }
        # Programs started by the IIS worker process: a shell under w3wp.exe is what a successful payload looks like.
        $shells = '^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|whoami|net|net1|nltest|csc|msbuild|curl|wget)\.exe$'
        try {
            $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
            $w3 = @{}; foreach ($p in $procs) { if ($p.Name -ieq 'w3wp.exe') { $w3[[int]$p.ProcessId] = $p } }
            foreach ($p in $procs) { if ($w3.ContainsKey([int]$p.ParentProcessId) -and $p.Name -imatch $shells) { $evHits++; Bad "running now: $($p.Name) (pid $($p.ProcessId)) started by w3wp.exe (pid $($p.ParentProcessId)): $($p.CommandLine)" } }
        } catch { Unread "cannot list processes: $($_.Exception.Message)" }
        # Process creation events (4688), recorded only when process creation auditing is on.
        try {
            $pc = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $since } -ErrorAction Stop |
                    Where-Object { $_.Message -match 'w3wp\.exe' -and $_.Message -match 'New Process Name:\s+\S*\\(cmd|powershell|pwsh|whoami|certutil|rundll32|mshta|net1?)\.exe' })
            foreach ($e in ($pc | Select-Object -First 30)) { Bad "event 4688 at $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')): a shell or tool started by w3wp.exe" }
            $evHits += $pc.Count
        } catch { if ($_.Exception.Message -notmatch 'No events were found') { Inf 'process creation events (4688) not readable or not recorded: turn on process creation auditing to see programs w3wp.exe starts' } }
    } else { Inf 'not Windows: event logs and processes not read' }

    Step 'Files changed recently in the sites'
    $roots = Get-SearchRoots
    $since2 = (Get-Date).AddDays(-$Days)
    foreach ($r in $roots) {
        $list = Get-FilesUnder $r
        if ($null -eq $list) { continue }
        $recent = @($list | Where-Object { $_.LastWriteTime -ge $since2 -and $_.Extension -imatch '^\.(aspx|ashx|asmx|asax|ascx|config|dll|exe|ps1|bat|cmd|vbs|js)$' } | Sort-Object LastWriteTime -Descending | Select-Object -First 30)
        foreach ($x in $recent) {
            $shellLike = $false
            if ($x.Extension -imatch '^\.(aspx|ashx|asmx|ascx)$') {
                try { $shellLike = ([IO.File]::ReadAllText($x.FullName) -match 'Process\.Start|ProcessStartInfo|cmd\.exe|Assembly\.Load|eval\(Request|Request\.(Form|QueryString)\[[^\]]*\]\)') } catch { }
            }
            if ($shellLike) { $script:NWebShell++; Bad "$($x.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))  $($x.FullName)  (looks like a web shell: runs commands or loads code from the request)" }
            else { Caution "$($x.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))  $($x.FullName)" }
        }
        if ($recent.Count -eq 0) { Inf "${r}: no page, script or binary changed in the last $Days days" }
        else { $script:NReview++ }
    }

    Step 'Verdict'
    $leads = $hits + $evHits + $script:NWebShell
    if ($leads -gt 0) {
        Warn "$leads lead(s) above: large POSTs to .aspx pages answered 302 or 500, ASP.NET errors from the module or ObjectStateFormatter, programs started by w3wp.exe, or new pages that run commands. $hits large POST(s) to .aspx pages were answered with 302 or 500: the pattern Mandiant describes. Look at each one, and treat the server as compromised if any came from an address you do not know: rotate every secret in Web.config and applicationHost.config (the machineKey, encryption keys and database passwords) and check the sites for files you did not put there."
        exit 1
    }
    if ($script:NReview -gt 0) { Warn 'No suspicious request was found. Files changed recently are listed above: check that each change was yours.' }
    if ($nosize -gt 0) { Warn 'No large request was found, but some logs do not record request sizes, so this is not a clean result.'; exit 2 }
    Info 'No request matching the exploitation pattern was found in the logs read.'
    exit 0
}

# ---------- lock -------------------------------------------------------------
$script:LockStream = $null
function Get-Lock {
    if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    $p = Join-Path $StateDir '.lock'
    $deadline = (Get-Date).AddSeconds($LockWait)
    while ($true) {
        try { $script:LockStream = [IO.File]::Open($p, 'OpenOrCreate', 'ReadWrite', 'None'); return }
        catch {
            if ((Get-Date) -ge $deadline) { Fatal "another run holds the lock $p (waited $LockWait seconds)" }
            Start-Sleep -Milliseconds 500
        }
    }
}
function Drop-Lock { if ($script:LockStream) { $script:LockStream.Dispose(); $script:LockStream = $null } }

function Test-ParsesAsXml([string]$path) {
    try { [void](Read-XmlFile $path); return $true } catch { return $false }
}

# ---------- mitigate ---------------------------------------------------------
function Invoke-Mitigate {
    Write-Host "$ScriptName $ScriptVersion ($ScriptDate) - mitigate on $([Environment]::MachineName) at $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    if ($DryRun) { Write-Host 'DRY RUN: nothing will be written' }
    if (-not $DryRun -and -not (Test-Elevated)) { Fatal 'mitigate changes Web.config files: open PowerShell with Run as Administrator, or add -DryRun to see the changes first' }
    Read-IisConfig
    $targets = @()
    foreach ($r in (Get-SearchRoots)) {
        $files = Get-FilesUnder $r
        if ($null -eq $files) { continue }
        foreach ($f in $files) { if ($f.Name -ieq 'web.config') { $targets += $f.FullName } }
    }
    if ($WindowsDir) {
        foreach ($fw in @('Framework', 'Framework64')) {
            $base = Join-Path (Join-Path $WindowsDir 'Microsoft.NET') $fw
            if (Test-Path -LiteralPath $base -PathType Container) {
                foreach ($v in @(Get-ChildItem -LiteralPath $base -Directory -Filter 'v*' -ErrorAction SilentlyContinue)) {
                    $wc = Join-Path (Join-Path $v.FullName 'Config') 'web.config'
                    if (Test-Path -LiteralPath $wc -PathType Leaf) { $targets += $wc }
                }
            }
        }
    }
    $todo = @(); $seenT = @{}
    foreach ($t in $targets) {
        $k = $t.ToLowerInvariant()
        if ($seenT.ContainsKey($k)) { continue }
        $seenT[$k] = $true
        if (Test-IsLink $t) { Caution "${t}: a symbolic link, left alone: change the file it points to by hand"; $script:NReview++; continue }
        try { $text = [IO.File]::ReadAllText($t) } catch { Unread "cannot read ${t}"; continue }
        if (-not $ModuleRegex.IsMatch($text) -and $text -inotmatch 'AntiCsrfModule') { continue }
        try { $doc = Read-XmlFile $t } catch { Caution "${t}: not well-formed XML, left alone: fix it by hand"; $script:NReview++; continue }
        $nodes = Get-ModuleNodes $doc
        if ($nodes.Count -gt 0) { $todo += [pscustomobject]@{ Path = $t; Count = $nodes.Count } }
    }
    Step 'Web.config files that register the module'
    if ($todo.Count -eq 0) {
        if ($script:NUnread -gt 0 -or $script:NReview -gt 0) { Warn 'No registration was found, but some files could not be read or parsed (above).'; exit 1 }
        Info 'No Web.config registers Idunno.AntiCsrf: nothing to do.'
        exit 0
    }
    foreach ($x in $todo) { Inf "$($x.Path): $($x.Count) registration(s) to remove" }
    if ($DryRun) {
        Step 'Verdict'
        Info "DRY RUN: $($todo.Count) file(s) would be copied to a new folder under $StateDir and changed. Those applications restart when their Web.config changes."
        exit 0
    }
    Get-Lock
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $bk = Join-Path $StateDir "backup-$stamp"
    New-Item -ItemType Directory -Path $bk -Force | Out-Null
    $manifest = Join-Path $bk 'manifest.tsv'
    $failed = 0; $i = 0
    foreach ($x in $todo) {
        $i++
        $copy = Join-Path $bk ("{0:D3}-web.config" -f $i)
        try { Copy-Item -LiteralPath $x.Path -Destination $copy -ErrorAction Stop }
        catch { Bad "$($x.Path): could not be copied ($($_.Exception.Message)); left alone"; $failed++; continue }
        Add-Content -LiteralPath $manifest -Value ("{0}`t{1}" -f $x.Path, (Split-Path $copy -Leaf))
        try {
            if (Test-IsLink $x.Path) { throw 'it became a symbolic link' }
            $doc = Read-XmlFile $x.Path
            foreach ($n in (Get-ModuleNodes $doc)) {
                $prev = $n.PreviousSibling
                if ($prev -and $prev.NodeType -eq [Xml.XmlNodeType]::Whitespace) { [void]$n.ParentNode.RemoveChild($prev) }
                [void]$n.ParentNode.RemoveChild($n)
            }
            $doc.Save($x.Path)
            $after = Read-XmlFile $x.Path
            if ((Get-ModuleNodes $after).Count -ne 0) { throw 'the registration is still there after saving' }
            Info "$($x.Path): module removed (copy: $copy)"
        } catch {
            Bad "$($x.Path): $($_.Exception.Message); restoring the copy"
            try { Copy-Item -LiteralPath $copy -Destination $x.Path -Force -ErrorAction Stop } catch { Bad "$($x.Path): could not be restored from $copy. Restore it by hand" }
            $failed++
        }
    }
    Drop-Lock
    Step 'Verdict'
    if ($failed -gt 0) { Warn "$failed file(s) could not be changed (above)."; exit 1 }
    if ($script:NReview -gt 0 -or $script:NUnread -gt 0) { Warn "The files above were changed, but $($script:NReview + $script:NUnread) file(s) could not be read or parsed and were left alone: check them by hand."; exit 1 }
    Warn "Idunno.AntiCsrf no longer runs in those applications, and neither does its CSRF protection. Replace it with a supported mechanism, delete Idunno.AntiCsrf.dll and the csrfSettings section once no page refers to it, and run 'hunt'. To undo: rollback"
    exit 0
}

# ---------- rollback ---------------------------------------------------------
function Invoke-Rollback {
    Write-Host "$ScriptName $ScriptVersion ($ScriptDate) - rollback on $([Environment]::MachineName) at $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    if ($DryRun) { Write-Host 'DRY RUN: nothing will be written' }
    if (-not $DryRun -and -not (Test-Elevated)) { Fatal 'rollback changes Web.config files: open PowerShell with Run as Administrator, or add -DryRun' }
    $bk = $BackupDir
    if (-not $bk) {
        if (Test-Path -LiteralPath $StateDir -PathType Container) {
            $last = Get-ChildItem -LiteralPath $StateDir -Directory -Filter 'backup-*' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
            if ($last) { $bk = $last.FullName }
        }
    }
    if (-not $bk -or -not (Test-Path -LiteralPath (Join-Path $bk 'manifest.tsv') -PathType Leaf)) { Fatal "no backup to restore under $StateDir (or give -BackupDir)" }
    if (-not $DryRun) { Get-Lock }
    $failed = 0
    Step "Restoring from $bk"
    foreach ($line in (Get-Content -LiteralPath (Join-Path $bk 'manifest.tsv'))) {
        if (-not $line) { continue }
        $parts = $line -split "`t"
        $dst = $parts[0]; $src = Join-Path $bk $parts[1]
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Bad "${dst}: its copy $src is missing"; $failed++; continue }
        if ($DryRun) { Inf "would restore $dst from $src"; continue }
        if (Test-IsLink $dst) { Bad "${dst}: is now a symbolic link: left alone, restore it by hand from $src"; $failed++; continue }
        try {
            Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
            if (-not (Test-ParsesAsXml $dst)) { throw 'the restored file does not parse' }
            Info "restored $dst"
        } catch { Bad "${dst}: could not be restored ($($_.Exception.Message))"; $failed++ }
    }
    Drop-Lock
    Step 'Verdict'
    if ($failed -gt 0) { Warn "$failed file(s) could not be restored (above)."; exit 1 }
    if ($DryRun) { Info 'DRY RUN: nothing was written.' } else { Warn 'Restored: Idunno.AntiCsrf is registered again where it was, and so is the hole. Run check.' }
    exit 0
}

# ---------- main -------------------------------------------------------------
if ($Help -or $Command -eq 'help' -or $Command -eq '-h' -or $Command -eq '--help') {
    $on = $false
    foreach ($line in (Get-Content -LiteralPath $MyInvocation.MyCommand.Path)) {
        if ($line.StartsWith('# Idunno.AntiCsrf unauthenticated', [StringComparison]::Ordinal)) { $on = $true }
        if ($line.StartsWith('# Assisted-by', [StringComparison]::Ordinal)) { break }
        if ($on) { $line -replace '^# ?', '' }
    }
    exit 0
}
switch ($Command) {
    'version' { Write-Host "$ScriptName $ScriptVersion ($ScriptDate)"; exit 0 }
    '--version' { Write-Host "$ScriptName $ScriptVersion ($ScriptDate)"; exit 0 }
    'check' { Invoke-Check }
    'hunt' { Invoke-Hunt }
    'mitigate' { Invoke-Mitigate }
    'rollback' { Invoke-Rollback }
    default { Write-Host "unknown command: $Command (use check, hunt, mitigate, rollback or version)" -ForegroundColor Red; exit 2 }
}
