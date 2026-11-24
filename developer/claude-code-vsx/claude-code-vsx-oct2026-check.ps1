# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PrivacySafe Security Patches: Claude Code extension backdoor, Windows check  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Claude Code extension SSH backdoor (Cursor marketplace, 29 October 2026): check
# No CVE (supply-chain compromise of an editor extension)
#
# The rest of this collection is for GNU/Linux. This is the Windows companion to
# claude-code-vsx-oct2026-check.sh, which covers GNU/Linux and macOS. It is read only:
# it changes nothing. It looks for what the tampered Claude Code extension (2.1.312 and
# 2.1.313, served from Cursor's marketplace between about 2:27am and 1:35pm Pacific on
# 29 October 2026) leaves on Windows:
#
#   - the extension folder, judged by what is inside extension.js (the real 2.1.312
#     exists, so the version number alone is not enough), and cached extension packages
#   - the attacker's SSH key in each profile's .ssh\authorized_keys and in
#     C:\ProgramData\ssh\administrators_authorized_keys, found by its key text, its
#     comment and its fingerprint, in UTF-8 or UTF-16 files, and when it shares a line
#     with a real key
#   - %USERPROFILE%\.config\smt.cmd and smtk, the .stk_ key copies in the temp folders
#     (and one level below, where Remote Desktop sessions keep theirs), and the Startup
#     entry sysmon.cmd
#   - a scheduled task named SysMon that runs the implant
#   - running tunnel processes, and any connection to the attacker's address
#   - whether an SSH server answers on 127.0.0.1, which is where the tunnel arrives
#
# Usage (PowerShell, no administrator rights needed to check your own account):
#   powershell -ExecutionPolicy Bypass -File .\claude-code-vsx-oct2026-check.ps1
#   powershell -ExecutionPolicy Bypass -File .\claude-code-vsx-oct2026-check.ps1 -Command version
#
# Open PowerShell with "Run as Administrator" to check every profile on the machine and
# to read C:\ProgramData\ssh\administrators_authorized_keys. Without it the check says what
# it could not read and does not call the result clean.
#
# Exit code: 0 nothing found, 1 the backdoor or a bad build was found, 2 something could
# not be read or listed, so the result is not a clean one.
#
# To remove what it finds, close every editor and run Cursor's remediate-windows.ps1 as
# Administrator (see the link printed at the end). That script cleans each profile's
# authorized_keys but not C:\ProgramData\ssh\administrators_authorized_keys: if this check
# flags that file, take the attacker's key out of it yourself, keeping any other key.
#
# Options:
#   -Homes C:\Users\a,C:\Users\b     profile folders to check (default: yours; as
#                                    Administrator: every profile)
#   -TempDirs D:\tmp                 more folders to search for .stk_ key copies
#   -ExtensionRoots D:\ide\extensions  more folders that hold extensions
#   -AdminKeysFile <path>            the machine-wide key file to check
#   -ExtraKeyBlobs, -ExtraFingerprints, -ExtraSha256   more indicators, for when the
#                                    vendors publish updates
#   -LoopbackPort 22                 port to probe on 127.0.0.1
#
# Works with Windows PowerShell 5.1 and PowerShell 7. Plain ASCII on purpose.
#
# Assisted-by: Claude Sonnet 5.5
# =============================================================================
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = 'check',
    [string[]]$Homes = @(),
    [string[]]$TempDirs = @(),
    [string[]]$ExtensionRoots = @(),
    [string]$AdminKeysFile = '',
    [string[]]$ExtraKeyBlobs = @(),
    [string[]]$ExtraFingerprints = @(),
    [string[]]$ExtraSha256 = @(),
    [int]$LoopbackPort = 22,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$ScriptName = 'claude-code-vsx-oct2026-check.ps1'
$ScriptVersion = '1.0.0'
$ScriptDate = '2026-10-30'
$Ref = 'https://cursor.com/blog/claude-code-extension-security-notice'
$FixedVer = '2.1.314'

# ---------- indicators (Cursor and Phorion, 29 and 30 October 2026) ----------
$C2Ip = '134.209.82.225'
$KeyBlobs = @('AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P') + @($ExtraKeyBlobs)
# fingerprint of the key planted in authorized_keys, and of the tunnel key
$Fprs = @('SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk', 'SHA256:KOAU57+ZG6u3MG4WwzPzPX2O5YEe9qdOC1Bl+6MVyDQ') + @($ExtraFingerprints)
# the backdoored extension.js
$JsSha256 = @('ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15') + @($ExtraSha256)
# the backdoored packages (2.1.312 and 2.1.313; darwin-arm64 and win32-x64). The last one is a
# darwin-arm64 package that one secondary report lists and Cursor's own list does not; a wrong
# hash can never match a good file.
$VsixSha256 = @(
    'fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364',
    '3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081',
    '80402fdcad8799285fd93044976973ca000da7995fb93363f819bb8e4f84ee6c',
    '6786ec90cbd45949695bd7805c9fbb26cfc91bc5fc897de0183d9bcb9cb21731',
    '432ccdee3801f99e52b8fe31f69ea9870118e96ea7ef9ecabed1479621b5ab62'
) + @($ExtraSha256)
# processes the implant runs: the tunnel loops pass a key file to ssh -i, and the task and the Startup entry run smt.cmd
$ProcRegex = '\\\.stk_[0-9a-f]{10}|\\\.config\\smt(k|\.cmd)|\\Startup\\sysmon\.cmd'
# what a scheduled task that runs the implant looks like
$TaskRegex = '\\\.config\\smt(k|\.cmd)|\\Startup\\sysmon\.cmd|\\\.stk_[0-9a-f]{10}'

# ---------- counters and output ----------------------------------------------
$script:NComp = 0       # signs that the backdoor ran here
$script:NExposed = 0    # a bad extension build is on disk
$script:NUnread = 0     # something could not be read or listed
$script:NReview = 0     # looks related, needs a look by hand
$script:AdminKeyHit = $false
$script:LoopbackOpen = $false
$script:KeyShared = $false

function Say([string]$m) { Write-Host $m }
function Step([string]$m) { Write-Host ''; Write-Host "===== $m =====" -ForegroundColor Cyan }
function Info([string]$m) { Write-Host "[+] $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Ok([string]$m) { Write-Host "  [ok]  $m" -ForegroundColor Green }
function Bad([string]$m) { Write-Host "  [BAD] $m" -ForegroundColor Red }
function Caution([string]$m) { Write-Host "  [!]   $m" -ForegroundColor Yellow }
function Inf([string]$m) { Write-Host "  [.]   $m" }
function Unread([string]$m) { $script:NUnread++; Caution $m }

$Latin1 = [Text.Encoding]::GetEncoding(28591)

# A path built one segment at a time, so it is right on Windows and testable anywhere else.
function Join-Segments([string]$base, [string[]]$parts) {
    foreach ($x in $parts) { $base = Join-Path $base $x }
    return $base
}

# ---------- helpers ----------------------------------------------------------
function Test-Elevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Read-Bytes([string]$path) {
    try { return , [IO.File]::ReadAllBytes($path) }
    catch { Unread "cannot read ${path}: $($_.Exception.Message)"; return $null }
}

# The bytes of a file as plain text. Latin-1 maps every byte to one character, and dropping
# the NUL bytes turns UTF-16 text into ASCII, so one search finds the key in a UTF-8 file, a
# UTF-16 file, or a file that is both (a UTF-16 file the attacker appended UTF-8 to).
function ConvertTo-PlainText([byte[]]$bytes) {
    $t = $Latin1.GetString($bytes).Replace([string][char]0, '')
    $bom = @([string][char]0xFF + [string][char]0xFE, [string][char]0xFE + [string][char]0xFF, [string][char]0xEF + [string][char]0xBB + [string][char]0xBF)
    foreach ($b in $bom) { if ($t.StartsWith($b, [StringComparison]::Ordinal)) { $t = $t.Substring($b.Length); break } }
    return $t
}

function Get-Sha256Of([string]$path) {
    try { return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { return '' }
}

$KeyRegex = [regex]'(?:^|\s)(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+(AAAA[0-9A-Za-z+/]+={0,3})'
$AnyKeyRegex = [regex]'(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+AAAA'

function Get-BlobFingerprint([string]$b64) {
    try {
        $raw = [Convert]::FromBase64String($b64)
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return 'SHA256:' + ([Convert]::ToBase64String($sha.ComputeHash($raw))).TrimEnd('=') }
        finally { $sha.Dispose() }
    } catch { return '' }
}
function Get-LineFingerprint([string]$t) {
    $m = $KeyRegex.Match($t)
    if ($m.Success) { return (Get-BlobFingerprint $m.Groups[2].Value) }
    return ''
}

# why a line of authorized_keys is the attacker's key, or '' when it is not
function Test-IocLine([string]$t) {
    if ($t.Contains('svc-telemetry')) { return 'it carries the svc-telemetry comment' }
    foreach ($b in $KeyBlobs) { if ($b -and $t.Contains($b)) { return 'it holds the attacker key text' } }
    $fp = Get-LineFingerprint $t
    if ($fp -and ($Fprs -contains $fp)) { return 'its fingerprint is a published indicator' }
    return ''
}

# The planted key is appended without a newline, so it can share a line with a real key.
function Test-SharedLine([string]$t) {
    foreach ($b in $KeyBlobs) {
        if (-not $b) { continue }
        $i = $t.IndexOf(('ssh-ed25519 ' + $b), [StringComparison]::Ordinal)
        if ($i -gt 0 -and $AnyKeyRegex.IsMatch($t.Substring(0, $i))) { return $true }
    }
    return $false
}

function Get-FileFingerprint([string]$path) {
    $kg = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if (-not $kg) { return '' }
    try {
        $out = & $kg.Source -l -f $path 2>$null
        if ($out) { $parts = ("$out" -split '\s+'); if ($parts.Count -ge 2) { return $parts[1] } }
    } catch { }
    return ''
}

function Get-ProfileFolders {
    if (@($Homes).Count -gt 0) { return @($Homes) }
    $own = $env:USERPROFILE
    if (-not $own) { $own = $HOME }
    if ((Test-Elevated) -and (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        try {
            $all = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath } | ForEach-Object { $_.LocalPath })
            if ($all.Count -gt 0) { return $all }
        } catch { }
    }
    return @($own)
}

# ---------- scan: editor extensions ------------------------------------------
# Folders look like anthropic.claude-code-2.1.313-win32-x64 (VS Code family) or anthropic.claude-code@2.1.313 (Theia).
function Get-ExtensionRootList([string]$profDir) {
    $roots = @()
    try {
        foreach ($d in @(Get-ChildItem -LiteralPath $profDir -Directory -Force -Filter '.*' -ErrorAction Stop)) {
            $e = Join-Path $d.FullName 'extensions'
            if (Test-Path -LiteralPath $e -PathType Container) { $roots += $e }
        }
    } catch { }
    foreach ($e in @($ExtensionRoots)) { if ($e -and (Test-Path -LiteralPath $e -PathType Container)) { $roots += $e } }
    return $roots
}

function Scan-Extensions([string]$profDir) {
    $found = 0
    foreach ($root in @(Get-ExtensionRootList $profDir | Select-Object -Unique)) {
        foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
            $l = $d.Name.ToLowerInvariant()
            if ($l.StartsWith('anthropic.claude-code-', [StringComparison]::Ordinal)) { $rest = $l.Substring('anthropic.claude-code-'.Length) }
            elseif ($l.StartsWith('anthropic.claude-code@', [StringComparison]::Ordinal)) { $rest = $l.Substring('anthropic.claude-code@'.Length) }
            else { continue }
            $found++
            $ver = ($rest -split '-')[0]
            $hit = ''; $jsOk = $false
            foreach ($f in @(Get-ChildItem -LiteralPath $d.FullName -Recurse -Depth 2 -Filter extension.js -File -Force -ErrorAction SilentlyContinue)) {
                $bytes = Read-Bytes $f.FullName
                if ($null -eq $bytes) { continue }
                $jsOk = $true
                $sha = Get-Sha256Of $f.FullName
                $txt = $Latin1.GetString($bytes)
                if ($sha -and ($JsSha256 -contains $sha)) { $hit = 'extension.js has the known backdoored SHA-256'; break }
                if ($txt.Contains($C2Ip)) { $hit = "extension.js contains the C2 address $C2Ip"; break }
                if ($txt.Contains('svc-telemetry')) { $hit = 'extension.js contains the svc-telemetry key comment'; break }
            }
            if ($hit) {
                Bad "backdoored extension: $($d.FullName) ($hit)"
                $script:NExposed++
            } elseif ($ver -eq '2.1.313') {
                Bad "version 2.1.313 is on disk: $($d.FullName) (never a legitimate release; Cursor lists it as malicious)"
                $script:NExposed++
            } elseif ($ver -eq '2.1.312') {
                if ($jsOk) {
                    Inf "version 2.1.312: $($d.FullName); its extension.js has none of the indicators (a legitimate 2.1.312 exists on npm and Open VSX, only Cursor's marketplace copy was modified)"
                } else {
                    Caution "version 2.1.312 with no readable extension.js: $($d.FullName); cannot tell the legitimate build from the modified one"
                    $script:NReview++
                }
            } else {
                Ok "Claude Code $ver in $($d.FullName): not an affected version"
            }
        }
    }
    if ($found -eq 0) { Inf "no Claude Code extension folders under $profDir" }
}

# ---------- scan: downloaded or cached extension packages --------------------
function Scan-Packages([string]$profDir) {
    $dirs = @()
    $roaming = Join-Segments $profDir @('AppData', 'Roaming')
    if (Test-Path -LiteralPath $roaming -PathType Container) {
        foreach ($e in @(Get-ChildItem -LiteralPath $roaming -Directory -Force -ErrorAction SilentlyContinue)) {
            $c = Join-Path $e.FullName 'CachedExtensionVSIXs'
            if (Test-Path -LiteralPath $c -PathType Container) { $dirs += $c }
        }
    }
    $dl = Join-Path $profDir 'Downloads'
    if (Test-Path -LiteralPath $dl -PathType Container) { $dirs += $dl }
    foreach ($d in $dirs) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -Depth 1 -File -Force -Filter '*claude-code*' -ErrorAction SilentlyContinue)) {
            $sha = Get-Sha256Of $f.FullName
            if ($sha -and ($VsixSha256 -contains $sha)) {
                Bad "extension package with a known bad hash: $($f.FullName)"
                $script:NExposed++
            }
        }
    }
}

# ---------- scan: SSH authorized keys ----------------------------------------
function Scan-KeyFile([string]$path, [bool]$machineWide) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
    $bytes = Read-Bytes $path
    if ($null -eq $bytes) {
        if ($machineWide) { Caution "run PowerShell as Administrator to read $path" }
        return
    }
    $text = ConvertTo-PlainText $bytes
    $n = 0; $badHere = $false
    foreach ($line in ($text -split "`n")) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $n++
        $why = Test-IocLine $t
        if ($why) {
            $badHere = $true
            $shown = $t.Substring(0, [Math]::Min(60, $t.Length))
            Bad "the attacker's key is in ${path}: $shown... ($why)"
            if (Test-SharedLine $t) {
                $script:KeyShared = $true
                Caution "that line also holds another key: the attacker's key was appended without a newline. Take out only the attacker's part and keep the other key (Cursor's remediate-windows.ps1 does that for a profile's authorized_keys)"
            }
        } else {
            $fp = Get-LineFingerprint $t
            $parts = $t -split '\s+'
            $comment = $parts[$parts.Count - 1]
            if ($comment.Length -gt 40) { $comment = $comment.Substring(0, 40) }
            if (-not $fp) { $fp = 'fingerprint unavailable' }
            Inf "key in ${path}: $fp $comment"
        }
    }
    if ($badHere) {
        $script:NComp++
        if ($machineWide) { $script:AdminKeyHit = $true }
    }
    if ($n -eq 0) { Inf "$path has no keys" }
    try {
        if ((Get-Item -LiteralPath $path -Force).LastWriteTime -ge [datetime]'2026-10-29') {
            Caution "$path was modified on or after 29 October 2026: check that every key above is one you added"
        }
    } catch { }
}

# ---------- scan: implant files and persistence ------------------------------
# kind is cmd or key
function Test-ImplantFile([string]$f, [string]$kind) {
    $bytes = Read-Bytes $f
    if ($null -eq $bytes) { return 'unread' }
    if ($kind -eq 'cmd') {
        $txt = $Latin1.GetString($bytes)
        if ($txt.Contains($C2Ip) -or $txt.ToLowerInvariant().Contains('smtk')) { return 'yes' }
        return 'no'
    }
    $fp = Get-FileFingerprint $f
    if ($fp) { if ($Fprs -contains $fp) { return 'yes' } else { return 'no' } }
    $head = $Latin1.GetString($bytes, 0, [Math]::Min(80, $bytes.Length))
    if ($head.Contains('PRIVATE KEY')) { return 'yes' }
    return 'no'
}
function Note-Implant([string]$f, [string]$kind) {
    switch (Test-ImplantFile $f $kind) {
        'yes' { Bad "implant file: $f"; $script:NComp++ }
        'no' { Caution "$f has the implant's name but not its content: review it by hand (left alone)"; $script:NReview++ }
        default { }   # unreadable: already counted
    }
}

function Scan-ImplantsHome([string]$profDir) {
    foreach ($n in @('smt.cmd', '.smt')) { $f = Join-Segments $profDir @('.config', $n); if (Test-Path -LiteralPath $f -PathType Leaf) { Note-Implant $f 'cmd' } }
    foreach ($n in @('smtk', '.smtk')) { $f = Join-Segments $profDir @('.config', $n); if (Test-Path -LiteralPath $f -PathType Leaf) { Note-Implant $f 'key' } }
    $f = Join-Segments $profDir @('AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'sysmon.cmd')
    if (Test-Path -LiteralPath $f -PathType Leaf) { Note-Implant $f 'cmd' }
}

function Get-TempFolderList {
    $dirs = @()
    foreach ($h in @(Get-ProfileFolders)) { $dirs += (Join-Segments $h @('AppData', 'Local', 'Temp')) }
    foreach ($e in @($env:TEMP, $env:TMP, $(if ($env:SystemRoot) { Join-Path $env:SystemRoot 'Temp' } else { '' }))) { if ($e) { $dirs += $e } }
    foreach ($e in @($TempDirs)) { if ($e) { $dirs += $e } }
    return @($dirs | Select-Object -Unique | Where-Object { Test-Path -LiteralPath $_ -PathType Container })
}

# The key copy is .stk_ and ten hex digits. On a Remote Desktop host the temp folder has a numbered folder for each session, so look one level down as well.
function Scan-TempFolders {
    $found = 0
    foreach ($d in (Get-TempFolderList)) {
        $files = @(Get-ChildItem -LiteralPath $d -Filter '.stk_*' -Force -File -ErrorAction SilentlyContinue)
        foreach ($sub in @(Get-ChildItem -LiteralPath $d -Directory -Force -ErrorAction SilentlyContinue)) {
            $files += @(Get-ChildItem -LiteralPath $sub.FullName -Filter '.stk_*' -Force -File -ErrorAction SilentlyContinue)
        }
        foreach ($f in $files) {
            if ($f.Name -match '^\.stk_[0-9a-f]{10}$') { $found++; Note-Implant $f.FullName 'key' }
        }
    }
    if ($found -eq 0) { Ok 'no .stk_ key copy in the temp folders' }
}

function Scan-ScheduledTasks {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { Unread 'scheduled tasks cannot be listed on this system'; return }
    $tasks = $null
    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) } catch { Unread "could not list scheduled tasks: $($_.Exception.Message)"; return }
    $hit = $false
    foreach ($t in $tasks) {
        $text = ''
        try { $text = (@($t.Actions) | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ' } catch { }
        $implant = ($text -match $TaskRegex) -or $text.Contains($C2Ip)
        if ($implant) {
            $hit = $true
            Bad "scheduled task $($t.TaskPath)$($t.TaskName) runs the implant: $text"
            $script:NComp++
        } elseif ($t.TaskName -ieq 'SysMon') {
            $hit = $true
            Caution "a scheduled task named SysMon exists but does not run the implant ($text): review it by hand"
            $script:NReview++
        }
    }
    if (-not $hit) { Ok 'no scheduled task named SysMon, and none runs the implant' }
}

function Scan-Processes {
    if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) { Unread 'could not list processes (no Get-CimInstance)'; return }
    $procs = $null
    try { $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop) } catch { Unread "could not list processes: $($_.Exception.Message)"; return }
    $found = 0
    foreach ($p in $procs) {
        $cl = [string]$p.CommandLine
        if (-not $cl) { continue }
        if ($p.ProcessId -eq $PID -or $cl.Contains($ScriptName)) { continue }
        if ($cl.Contains($C2Ip) -or ($cl -match $ProcRegex)) {
            $found++
            $shown = $cl.Substring(0, [Math]::Min(110, $cl.Length))
            Bad "tunnel or persistence process $($p.ProcessId) ($($p.Name)): $shown"
            $script:NComp++
        }
    }
    if ($found -eq 0) { Ok 'no tunnel or retry-loop process is running' }
}

function Scan-Network {
    $seen = $null
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        try { $seen = (@(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.RemoteAddress -eq $C2Ip })).Count -gt 0 }
        catch { Unread "could not list TCP connections: $($_.Exception.Message)"; return }
    } elseif (Get-Command netstat -ErrorAction SilentlyContinue) {
        try { $seen = ((& netstat -an 2>$null) -join "`n").Contains($C2Ip) } catch { Unread 'netstat failed: cannot look for a connection to the C2'; return }
    } else {
        Unread 'neither Get-NetTCPConnection nor netstat is available: cannot look for a connection to the C2'
        return
    }
    if ($seen) { Bad "a connection to the C2 $C2Ip is open or being retried"; $script:NComp++ }
    else { Ok "no connection to $C2Ip" }
}

# Can something reach an SSH server on the loopback address? That is where the reverse tunnel delivers the attacker. A successful probe sends no data.
function Scan-Loopback {
    $open = $false
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect('127.0.0.1', $LoopbackPort, $null, $null)
        $open = $iar.AsyncWaitHandle.WaitOne(2000, $false) -and $client.Connected
    } catch { $open = $false } finally { $client.Close() }
    if ($open) {
        $script:LoopbackOpen = $true
        Caution "127.0.0.1:$LoopbackPort accepts connections: this machine runs an SSH server. If the key was planted and the tunnel connected, this is the door it opened onto. The payload tries to turn the OpenSSH Server on (it needs administrator rights, which the extension has on few machines): if you did not set this server up yourself, treat it as part of the compromise"
    } else {
        Ok "127.0.0.1:$LoopbackPort is closed: nothing listens there, so a connection forwarded through the tunnel would be refused"
    }
    $sshd = $null
    try { $sshd = Get-Service -Name sshd -ErrorAction Stop } catch { }
    if ($sshd) { Inf "the sshd service exists and is $($sshd.Status) (start type $($sshd.StartType))" }
    if ($env:SystemRoot -and (Test-Path -LiteralPath (Join-Segments $env:SystemRoot @('System32', 'OpenSSH', 'sshd.exe')))) { Inf 'the OpenSSH Server program is installed on this machine' }
}

# ---------- driver -----------------------------------------------------------
function Get-DefaultAdminKeysFile {
    if ($AdminKeysFile) { return $AdminKeysFile }
    $pd = $env:ProgramData
    if (-not $pd) { $pd = 'C:\ProgramData' }
    return (Join-Segments $pd @('ssh', 'administrators_authorized_keys'))
}

function Invoke-Check {
    Say "Claude Code extension backdoor, Windows check $ScriptVersion ($ScriptDate)"
    Say "Cursor's notice: $Ref"
    if (-not (Test-Elevated)) { Inf 'Not running as Administrator: this checks your own account only. Open PowerShell with "Run as Administrator" to check every profile and read C:\ProgramData\ssh.' }
    $profiles = @(Get-ProfileFolders)
    $checked = 0
    foreach ($h in $profiles) {
        if (-not (Test-Path -LiteralPath $h -PathType Container)) { Inf "profile folder does not exist, skipped: $h"; continue }
        try { $null = Get-ChildItem -LiteralPath $h -Force -ErrorAction Stop | Select-Object -First 1 }
        catch { Unread "cannot read ${h}: $($_.Exception.Message)"; continue }
        $checked++
        Step "Account: $h"
        Inf 'editor extensions:'
        Scan-Extensions $h
        Scan-Packages $h
        Inf 'SSH authorized keys:'
        Scan-KeyFile (Join-Segments $h @('.ssh', 'authorized_keys')) $false
        Inf 'implant files and persistence:'
        Scan-ImplantsHome $h
    }
    if ($checked -eq 0) { Write-Host "[-] FATAL: none of the profile folders to check can be read ($($profiles -join ', ')): nothing was checked" -ForegroundColor Red; exit 2 }
    Step 'Machine-wide: administrators_authorized_keys, key copies in temp folders, scheduled tasks'
    Inf 'SSH authorized keys for administrators:'
    Scan-KeyFile (Get-DefaultAdminKeysFile) $true
    Scan-TempFolders
    Scan-ScheduledTasks
    Step 'Running processes and network'
    Scan-Processes
    Scan-Network
    Scan-Loopback
    Show-Verdict
    if ($script:NComp -gt 0 -or $script:NExposed -gt 0) { exit 1 }
    if ($script:NUnread -gt 0) { exit 2 }
    exit 0
}

function Show-Verdict {
    Write-Host ''
    if ($script:NComp -gt 0) {
        Warn "COMPROMISED: $($script:NComp) sign(s) that the backdoor ran on this machine."
        if ($script:LoopbackOpen) { Warn "This machine runs an SSH server, so a login through the tunnel was possible while the C2 was up." }
        Warn "Next: close every editor, then run Cursor's remediate-windows.ps1 from PowerShell opened with Run as Administrator. Then rotate every credential this account could reach, from a different, trusted machine. Updating the extension alone does not remove the backdoor."
        if ($script:AdminKeyHit) { Warn "The attacker's key is in the machine-wide administrators_authorized_keys. Cursor's remediate-windows.ps1 does not clean that file: remove the attacker's key from it yourself, keeping any other key, and check that the OpenSSH Server is one you meant to run." }
    } elseif ($script:NExposed -gt 0) {
        Warn "EXPOSED: a bad extension build is on disk, but no key, implant or tunnel was found. It may never have been loaded, or it may already have been cleaned. Close every editor, delete the folder shown above, and install the extension again from a source you trust."
    } elseif ($script:NUnread -gt 0) {
        Warn "No indicator found, but $($script:NUnread) thing(s) could not be read, so this is not a clean result."
    } else {
        Info 'No indicator of the Claude Code extension backdoor was found.'
    }
    if ($script:NComp -gt 0 -or $script:NExposed -gt 0) {
        Warn "Also install the vendor's fix: Claude Code $FixedVer or newer. Do not stop there: it does not remove the backdoor."
    }
    if ($script:NReview -gt 0) { Warn "$($script:NReview) item(s) look related and need a look by hand (marked above)." }
    Inf "This checks Windows only. On GNU/Linux and macOS use claude-code-vsx-oct2026-check.sh. Cursor's notice and its remediation scripts: $Ref"
}

# ---------- main -------------------------------------------------------------
if ($Help -or $Command -eq 'help') {
    $on = $false
    foreach ($line in (Get-Content -LiteralPath $MyInvocation.MyCommand.Path)) {
        if ($line.StartsWith('# Claude Code extension SSH backdoor', [StringComparison]::Ordinal)) { $on = $true }
        if ($line.StartsWith('# Assisted-by', [StringComparison]::Ordinal)) { break }
        if ($on) { $line -replace '^# ?', '' }
    }
    exit 0
}
switch ($Command) {
    'version' { Write-Host "$ScriptName $ScriptVersion ($ScriptDate)"; exit 0 }
    'check' { Invoke-Check }
    default { Write-Host "unknown command: $Command (use check or version)" -ForegroundColor Red; exit 2 }
}
