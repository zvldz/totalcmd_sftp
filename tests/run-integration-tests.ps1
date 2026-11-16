#requires -Version 5.1
<#
.SYNOPSIS
Runs the built plugin against a real SSH server in every transfer mode.

.DESCRIPTION
The harness (tests\integration\PluginHarness.cpp) loads
build\bin\<arch>_Release\sftpplug.wfx and drives it through the Fs* exports
Total Commander uses. Each mode runs as its own session in a temporary
sftpplug.ini, so nothing of the user's own configuration is read or written.

By default the servers are the Docker bench in tools\ssh-test, started here
(keys are generated on first use):
  127.0.0.1:2222  OpenSSH with the "sftp" subsystem
  127.0.0.1:2223  the same without it, reached through sftpservercommand

Everything a run creates on the server lives in one directory under
-RemoteBase, and only that directory is removed.

.PARAMETER Modes
sftp, scp, scponly, shell, text, text-scp, text-scponly, nosub, nosub-bad,
postcmd, key-utf8, key-cp1251, classic-gate (default: all).
  text*      text mode (CRLF <-> LF) over SFTP, SCP and SCP-only
  nosub      SFTP through sftpservercommand; the server is restarted
             mid-run and the session has to reconnect through the command
  nosub-bad  a wrong sftpservercommand: fails, and without hanging
  postcmd    a post-login command printing a Cyrillic word: whole in the log
  classic-gate  a PHP Agent session pointed at the SSH bench: the classic
             build (bin\SFTPplug.zip, the one tested) refuses it rather
             than connecting over SSH
  key-*      a key whose passphrase is a Cyrillic word, stored as UTF-8 or
             as cp1251 bytes; the second only means something where the
             ANSI code page is 1251

.EXAMPLE
.\tests\run-integration-tests.ps1
.\tests\run-integration-tests.ps1 -Arch x64 -Modes sftp,nosub
#>
param(
    [ValidateSet('x64', 'x86', 'both')] [string]$Arch = 'both',
    [string[]]$Modes = @('sftp', 'scp', 'scponly', 'shell', 'text', 'text-scp', 'text-scponly', 'nosub', 'nosub-bad', 'postcmd', 'key-utf8', 'key-cp1251', 'classic-gate'),
    [string]$RemoteBase = '/tmp',
    [switch]$VerboseLog
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
$Bench = Join-Path $Root 'tools\ssh-test'
$KeyFile = Join-Path $Bench 'keys\id_ed25519'
# Both protected with the same Cyrillic word, one as UTF-8, one as cp1251.
$KeyFileUtf8 = Join-Path $Bench 'keys\id_ed25519_utf8'
$KeyFileCp1251 = Join-Path $Bench 'keys\id_ed25519_cp1251'

$Modes = @($Modes | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$knownModes = 'sftp', 'scp', 'scponly', 'shell', 'text', 'text-scp', 'text-scponly', 'nosub', 'nosub-bad', 'postcmd', 'key-utf8', 'key-cp1251', 'classic-gate'
foreach ($m in $Modes) { if ($m -notin $knownModes) { throw "Unknown mode '$m'. Known: $($knownModes -join ', ')" } }

# ---------------------------------------------------------------------------
# Test servers
# ---------------------------------------------------------------------------
Push-Location $Bench
try {
    docker compose build 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Building tools\ssh-test failed. Is Docker running?' }
    # A missing key means a new set: the servers read authorized_keys only
    # when they start, so they are recreated after it.
    $recreate = @()
    if (@($KeyFile, $KeyFileUtf8, $KeyFileCp1251 | Where-Object { -not (Test-Path $_) }).Count) {
        docker compose run --rm ssh gen-keys
        if ($LASTEXITCODE -ne 0) { throw 'Generating the test keys failed.' }
        $recreate = @('--force-recreate')
    }
    docker compose up -d @recreate 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Starting tools\ssh-test failed.' }
} finally {
    Pop-Location
}

# ---------------------------------------------------------------------------
# Sessions, one per mode
# ---------------------------------------------------------------------------
# A Cyrillic word for the post-login command, built from code points so the
# script stays ASCII, which Windows PowerShell would read as ANSI.
$Privet = -join [char[]](0x43F, 0x440, 0x438, 0x432, 0x435, 0x442)
$env:SFTP_IT_POSTCMD_EXPECT = $Privet
# The nosub mode restarts its server mid-run.
$env:SFTP_IT_RESTART_CMD = "docker compose -f `"$(Join-Path $Bench 'docker-compose.yml')`" restart ssh-nosub"

$base = [ordered]@{ server = '127.0.0.1:2222'; user = 'tester'; privkeyfile = $KeyFile; transfermode = '0'; utf8 = '1' }
$overrides = @{
    sftp    = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0' }
    scp     = @{ scpfordata = '1'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0' }
    scponly = @{ scpfordata = '1'; scponly = '1'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0' }
    shell   = @{ scpfordata = '1'; scponly = '1'; shelltransfer = '1'; shelltransferforce = '1'; unixlinebreaks = '0' }
    text    = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '1' }
    nosub   = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                 server = '127.0.0.1:2223'; sftpservercommand = '/usr/lib/openssh/sftp-server' }
    'text-scp'     = @{ scpfordata = '1'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '1' }
    'text-scponly' = @{ scpfordata = '1'; scponly = '1'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '1' }
    'nosub-bad'    = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                        server = '127.0.0.1:2223'; sftpservercommand = '/nonexistent/sftp-server' }
    postcmd        = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                        sendcommand = "echo $Privet" }
    'classic-gate' = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                        transfermode = '1' }
    'key-utf8'   = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                      privkeyfile = $KeyFileUtf8 }
    'key-cp1251' = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                      privkeyfile = $KeyFileCp1251 }
}
# The passphrase is typed the same way for both keys; the plugin has to
# find the bytes the key was protected with. Built from code points so the
# script stays ASCII, which Windows PowerShell would read as ANSI.
$env:SFTP_IT_PASSPHRASE = -join [char[]](0x43F, 0x430, 0x440, 0x43E, 0x43B, 0x44C)

$iniDir = Join-Path ([System.IO.Path]::GetTempPath()) "sftpplug-it-ini-$PID"
New-Item -ItemType Directory -Path $iniDir -Force | Out-Null
$ini = [System.Text.StringBuilder]::new()
foreach ($mode in $Modes) {
    [void]$ini.AppendLine("[it-$mode]")
    foreach ($key in $base.Keys) {
        if (-not $overrides[$mode].ContainsKey($key)) { [void]$ini.AppendLine("$key=$($base[$key])") }
    }
    foreach ($key in $overrides[$mode].Keys) { [void]$ini.AppendLine("$key=$($overrides[$mode][$key])") }
    [void]$ini.AppendLine()
}
[System.IO.File]::WriteAllText((Join-Path $iniDir 'sftpplug.ini'), $ini.ToString(), [System.Text.UTF8Encoding]::new($false))

# ---------------------------------------------------------------------------
# Build the harness and run every mode
# ---------------------------------------------------------------------------
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found. Install Visual Studio 2022 or later.' }
$vsPath = & $vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -property installationPath
if (-not $vsPath) { throw 'Visual Studio installation not found.' }
$vsDevCmd = Join-Path $vsPath 'Common7\Tools\VsDevCmd.bat'

# The bench's host keys change with every container, and each run starts
# from an empty ini, so the first-connection prompt is always accepted.
$env:SFTP_IT_ACCEPT_NEW_HOSTKEY = '1'
$env:SFTP_IT_VERBOSE = if ($VerboseLog) { '1' } else { '0' }

$archs = if ($Arch -eq 'both') { @('x64', 'x86') } else { @($Arch) }
$failures = @()
try {
    # The plugin under test is the one that ships: unpacked from the zip
    # build.ps1 makes, language files included.
    $zip = Join-Path $Root 'bin\SFTPplug.zip'
    if (-not (Test-Path $zip)) { throw "$zip not found. Run .\build.ps1 first." }
    $pluginDir = Join-Path $iniDir 'plugin'
    Expand-Archive -LiteralPath $zip -DestinationPath $pluginDir -Force

    foreach ($a in $archs) {
        $plugin = Join-Path $pluginDir $(if ($a -eq 'x64') { 'SFTPplug.wfx64' } else { 'SFTPplug.wfx' })

        $out = Join-Path $PSScriptRoot "out\integration-$a"
        if (Test-Path $out) { Remove-Item $out -Recurse -Force }
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $exe = Join-Path $out 'plugin_harness.exe'
        $log = Join-Path $out 'build.log'
        $source = Join-Path $PSScriptRoot 'integration\PluginHarness.cpp'
        $cmd = "call `"$vsDevCmd`" -arch=$a -host_arch=x64 -no_logo >nul && cd /d `"$out`" && " +
               "cl /nologo /std:c++20 /EHsc /W3 /utf-8 /MT /O2 /DUNICODE /D_UNICODE " +
               "/I`"$(Join-Path $Root 'src\include')`" `"$source`" /Fe:`"$exe`""
        cmd /c $cmd *> $log
        if ($LASTEXITCODE -ne 0) {
            Get-Content $log -Tail 30 | ForEach-Object { Write-Host "    $_" }
            $failures += "$a (build)"
            continue
        }

        foreach ($mode in $Modes) {
            Write-Host "=== $a / $mode ===" -ForegroundColor Cyan
            & $exe $plugin $iniDir "it-$mode" $RemoteBase $mode
            if ($LASTEXITCODE -ne 0) { $failures += "$a/$mode" }
        }
    }
} finally {
    Remove-Item -LiteralPath $iniDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count) {
    Write-Host "INTEGRATION TESTS FAILED: $($failures -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host 'INTEGRATION TESTS PASSED' -ForegroundColor Green
