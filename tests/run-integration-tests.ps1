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
  127.0.0.1:2222  OpenSSH with the "sftp" subsystem; also the jump host
  127.0.0.1:2223  the same without it, reached through sftpservercommand
  127.0.0.1:2224  the same, given a new host key by the hostkey mode
  [::1]:2225      the first, over IPv6
  127.0.0.1:1080  SOCKS5 proxy, 1081 the same with a user and password,
                  1082 SOCKS4 and SOCKS4A, 8888 an HTTP CONNECT proxy, 8889
                  the same with a user and password, all in front of the first

Everything a run creates on the server lives in one directory under
-RemoteBase, and only that directory is removed.

.PARAMETER Modes
sftp, scp, scponly, shell, text, text-scp, text-scponly, nosub, nosub-bad,
postcmd, key-utf8, key-cp1251, classic-gate, secrets, pass-store, jump-key,
jump-pass, jump-ref, socks5, socks5-auth, socks4, socks4a, http-proxy,
http-auth, ipv6, hostkey, netfail, php, php74 (default: all).
  text*      text mode (CRLF <-> LF) over SFTP, SCP and SCP-only
  nosub      SFTP through sftpservercommand; the server is restarted
             mid-run and the session has to reconnect through the command
  nosub-bad  a wrong sftpservercommand: fails, and without hanging
  postcmd    a post-login command printing a Cyrillic word: whole in the log
  classic-gate  a PHP Agent session pointed at the SSH bench: the classic
             build (bin\SFTPplug.zip, the one tested) refuses it rather
             than connecting over SSH
  secrets    no server: where passwords end up when sessions are copied in,
             out, renamed and deleted, with an in-memory password manager
  key-*      a key whose passphrase is a Cyrillic word, stored as UTF-8 or
             as cp1251 bytes; the second only means something where the
             ANSI code page is 1251
  pass-store the password kept in Total Commander's password manager ("!")
  jump-*     through the jump host: with a key, with its password in the
             password manager, and named by a reference to another session
             whose password is there
  socks5*, socks4*, http-*  through a proxy; socks5-auth and http-auth with a
             user, its password in the password manager; socks4 names the
             server by its address, socks4a by its name, which the proxy
             resolves
  ipv6       the server named by an IPv6 address, [::1]:2225
  hostkey    the server's host key changes mid-run: the reconnect has to ask
  netfail    no server: a proxy that drops the connection, a proxy name too
             long for its buffer, a server that never answers the handshake,
             a SOCKS5 and an HTTP proxy given a wrong password; each fails,
             and in time
  php, php74 the extra build (bin\SFTPplug-extra.zip) against the PHP Agent
             bench in tools\php-agent-test, PHP 8.3 and PHP 7.4, started here;
             the files go to the agent's root

.EXAMPLE
.\tests\run-integration-tests.ps1
.\tests\run-integration-tests.ps1 -Arch x64 -Modes sftp,nosub
#>
param(
    [ValidateSet('x64', 'x86', 'both')] [string]$Arch = 'both',
    [string[]]$Modes = @('sftp', 'scp', 'scponly', 'shell', 'text', 'text-scp', 'text-scponly', 'nosub', 'nosub-bad', 'postcmd', 'key-utf8', 'key-cp1251', 'classic-gate', 'secrets', 'pass-store', 'jump-key', 'jump-pass', 'jump-ref', 'socks5', 'socks5-auth', 'socks4', 'socks4a', 'http-proxy', 'http-auth', 'ipv6', 'hostkey', 'netfail', 'php', 'php74'),
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
$knownModes = 'sftp', 'scp', 'scponly', 'shell', 'text', 'text-scp', 'text-scponly', 'nosub', 'nosub-bad', 'postcmd', 'key-utf8', 'key-cp1251', 'classic-gate', 'secrets', 'pass-store', 'jump-key', 'jump-pass', 'jump-ref', 'socks5', 'socks5-auth', 'socks4', 'socks4a', 'http-proxy', 'http-auth', 'ipv6', 'hostkey', 'netfail', 'php', 'php74'
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
$PhpBench = Join-Path $Root 'tools\php-agent-test'
if (@($Modes | Where-Object { $_ -like 'php*' }).Count) {
    docker compose -f (Join-Path $PhpBench 'docker-compose.yml') up -d 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Starting tools\php-agent-test failed.' }
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
# The hostkey mode gives its server a new host key and restarts it.
$env:SFTP_IT_HOSTKEY_CMD = "docker compose -f `"$(Join-Path $Bench 'docker-compose.yml')`" exec -T ssh-hk " +
    "sh -c `"rm -f /etc/ssh/ssh_host_* && ssh-keygen -A >/dev/null`" && " +
    "docker compose -f `"$(Join-Path $Bench 'docker-compose.yml')`" restart ssh-hk >nul 2>&1"

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
    secrets      = @{}
    'pass-store' = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                      privkeyfile = ''; password = '!' }
    # The jump host is the bench itself; the target, as the bastion sees it,
    # is its own sshd.
    'jump-key'   = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                      server = '127.0.0.1:22'; usejumphost = '1'; jumphost = '127.0.0.1'; jumpport = '2222'
                      jumpuser = 'tester'; jumpprivkeyfile = $KeyFile }
    'jump-pass'  = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                      server = '127.0.0.1:22'; usejumphost = '1'; jumphost = '127.0.0.1'; jumpport = '2222'
                      jumpuser = 'tester'; jumppassword = '!' }
    'jump-ref'   = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                      server = '127.0.0.1:22'; usejumphost = '1'; jumpsessionref = 'it-bastion' }
    # Through a proxy the target is named as the proxy sees it.
    socks5        = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                       server = 'ssh:22'; proxynr = '1' }
    'socks5-auth' = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                       server = 'ssh:22'; proxynr = '2' }
    'http-proxy'  = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                       server = 'ssh:22'; proxynr = '3' }
    'http-auth'   = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                       server = 'ssh:22'; proxynr = '7' }
    # SOCKS4 carries an address only, SOCKS4A a name the proxy resolves; the
    # proxy reaches the server's own sshd either way.
    socks4        = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                       server = '127.0.0.1:22'; proxynr = '6' }
    socks4a       = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                       server = 'ssh:22'; proxynr = '6' }
    ipv6          = @{ scpfordata = '0'; scponly = '0'; shelltransfer = '0'; shelltransferforce = '0'; unixlinebreaks = '0'
                       server = '[::1]:2225' }
    hostkey       = @{ server = '127.0.0.1:2224' }
    netfail       = @{}
    # PHP Agent: the password is the bench's TC_SFTP_AGENT_PSK.
    php           = @{ server = 'http://127.0.0.1:8083/sftp.php'; transfermode = '1'; privkeyfile = ''
                       password = 'plain:test-psk-change-me' }
    php74         = @{ server = 'http://127.0.0.1:8074/sftp.php'; transfermode = '1'; privkeyfile = ''
                       password = 'plain:test-psk-change-me' }
}
# Passwords kept in Total Commander's password manager, per mode.
$stores = @{
    'pass-store'  = 'it-pass-store=tester'
    'jump-pass'   = 'it-jump-pass$$jump=tester'
    'jump-ref'    = 'it-bastion=tester'
    'socks5-auth' = 'proxy2$$pass=proxypass'
    'http-auth'   = 'proxy7$$pass=proxypass'
    netfail       = 'proxy8$$pass=wrongpass|proxy9$$pass=wrongpass'
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
# The second session a text-mode file is copied to: same server and folder,
# Unix line ends as well.
[void]$ini.AppendLine("[it-copy-target]")
foreach ($key in $base.Keys) { [void]$ini.AppendLine("$key=$($base[$key])") }
[void]$ini.AppendLine("unixlinebreaks=1")
[void]$ini.AppendLine()
# Sessions and proxy records the modes above refer to. Proxy types: 2 HTTP,
# 3 SOCKS4/4A, 4 SOCKS5.
[void]$ini.Append(@"
[it-bastion]
server=127.0.0.1:2222
user=tester
password=!

[it-netfail-close]
server=127.0.0.1:2222
user=tester
privkeyfile=$KeyFile
proxynr=4

[it-netfail-longproxy]
server=127.0.0.1:2222
user=tester
privkeyfile=$KeyFile
proxynr=5

[it-netfail-silent]
server=127.0.0.1:2292
user=tester
privkeyfile=$KeyFile

[it-netfail-socks5pass]
server=ssh:22
user=tester
privkeyfile=$KeyFile
proxynr=8

[it-netfail-httppass]
server=ssh:22
user=tester
privkeyfile=$KeyFile
proxynr=9

[proxy]
proxytype=4
proxyserver=127.0.0.1:1080

[proxy2]
proxytype=4
proxyserver=127.0.0.1:1081
proxyuser=proxyuser
proxypassword=!

[proxy3]
proxytype=2
proxyserver=127.0.0.1:8888

[proxy4]
proxytype=4
proxyserver=127.0.0.1:2291

[proxy5]
proxytype=4
proxyserver=$('p' * 260).example:1080

[proxy6]
proxytype=3
proxyserver=127.0.0.1:1082

[proxy7]
proxytype=2
proxyserver=127.0.0.1:8889
proxyuser=proxyuser
proxypassword=!

[proxy8]
proxytype=4
proxyserver=127.0.0.1:1081
proxyuser=proxyuser
proxypassword=!

[proxy9]
proxytype=2
proxyserver=127.0.0.1:8889
proxyuser=proxyuser
proxypassword=!

"@)
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
    # The PHP Agent modes need the extra build.
    $pluginDirExtra = Join-Path $iniDir 'plugin-extra'
    if (@($Modes | Where-Object { $_ -like 'php*' }).Count) {
        $zipExtra = Join-Path $Root 'bin\SFTPplug-extra.zip'
        if (-not (Test-Path $zipExtra)) { throw "$zipExtra not found. Run .\build.ps1 first." }
        Expand-Archive -LiteralPath $zipExtra -DestinationPath $pluginDirExtra -Force
    }

    foreach ($a in $archs) {
        $wfx = if ($a -eq 'x64') { 'SFTPplug.wfx64' } else { 'SFTPplug.wfx' }

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
            $env:SFTP_IT_STORE = if ($stores.ContainsKey($mode)) { $stores[$mode] } else { '' }
            $isPhp = $mode -like 'php*'
            $plugin = Join-Path $(if ($isPhp) { $pluginDirExtra } else { $pluginDir }) $wfx
            & $exe $plugin $iniDir "it-$mode" $(if ($isPhp) { '/' } else { $RemoteBase }) $mode
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
