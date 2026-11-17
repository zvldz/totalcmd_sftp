#requires -Version 5.1
<#
.SYNOPSIS
Builds and runs the unit tests for x64 and x86.

.DESCRIPTION
The tests compile the plugin's own sources for the modules they cover
(PPK converter, text conversion, terminal filter, LAN Pair key, handshake
and session, address and base64 helpers, the session registry, the
OpenSSH, FileZilla and KiTTY importers) against the OpenSSL that
build-deps.ps1 produced, so run that once first. Each test
binary goes to tests\out\<arch>.

.PARAMETER Arch
x64, x86 or both (default).

.PARAMETER Filter
Runs only test cases whose name contains this text.
#>
param(
    [ValidateSet('x64', 'x86', 'both')] [string]$Arch = 'both',
    [string]$Filter
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent

# Production sources exercised by the unit tests, compiled as they are.
$UnitSources = @(
    'src\core\TextConversion.cpp',
    'src\core\PpkConverter.cpp',
    'src\core\TerminalText.cpp',
    'src\core\WildcardMatch.cpp',
    'src\core\PasswordCrypto.cpp',
    'src\core\AuthSecrets.cpp',
    'src\core\Utf8Escape.cpp',
    'src\core\IniFile.cpp',
    'src\core\KittyDecrypt.cpp',
    'src\core\LanPairProtocol.cpp',
    'src\core\LanPair.cpp',
    'src\core\LanPairSession.cpp',
    'src\core\TrustedInstallerToken.cpp',
    'src\core\DllExceptionBarrier.cpp',
    'src\core\CoreUtils.cpp',
    'src\core\UnicodeHelpers.cpp',
    'src\core\ImportIoUtil.cpp',
    'src\core\SecureCrtAdapter.cpp',
    'src\core\VanDykeIniParser.cpp',
    'src\core\OpenSshAdapter.cpp',
    'src\core\FileZillaAdapter.cpp',
    'src\core\KittyAdapter.cpp',
    'src\core\PuttyAdapter.cpp',
    'src\core\ServerRegistry.cpp'
)
$SystemLibs = 'ws2_32.lib comdlg32.lib crypt32.lib advapi32.lib user32.lib bcrypt.lib iphlpapi.lib shell32.lib ole32.lib dbghelp.lib'

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found. Install Visual Studio 2022 or later.' }
$vsPath = & $vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -property installationPath
if (-not $vsPath) { throw 'Visual Studio installation not found.' }
$vsDevCmd = Join-Path $vsPath 'Common7\Tools\VsDevCmd.bat'

$testSources = @(Get-ChildItem (Join-Path $PSScriptRoot 'unit') -Filter '*.cpp' | ForEach-Object { "`"$($_.FullName)`"" })
$prodSources = @($UnitSources | ForEach-Object { "`"$(Join-Path $Root $_)`"" })
# Same language level and warning level as the plugin; global.h is not
# forced in, the tested sources include what they use. WIN32_LEAN_AND_MEAN
# keeps windows.h from pulling in the old winsock.h, as global.h does.
$common = '/nologo /std:c++20 /EHsc /W3 /utf-8 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0601 /MT /O2 /DNDEBUG'
$include = "/I`"$(Join-Path $Root 'src\include')`" /I`"$(Join-Path $PSScriptRoot 'unit')`""

$env:SFTP_TEST_FIXTURES = Join-Path $PSScriptRoot 'fixtures'

$archs = if ($Arch -eq 'both') { @('x64', 'x86') } else { @($Arch) }
$failures = @()
foreach ($a in $archs) {
    $libDir = Join-Path $Root 'src\lib'
    $crypto = Join-Path $libDir "libcrypto_$a.lib"
    $osslInclude = Join-Path $libDir "include-$a"
    if (-not (Test-Path $crypto) -or -not (Test-Path $osslInclude)) {
        throw "OpenSSL for $a is not built. Run .\build-deps.ps1 first."
    }

    $out = Join-Path $PSScriptRoot "out\$a"
    if (Test-Path $out) { Remove-Item $out -Recurse -Force }
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    $exe = Join-Path $out 'unit_tests.exe'
    $log = Join-Path $out 'build.log'

    Write-Host "=== unit tests $a ===" -ForegroundColor Cyan
    $cmd = "call `"$vsDevCmd`" -arch=$a -host_arch=x64 -no_logo >nul && cd /d `"$out`" && " +
           "cl $common $include /I`"$osslInclude`" $($testSources -join ' ') $($prodSources -join ' ') " +
           "/Fe:`"$exe`" /Fo:`"$out\\`" /link `"$crypto`" $SystemLibs"
    cmd /c $cmd *> $log
    if ($LASTEXITCODE -ne 0) {
        Get-Content $log -Tail 30 | ForEach-Object { Write-Host "    $_" }
        $failures += "$a (build)"
        continue
    }

    [string[]]$testArgs = if ($Filter) { $Filter } else { @() } # an array: a string would splat letter by letter
    & $exe @testArgs | ForEach-Object { Write-Host "    $_" }
    if ($LASTEXITCODE -ne 0) { $failures += $a }
}

if ($failures.Count) {
    Write-Host "UNIT TESTS FAILED: $($failures -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host 'UNIT TESTS PASSED' -ForegroundColor Green
