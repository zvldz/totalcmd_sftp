#requires -Version 5.1
<#
.SYNOPSIS
Renders every plugin dialog in every language and checks its layout.

.DESCRIPTION
The test executable embeds the plugin's own resources and layout code, so
each dialog is built exactly as the plugin builds it. Failures are clipped
text, overlapping controls and controls outside the dialog; a report and a
PNG of each dialog go to tests\out\ui-<arch>. The result depends on the
DPI of the screen the test runs on.

.PARAMETER Arch
x64 (default), x86 or both.
#>
param([ValidateSet('x64', 'x86', 'both')] [string]$Arch = 'x64')

$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found. Install Visual Studio 2022 or later.' }
$vsPath = & $vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -property installationPath
if (-not $vsPath) { throw 'Visual Studio installation not found.' }
$vsDevCmd = Join-Path $vsPath 'Common7\Tools\VsDevCmd.bat'

$archs = if ($Arch -eq 'both') { @('x64', 'x86') } else { @($Arch) }
$failures = @()
foreach ($a in $archs) {
    $out = Join-Path $PSScriptRoot "out\ui-$a"
    if (Test-Path $out) { Remove-Item $out -Recurse -Force }
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    $exe = Join-Path $out 'dialog_layout_test.exe'
    $res = Join-Path $out 'sftpplug.res'
    $log = Join-Path $out 'build.log'
    $inc = "/I`"$(Join-Path $Root 'src\include')`""

    Write-Host "=== UI layout $a ===" -ForegroundColor Cyan
    $cmd = "call `"$vsDevCmd`" -arch=$a -host_arch=x64 -no_logo >nul && " +
           "cd /d `"$(Join-Path $Root 'src\res')`" && rc /nologo $inc /fo `"$res`" sftpplug.rc && " +
           "cd /d `"$out`" && cl /nologo /std:c++20 /EHsc /W3 /permissive- /utf-8 /MT /O2 /DUNICODE /D_UNICODE $inc " +
           "`"$(Join-Path $PSScriptRoot 'ui\DialogLayoutTest.cpp')`" `"$(Join-Path $Root 'src\core\DialogLayout.cpp')`" `"$res`" " +
           "/Fe:`"$exe`" /link /SUBSYSTEM:CONSOLE /MANIFEST:EMBED /MANIFESTINPUT:`"$(Join-Path $PSScriptRoot 'ui\host.manifest')`" " +
           "user32.lib gdi32.lib dwmapi.lib gdiplus.lib"
    cmd /c $cmd *> $log
    if ($LASTEXITCODE -ne 0) {
        Get-Content $log -Tail 30 | ForEach-Object { Write-Host "    $_" }
        $failures += "$a (build)"
        continue
    }
    & $exe (Join-Path $Root 'src\res\language') $out | Tee-Object -FilePath (Join-Path $out 'report.txt')
    if ($LASTEXITCODE -ne 0) { $failures += $a }
}

if ($failures.Count) {
    Write-Host "UI LAYOUT TESTS FAILED: $($failures -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host 'UI LAYOUT TESTS PASSED' -ForegroundColor Green
