#requires -Version 5.1
<#
.SYNOPSIS
Checks the built packages: what is in them and how their plugin files are
built.

.DESCRIPTION
Reads bin\SFTPplug.zip (classic) and bin\SFTPplug-extra.zip (extra), as
build.ps1 leaves them, and checks:
  - the entries: the two plugin files, pluginst.inf, the help page, the
    template, readme.txt and every language file, sftp.php in the extra
    package only, and nothing else;
  - SFTPplug.wfx64 is x64 and SFTPplug.wfx is x86;
  - each plugin file is built with ASLR, DEP and Control Flow Guard (and
    high-entropy ASLR on x64), exports every Fs* function of sftpplug.def,
    and loads only system DLLs (no C runtime DLL: it is linked in).
Exits with 1 and lists the problems if there are any.
#>
$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
Add-Type -AssemblyName System.IO.Compression.FileSystem

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found. Install Visual Studio 2022 or later.' }
$vsPath = & $vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -property installationPath
$dumpbin = Get-ChildItem (Join-Path $vsPath 'VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe') |
           Sort-Object FullName | Select-Object -Last 1
if (-not $dumpbin) { throw 'dumpbin.exe not found in the Visual Studio installation.' }

$exports = @(Get-Content (Join-Path $Root 'build\sftpplug.def') |
             ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne 'EXPORTS' })
$systemDlls = 'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll', 'ole32.dll',
              'comdlg32.dll', 'comctl32.dll', 'crypt32.dll', 'bcrypt.dll', 'ws2_32.dll', 'iphlpapi.dll',
              'winhttp.dll', 'uxtheme.dll', 'dwmapi.dll', 'dbghelp.dll', 'version.dll'
$languages = @(Get-ChildItem (Join-Path $Root 'src\res\language') -Filter '*.lng' | ForEach-Object { "language/$($_.Name)" })
$common = @('SFTPplug.wfx', 'SFTPplug.wfx64', 'pluginst.inf', 'SFTPplug-help.html', 'sftpplug.tpl', 'readme.txt') + $languages

$problems = @()
$work = Join-Path ([System.IO.Path]::GetTempPath()) "sftpplug-package-$PID"
foreach ($package in @(@{ Zip = 'SFTPplug.zip'; Extra = $false }, @{ Zip = 'SFTPplug-extra.zip'; Extra = $true })) {
    $zipPath = Join-Path $Root "bin\$($package.Zip)"
    if (-not (Test-Path $zipPath)) { $problems += "$($package.Zip): not built"; continue }

    $expected = $common + $(if ($package.Extra) { @('sftp.php') } else { @() })
    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        $entries = @($zip.Entries | ForEach-Object { $_.FullName })
        foreach ($name in $expected) {
            if ($entries -cnotcontains $name) { $problems += "$($package.Zip): $name is missing" }
        }
        foreach ($name in $entries) {
            if ($expected -cnotcontains $name) { $problems += "$($package.Zip): $name is not expected" }
        }

        if (Test-Path $work) { Remove-Item $work -Recurse -Force }
        New-Item -ItemType Directory -Path $work | Out-Null
        foreach ($plugin in @(@{ Name = 'SFTPplug.wfx64'; Machine = 'x64' }, @{ Name = 'SFTPplug.wfx'; Machine = 'x86' })) {
            $entry = $zip.GetEntry($plugin.Name)
            if (-not $entry) { continue }
            $file = Join-Path $work $plugin.Name
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $file)
            $where = "$($package.Zip) $($plugin.Name)"

            $headers = (& $dumpbin.FullName /nologo /headers $file) -join "`n"
            if ($headers -notmatch "machine \($($plugin.Machine)\)") { $problems += "${where}: not $($plugin.Machine)" }
            $flags = @('Dynamic base', 'NX compatible', 'Control Flow Guard')
            if ($plugin.Machine -eq 'x64') { $flags += 'High Entropy Virtual Addresses' }
            foreach ($flag in $flags) {
                if ($headers -notmatch [regex]::Escape($flag)) { $problems += "${where}: built without $flag" }
            }

            $exported = @(& $dumpbin.FullName /nologo /exports $file |
                          Where-Object { $_ -match '^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(\w+)' } |
                          ForEach-Object { $Matches[1] })
            foreach ($name in $exports) {
                if ($exported -cnotcontains $name) { $problems += "${where}: $name is not exported" }
            }

            $dlls = @(& $dumpbin.FullName /nologo /dependents $file |
                      Where-Object { $_ -match '^\s+(\S+\.dll)\s*$' } | ForEach-Object { $Matches[1].ToLowerInvariant() })
            if ($dlls.Count -eq 0) { $problems += "${where}: no DLL dependencies read" }
            foreach ($dll in $dlls) {
                if ($systemDlls -notcontains $dll) { $problems += "${where}: loads $dll" }
            }
        }
    } finally {
        $zip.Dispose()
        if (Test-Path $work) { Remove-Item $work -Recurse -Force }
    }
}

if ($problems.Count) {
    $problems | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    Write-Host "$($problems.Count) package problem(s)" -ForegroundColor Red
    exit 1
}
Write-Host "Packages: classic and extra, entries, architecture, hardening, $($exports.Count) exports and system DLLs only"
