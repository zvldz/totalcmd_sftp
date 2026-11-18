#requires -Version 5.1
<#
.SYNOPSIS
Prints the cache key of the dependency build (OpenSSL, libssh2): what
build-deps.ps1 puts into src\lib.

.DESCRIPTION
The key names everything the libraries are built from, so a cached copy is
the one a fresh build would make: the OpenSSL and libssh2 commits the
submodules point at, build-deps.ps1 and the patches it applies, the MSVC
tools version (the newest under Visual Studio, as build.ps1 picks it) and
the NASM version. The release and the cache workflows both call this, so
they agree on the key.
#>
$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent

$parts = [System.Collections.Generic.List[string]]::new()
foreach ($module in 'thirdparty/openssl', 'thirdparty/libssh2') {
    $commit = git -C $Root rev-parse "HEAD:$module"
    if ($LASTEXITCODE -ne 0 -or -not $commit) { throw "No submodule commit for $module" }
    $parts.Add("$module=$commit")
}

$files = @(Get-Item (Join-Path $Root 'build-deps.ps1')) +
         @(Get-ChildItem (Join-Path $Root 'thirdparty\patches') -Recurse -File | Sort-Object FullName)
foreach ($file in $files) {
    $relative = $file.FullName.Substring($Root.Length + 1).Replace('\', '/')
    $parts.Add("$relative=$((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash)")
}

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = & $vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -property installationPath
$msvc = Get-ChildItem (Join-Path $vsPath 'VC\Tools\MSVC') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name
if (-not $msvc) { throw 'MSVC tools not found' }

# Where build-deps.ps1 looks for it, in its order.
$nasmExe = @((Join-Path $env:LOCALAPPDATA 'bin\NASM\nasm.exe'), (Join-Path $env:ProgramFiles 'NASM\nasm.exe'),
             (Get-Command nasm.exe -ErrorAction SilentlyContinue).Source) |
           Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $nasmExe) { throw 'nasm.exe not found' }
$nasm = ((& $nasmExe -v) -split ' ')[2]

$digest = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes(($parts -join "`n")))
$hash = -join ($digest[0..11] | ForEach-Object { $_.ToString('x2') })
Write-Output "deps-msvc$msvc-nasm$nasm-$hash"
exit 0
