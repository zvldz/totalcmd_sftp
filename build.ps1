param(
    [switch]$nohelp,
    [switch]$nodeploy,
    [switch]$nozip,
    [switch]$x64only
)

# ============================================================================
# Configuration
# ============================================================================
$projectName = "SFTPplug"
$projectRoot = $PSScriptRoot
$binDir = Join-Path $projectRoot "bin"
$buildDir = Join-Path $projectRoot "build"
$buildOutputDir    = Join-Path $buildDir "bin\x64_Release"
$buildOutputDirX86 = Join-Path $buildDir "bin\Win32_Release"
$phpAgentSource = Join-Path $projectRoot "src\agent\sftp.php"
$helpBuilder = Join-Path $projectRoot "tools\build-help-page.py"
$helpCompiled = Join-Path $projectRoot "bin\$projectName-help.html"

# Read plugin version from version.h (single source of truth)
$pluginVersion = "0.0.0.0"
$verHPath = Join-Path $projectRoot "src\include\version.h"
if (Test-Path $verHPath) {
    $verHContent = Get-Content $verHPath -Raw
    if ($verHContent -match '#define\s+VER_FILEVERSION_STR\s+"([^"]+)"') {
        $pluginVersion = $matches[1]
    }
}

# ============================================================================
# Helper Functions
# ============================================================================

function Get-TotalCommanderPath {
    <#
    .SYNOPSIS
    Finds Total Commander installation path from registry or default locations.
    #>
    
    # Try HKEY_CURRENT_USER first
    $tcPath = $null
    try {
        $tcKey = Get-ItemProperty -Path "HKCU:\Software\Ghisler\Total Commander" -ErrorAction SilentlyContinue
        if ($tcKey -and $tcKey.InstallDir) {
            $tcPath = $tcKey.InstallDir
            Write-Host "  Found TC in HKCU: $tcPath" -ForegroundColor Gray
        }
    } catch {
        # Ignore
    }
    
    # Try HKEY_LOCAL_MACHINE if not found in HKCU
    if (-not $tcPath) {
        try {
            $tcKey = Get-ItemProperty -Path "HKLM:\Software\Ghisler\Total Commander" -ErrorAction SilentlyContinue
            if ($tcKey -and $tcKey.InstallDir) {
                $tcPath = $tcKey.InstallDir
                Write-Host "  Found TC in HKLM: $tcPath" -ForegroundColor Gray
            }
        } catch {
            # Ignore
        }
    }
    
    # Fallback to default locations
    if (-not $tcPath) {
        $defaultPaths = @(
            "C:\totalcmd",
            "${env:ProgramFiles}\totalcmd",
            "${env:ProgramFiles(x86)}\totalcmd"
        )
        foreach ($path in $defaultPaths) {
            if (Test-Path (Join-Path $path "TOTALCMD64.EXE")) {
                $tcPath = $path
                Write-Host "  Found TC in default location: $tcPath" -ForegroundColor Gray
                break
            }
        }
    }
    
    return $tcPath
}

function Stop-TotalCommander {
    <#
    .SYNOPSIS
    Stops all running Total Commander processes.
    #>
    Write-Host "  Checking for running Total Commander instances..." -ForegroundColor Gray
    
    $tcProcesses = Get-Process -Name "TOTALCMD*", "TOTALCMD64" -ErrorAction SilentlyContinue
    if ($tcProcesses) {
        Write-Host "  Stopping $($tcProcesses.Count) Total Commander process(es)..." -ForegroundColor Yellow
        foreach ($proc in $tcProcesses) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Host "    Stopped: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Gray
            } catch {
                Write-Host "    Failed to stop $($proc.Name): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Start-Sleep -Milliseconds 500  # Wait for processes to fully terminate
    } else {
        Write-Host "  No running Total Commander instances found" -ForegroundColor Gray
    }
}



function Remove-PathSafe {
    param([Parameter(Mandatory = $true)][string]$PathToRemove
    )
    if (-not (Test-Path $PathToRemove)) {
        return $true
    }
    try {
        Remove-Item $PathToRemove -Recurse -Force -ErrorAction Stop
        return $true
    } catch {
        Write-Host "  Warning: could not remove $PathToRemove" -ForegroundColor Yellow
        Write-Host "  $($_.Exception.Message)" -ForegroundColor DarkGray
        return $false
    }
}

function Build-HelpPage {
<#
.SYNOPSIS
Folds src/help/*.html into one self-contained page.

.DESCRIPTION
The help ships as a single HTML file rather than a CHM: hhc.exe is the only
CHM compiler, Microsoft withdrew it, and a CHM carried inside a downloaded ZIP
is blocked by Windows and opens blank. One page also means Ctrl+F searches
every topic at once. The builder needs nothing but Python.
#>
    Write-Host ""
    Write-Host "--- Building Help Page ---" -ForegroundColor Cyan

    if (-not (Test-Path $helpBuilder)) {
        Write-Host "  tools\build-help-page.py not found - help page skipped" -ForegroundColor Yellow
        return $false
    }

    $python = $null
    foreach ($candidate in @('python', 'python3', 'py')) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd) { $python = $cmd.Source; break }
    }
    if (-not $python) {
        Write-Host "  Python not found - help page skipped" -ForegroundColor Yellow
        return $false
    }

    & $python $helpBuilder $helpCompiled
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $helpCompiled)) {
        Write-Host "  Help page build FAILED" -ForegroundColor Red
        return $false
    }

    $sizeKB = [math]::Round((Get-Item $helpCompiled).Length / 1KB)
    Write-Host "  $projectName-help.html ($sizeKB KB)" -ForegroundColor Green
    return $true
}

function Clean-BuildOutput {
    <#
    .SYNOPSIS
    Removes all intermediate build files, leaving only the final wfx.
    #>
    Write-Host "  Cleaning intermediate files..." -ForegroundColor Gray
    
    foreach ($outDir in @($buildOutputDir, $buildOutputDirX86)) {
        if (Test-Path $outDir) {
            Get-ChildItem -Path $outDir | Where-Object {
                $_.Name -notlike "*.wfx" -and $_.Name -notlike "*.pdb"
            } | Remove-Item -Recurse -Force
        }
    }
    $intermediatesDir = Join-Path $buildDir ".intermediates"
    if (Test-Path $intermediatesDir) {
        Remove-Item $intermediatesDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# Main Build Script
# ============================================================================



# The help page needs only Python, so it is built unless explicitly skipped.
$buildHelp = -not $nohelp

Write-Host "--- SFTP Plugin Build Script ---" -ForegroundColor Cyan
Write-Host "Project Root: $projectRoot" -ForegroundColor Gray
Write-Host "Build help page: $($(if ($buildHelp) { 'Yes' } else { 'No' }))" -ForegroundColor Gray
Write-Host ""

# ============================================================================
# Step 1: Find MSBuild
# ============================================================================
Write-Host "--- Finding Visual Studio Build Tools ---" -ForegroundColor Cyan

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Error "vswhere.exe not found. Install Visual Studio 2022 or later."
    exit 1
}

$vsPath = &$vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -property installationPath
if (-not $vsPath) {
    Write-Error "Visual Studio Build Tools not found."
    exit 1
}

$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
$vcToolsRoot = Join-Path $vsPath "VC\Tools\MSVC"

Write-Host "  MSBuild: $msbuild" -ForegroundColor Gray

# Get VC tools version
$vcToolsVersion = $null
if (Test-Path $vcToolsRoot) {
    $vcToolsVersion = Get-ChildItem $vcToolsRoot -Directory |
        Sort-Object Name -Descending |
        Select-Object -First 1 -ExpandProperty Name
    Write-Host "  VC Tools Version: $vcToolsVersion" -ForegroundColor Gray
}

# Validate VC tools version
if ($vcToolsVersion) {
    $minimumVcToolsVersion = [version]"14.44.0.0"
    $currentVcToolsVersion = [version]("$vcToolsVersion.0")
    if ($currentVcToolsVersion -lt $minimumVcToolsVersion) {
        Write-Error "VC tools $vcToolsVersion detected. Version 14.44 or later required."
        exit 1
    }
}

# ============================================================================
# Step 2: Prepare directories
# ============================================================================
Write-Host ""
Write-Host "--- Preparing Build Directories ---" -ForegroundColor Cyan

# Clean only the final artifact, not the whole bin directory.
# Avoids spurious failures when bin/ is held by AV, indexer, or a file monitor —
# those typically lock the folder handle without locking individual files.
$zipPath = Join-Path $binDir "$projectName.zip"
if (Test-Path $zipPath) {
    if (-not (Remove-PathSafe -PathToRemove $zipPath)) {
        Write-Host "  Continuing with existing zip in place" -ForegroundColor Yellow
    }
}
if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}
New-Item -ItemType Directory -Path $binDir -Force | Out-Null

# Clean build output directory
if (-not (Remove-PathSafe -PathToRemove $buildOutputDir)) {
    Write-Host "  Continuing with existing build output" -ForegroundColor Yellow
}

Write-Host "  Directories ready" -ForegroundColor Gray

# ============================================================================
# Step 3: Build
# ============================================================================
$vcxprojPath = Join-Path $buildDir "SFTPplug.vcxproj"
if (-not (Test-Path $vcxprojPath)) {
    Write-Error "Project file not found: $vcxprojPath"
    exit 1
}

# Ensure libssh2 + libcrypto are present. These are not committed to the repo
# (they are ~107 MB of binaries); build-deps.ps1 regenerates them from the
# OpenSSL + libssh2 git submodules under thirdparty/.
$requiredLibs = @('libssh2_x64.lib', 'libcrypto_x64.lib')
if (-not $x64only) {
    $requiredLibs += @('libssh2_x86.lib', 'libcrypto_x86.lib')
}
$missingLibs = $requiredLibs | Where-Object { -not (Test-Path (Join-Path $projectRoot "src\lib\$_")) }
if ($missingLibs) {
    Write-Host ""
    Write-Host "--- Missing dependency libs ---" -ForegroundColor Cyan
    $missingLibs | ForEach-Object { Write-Host "  src\lib\$_" -ForegroundColor Yellow }
    $depsScript = Join-Path $projectRoot "build-deps.ps1"
    if (-not (Test-Path $depsScript)) {
        Write-Error "build-deps.ps1 not found; cannot rebuild missing libs."
        exit 1
    }
    Write-Host "  Invoking build-deps.ps1 (one-time, ~5-10 min)..." -ForegroundColor Gray
    $depsArgs = @()
    if ($x64only) { $depsArgs += '-X64Only' }
    & $depsScript @depsArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "build-deps.ps1 failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
}

$msBuildBase = @(
    $vcxprojPath,
    "/t:Rebuild",
    "/p:Configuration=Release",
    "/p:PlatformToolset=v145",
    "/p:WindowsTargetPlatformVersion=10.0",
    "/p:DebugSymbols=false",
    "/p:DebugType=none",
    "/m",
    "/nologo",
    "/v:m"
)
if ($vcToolsVersion) { $msBuildBase += "/p:VCToolsVersion=$vcToolsVersion" }

# --- x64 ---
Write-Host ""
Write-Host "--- Building Release x64 ---" -ForegroundColor Cyan

$msbuildExitCode = 0
Write-Host "  Building: $vcxprojPath (x64)" -ForegroundColor Gray
&$msbuild ($msBuildBase + @("/p:Platform=x64"))
$msbuildExitCode = $LASTEXITCODE
if ($msbuildExitCode -ne 0) {
    Write-Host "!!! BUILD FAILED (x64) !!!" -ForegroundColor Red
    exit $msbuildExitCode
}
Write-Host "  x64 build completed" -ForegroundColor Green

# --- x86 ---
if (-not $x64only) {
    Write-Host ""
    Write-Host "--- Building Release x86 ---" -ForegroundColor Cyan

    $msbuildExitCode = 0
    Write-Host "  Building: $vcxprojPath (x86)" -ForegroundColor Gray
    &$msbuild ($msBuildBase + @("/p:Platform=Win32"))
    $msbuildExitCode = $LASTEXITCODE
    if ($msbuildExitCode -ne 0) {
        Write-Host "!!! BUILD FAILED (x86) !!!" -ForegroundColor Red
        exit $msbuildExitCode
    }
    Write-Host "  x86 build completed" -ForegroundColor Green
} else {
    Write-Host "  Skipping x86 build (-x64only)" -ForegroundColor Gray
}

# Clean intermediate files
Clean-BuildOutput

# ============================================================================
# Step 4: Build the help page
# ============================================================================
if ($buildHelp) {
    Build-HelpPage | Out-Null
}

# ============================================================================
# Step 5: Create ZIP package (ONLY output in bin\)
# ============================================================================
if (-not $nozip) {
    Write-Host ""
    Write-Host "--- Creating ZIP Package ---" -ForegroundColor Cyan
    
    $zipPath = Join-Path $binDir "$projectName.zip"
    $pluginstInf = @"
[plugininstall]
description=Secure FTP plugin (x64+x86) - static build, no external DLL required
type=wfx
file=$projectName.wfx
file64=$projectName.wfx64
defaultdir=$projectName
version=$pluginVersion
"@

    Add-Type -AssemblyName System.IO.Compression

    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

    $outStream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::Create)
    $zip = [System.IO.Compression.ZipArchive]::new($outStream, [System.IO.Compression.ZipArchiveMode]::Create)

    function Add-ZipFile([string]$src, [string]$entryName) {
        $entry = $zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
        $dst = $entry.Open()
        $fs  = [System.IO.File]::OpenRead($src)
        try   { $fs.CopyTo($dst) }
        finally { $fs.Dispose(); $dst.Dispose() }
    }

    function Add-ZipString([string]$text, [string]$entryName) {
        $entry = $zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
        $dst = $entry.Open()
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($text)
        try   { $dst.Write($bytes, 0, $bytes.Length) }
        finally { $dst.Dispose() }
    }

    try {
        Add-ZipFile  (Join-Path $buildOutputDir    "$projectName.wfx") "$projectName.wfx64"
        Add-ZipFile  (Join-Path $buildOutputDirX86 "$projectName.wfx") "$projectName.wfx"
        # NOTE: sftpplug.pdb is intentionally not packed for release. To ship
        # a diagnostic build that resolves stack frames in C:\temp\sftpplug.log,
        # set LOG_ENABLED=1 in global.h and re-enable PDB inclusion here.
        Add-ZipString $pluginstInf "pluginst.inf"

        if (Test-Path $phpAgentSource) { Add-ZipFile $phpAgentSource "sftp.php" }
        if (Test-Path $helpCompiled)   { Add-ZipFile $helpCompiled   "$projectName-help.html" }

        $tplSource = Join-Path $projectRoot "src\res\sftpplug.tpl"
        if (Test-Path $tplSource)      { Add-ZipFile $tplSource      "sftpplug.tpl" }

        # Pack all external language files
        $lngDir = Join-Path $projectRoot "src\res\language"
        foreach ($lngFile in Get-ChildItem -Path $lngDir -Filter "*.lng" -ErrorAction SilentlyContinue) {
            Add-ZipFile $lngFile.FullName "language\$($lngFile.Name)"
        }

        $readmeSource = Join-Path $projectRoot "src\help\readme.txt"
        if (Test-Path $readmeSource)   { Add-ZipFile $readmeSource   "readme.txt" }

        Write-Host "  Created: $projectName.zip" -ForegroundColor Green
    } catch {
        Write-Host "  Failed to create ZIP: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        $zip.Dispose()
        $outStream.Dispose()
    }
}

# ============================================================================
# Step 6: Deploy to Total Commander
# ============================================================================
$deploySuccess = $false
if (-not $nodeploy) {
    Write-Host ""
    Write-Host "--- Deploying to Total Commander ---" -ForegroundColor Cyan
    
    $tcPath = Get-TotalCommanderPath
    
    if ($tcPath) {
        # Stop Total Commander
        Stop-TotalCommander
        
        # Deploy files
        $pluginDir = Join-Path $tcPath "plugins\wfx\$projectName"
        try {
            New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
            
            Copy-Item -Path (Join-Path $buildOutputDir    "$projectName.wfx") -Destination (Join-Path $pluginDir "$projectName.wfx64") -Force
            Write-Host "  Deployed: $projectName.wfx64" -ForegroundColor Green
            Copy-Item -Path (Join-Path $buildOutputDirX86 "$projectName.wfx") -Destination (Join-Path $pluginDir "$projectName.wfx") -Force
            Write-Host "  Deployed: $projectName.wfx (x86)" -ForegroundColor Green
            
            if (Test-Path $helpCompiled) {
                Copy-Item -Path $helpCompiled -Destination (Join-Path $pluginDir "$projectName-help.html") -Force
                Write-Host "  Deployed: $projectName-help.html" -ForegroundColor Green
            }
            
            if (Test-Path $phpAgentSource) {
                Copy-Item -Path $phpAgentSource -Destination (Join-Path $pluginDir "sftp.php") -Force
                Write-Host "  Deployed: sftp.php" -ForegroundColor Green
            }

            $tplSource = Join-Path $projectRoot "src\res\sftpplug.tpl"
            if (Test-Path $tplSource) {
                Copy-Item -Path $tplSource -Destination (Join-Path $pluginDir "sftpplug.tpl") -Force
                Write-Host "  Deployed: sftpplug.tpl" -ForegroundColor Green
            }

            # Deploy external language files
            $lngDir = Join-Path $projectRoot "src\res\language"
            $lngDestDir = Join-Path $pluginDir "language"
            New-Item -ItemType Directory -Path $lngDestDir -Force | Out-Null
            foreach ($lngFile in Get-ChildItem -Path $lngDir -Filter "*.lng" -ErrorAction SilentlyContinue) {
                Copy-Item -Path $lngFile.FullName -Destination (Join-Path $lngDestDir $lngFile.Name) -Force
                Write-Host "  Deployed: language\$($lngFile.Name)" -ForegroundColor Green
            }
            
            $deploySuccess = $true
        } catch {
            Write-Host "  Deploy failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  Total Commander not found - skipping deploy" -ForegroundColor Yellow
        Write-Host "  Install TC or set registry key: HKCU\Software\Ghisler\Total Commander\InstallDir" -ForegroundColor Gray
    }
}

# ============================================================================
# Step 7: Clean up intermediate build directory
# ============================================================================
$buildBinDir = Join-Path $buildDir "bin"
if (Test-Path $buildBinDir) {
    Remove-Item $buildBinDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# Step 8: Final Summary
# ============================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BUILD COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output directory: $binDir" -ForegroundColor White
if (Test-Path (Join-Path $binDir "$projectName.zip")) {
    Write-Host "  - $projectName.zip (TC auto-install)" -ForegroundColor Gray
}

if ($deploySuccess) {
    Write-Host ""
    Write-Host "Deployed to: $tcPath\plugins\wfx\$projectName" -ForegroundColor Green
    Write-Host ""
    Write-Host "Restart Total Commander to load the plugin." -ForegroundColor Cyan
}

Write-Host ""
