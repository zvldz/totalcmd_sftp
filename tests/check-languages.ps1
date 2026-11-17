#requires -Version 5.1
<#
.SYNOPSIS
Checks that every language file translates every string, with the same
placeholders as English.

.DESCRIPTION
The English strings are the STRINGTABLE entries of src\res\sftpplug.rc. Each
src\res\language\*.lng must have every one of them, nothing else, and each
translation must carry the same "{}" placeholders and the same printf
specifiers (%s, %d, ...) in the same order: a missing one leaves the value
out of the message, an extra or reordered one reads the wrong argument.
Exits with 1 and lists the problems if there are any.
#>
$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
$utf8 = [System.Text.UTF8Encoding]::new($false)

$ids = @{}
foreach ($m in [regex]::Matches([System.IO.File]::ReadAllText((Join-Path $Root 'src\res\resource.h'), $utf8),
                                '(?m)^#define\s+(\w+)\s+(\d+)')) {
    $ids[$m.Groups[1].Value] = [int]$m.Groups[2].Value
}

# English: the STRINGTABLE entries, whose text may start on the next line.
$english = @{}
$rc = [System.IO.File]::ReadAllText((Join-Path $Root 'src\res\sftpplug.rc'), $utf8)
foreach ($table in [regex]::Matches($rc, '(?s)STRINGTABLE\s*BEGIN(.*?)\bEND\b')) {
    foreach ($m in [regex]::Matches($table.Groups[1].Value, '(?m)^\s*(IDS_\w+)\s+"((?:[^"]|"")*)"')) {
        $name = $m.Groups[1].Value
        if (-not $ids.ContainsKey($name)) { throw "sftpplug.rc: $name is not defined in resource.h" }
        $english[$ids[$name]] = $m.Groups[2].Value.Replace('""', '"')
    }
}
if ($english.Count -eq 0) { throw 'No strings found in sftpplug.rc' }

# The placeholders of a string, in order: "{}" and printf specifiers ("%%" is
# a literal percent sign, not a placeholder).
function Get-Placeholders([string]$text) {
    @([regex]::Matches($text, '\{\}|%%|%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|I64|z)?[diuxXcsSpfeEgG]') |
      Where-Object { $_.Value -ne '%%' } | ForEach-Object { $_.Value })
}

$problems = @()
$files = @(Get-ChildItem (Join-Path $Root 'src\res\language') -Filter '*.lng' | Sort-Object Name)
if ($files.Count -eq 0) { throw 'No language files found' }
foreach ($file in $files) {
    $table = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($file.FullName, $utf8)) {
        if ($line -notmatch '^(\d+)=(.*)$') { continue }
        $num = [int]$Matches[1]
        if ($table.ContainsKey($num)) { $problems += "$($file.Name): $num is listed twice" }
        $table[$num] = $Matches[2]
    }
    foreach ($num in $english.Keys | Sort-Object) {
        if (-not $table.ContainsKey($num)) {
            $problems += "$($file.Name): $num is missing (`"$($english[$num])`")"
            continue
        }
        $want = (Get-Placeholders $english[$num]) -join ' '
        $have = (Get-Placeholders $table[$num]) -join ' '
        if ($want -ne $have) {
            $problems += "$($file.Name): $num has placeholders [$have], English has [$want]"
        }
    }
    foreach ($num in $table.Keys | Sort-Object) {
        if (-not $english.ContainsKey($num)) { $problems += "$($file.Name): $num is not a string of the plugin" }
    }
}

if ($problems.Count) {
    $problems | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    Write-Host "$($problems.Count) language problem(s)" -ForegroundColor Red
    exit 1
}
Write-Host "Languages: $($files.Count) files x $($english.Count) strings, placeholders match"
exit 0
