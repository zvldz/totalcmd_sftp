#requires -Version 5.1
<#
.SYNOPSIS
Checks the keyboard shortcuts (&-mnemonics) of every dialog in every language.

.DESCRIPTION
For each dialog table in src\include\DialogStrings.h the strings are taken
from src\res\sftpplug.rc (English) and from every src\res\language\*.lng
file (a translation missing there falls back to English, as in the plugin).
A dialog fails when two of its controls share a shortcut letter (the second
can never be reached), or when a shortcut sits on something no keyboard
types directly: a bracket or other sign, or a CJK character (Japanese and
Chinese use the "Text(&C)" form with a Latin letter instead).
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

$dialogs = [ordered]@{}
$header = [System.IO.File]::ReadAllText((Join-Path $Root 'src\include\DialogStrings.h'), $utf8)
foreach ($m in [regex]::Matches($header, '(?s)DialogString (k\w+)\[\] = \{(.*?)\};')) {
    $dialogs[$m.Groups[1].Value] = @([regex]::Matches($m.Groups[2].Value, '\{(\w+),\s*(\w+)\}') |
                                     ForEach-Object { $_.Groups[2].Value })
}

# English: the STRINGTABLE entries, whose text may start on the next line.
$english = @{}
$rc = [System.IO.File]::ReadAllText((Join-Path $Root 'src\res\sftpplug.rc'), $utf8)
foreach ($m in [regex]::Matches($rc, '(?m)^\s*(IDS_\w+)\s+"((?:[^"]|"")*)"')) {
    if ($ids.ContainsKey($m.Groups[1].Value)) {
        $english[$ids[$m.Groups[1].Value]] = $m.Groups[2].Value.Replace('""', '"')
    }
}

$languages = [ordered]@{ eng = $english }
foreach ($file in Get-ChildItem (Join-Path $Root 'src\res\language') -Filter '*.lng' | Sort-Object Name) {
    $table = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($file.FullName, $utf8)) {
        if ($line -match '^(\d+)=(.*)$') { $table[[int]$Matches[1]] = $Matches[2] }
    }
    $languages[$file.BaseName] = $table
}

# The character after a single '&' ("&&" is a literal ampersand), or $null.
function Get-Mnemonic([string]$text) {
    for ($i = 0; $i -lt $text.Length - 1; $i++) {
        if ($text[$i] -ne '&') { continue }
        if ($text[$i + 1] -eq '&') { $i++; continue }
        return $text[$i + 1]
    }
    return $null
}

function Test-Typeable([char]$c) {
    $code = [int]$c
    $cjk = ($code -ge 0x2E80 -and $code -le 0x9FFF) -or ($code -ge 0xAC00 -and $code -le 0xD7AF) -or
           ($code -ge 0xF900 -and $code -le 0xFAFF) -or ($code -ge 0xFF00 -and $code -le 0xFFEF)
    return [char]::IsLetterOrDigit($c) -and -not $cjk
}

$problems = @()
foreach ($lang in $languages.Keys) {
    foreach ($dialog in $dialogs.Keys) {
        $seen = @{}
        foreach ($stringId in $dialogs[$dialog]) {
            if (-not $ids.ContainsKey($stringId)) { continue }
            $num = $ids[$stringId]
            $text = if ($languages[$lang].ContainsKey($num)) { $languages[$lang][$num] } else { $english[$num] }
            if (-not $text) { continue }
            $ch = Get-Mnemonic $text
            if ($null -eq $ch) { continue }
            if (-not (Test-Typeable $ch)) {
                $problems += "$lang $dialog ${stringId}: shortcut on '$ch' in `"$text`""
                continue
            }
            $key = [string]$ch
            $key = $key.ToLowerInvariant()
            if ($seen.ContainsKey($key)) {
                $problems += "$lang $dialog ${stringId}: '&$ch' also used by $($seen[$key])"
            } else {
                $seen[$key] = $stringId
            }
        }
    }
}

if ($problems.Count) {
    $problems | ForEach-Object { Write-Host "    $_" }
    Write-Host "MNEMONIC CHECK FAILED ($($problems.Count))" -ForegroundColor Red
    exit 1
}
Write-Host "Mnemonics: $($languages.Count) languages x $($dialogs.Count) dialogs, no repeats" -ForegroundColor Green
exit 0
