param(
    [Parameter(Mandatory = $false)]
    [string]$Message = "",

    [Parameter(Mandatory = $false)]
    [string]$Branch = "main",

    [Parameter(Mandatory = $false)]
    [string]$Remote = "origin"
)

$ErrorActionPreference = "Stop"

$git = "C:\Program Files\Git\cmd\git.exe"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path $git)) {
    throw "Git was not found at $git"
}

Set-Location $repoRoot

$insideRepo = & $git rev-parse --is-inside-work-tree 2>$null
if ($insideRepo -ne "true") {
    & $git init | Out-Null
}

& $git add -A

$status = (& $git status --short).Trim()

if (-not $status) {
    Write-Host "No local changes to commit."
} else {
    if (-not $Message.Trim()) {
        $Message = "Update project files"
    }

    & $git commit -m $Message
}

& $git push $Remote $Branch
