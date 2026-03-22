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

$statusOutput = & $git status --short
$status = if ($null -eq $statusOutput) { "" } else { ([string]$statusOutput).Trim() }

if (-not $status) {
    Write-Host "No local changes to commit."
} else {
    $commitMessage = if ($null -eq $Message) { "" } else { $Message.Trim() }

    if (-not $commitMessage) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
        $commitMessage = "Update project files ($timestamp)"
    }

    & $git commit -m $commitMessage
}

& $git push $Remote $Branch
