Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-InProjectRoot {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ProjectRoot,

        [Parameter(Mandatory = $true)]
        [string]$TargetPath
    )

    $resolvedRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
    $resolvedTarget = [System.IO.Path]::GetFullPath($TargetPath)

    if (-not $resolvedTarget.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify path outside the project root: $resolvedTarget"
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

$dataDir = Join-Path $projectRoot "data"
$logDir = Join-Path $projectRoot "logs"
$encryptedDir = Join-Path $dataDir "encrypted"
$uploadsDir = Join-Path $dataDir "uploads"

$jsonDefaults = @{
    "users.json" = "[]"
    "sessions.json" = "{}"
    "login_attempts.json" = "{}"
    "documents.json" = "{}"
    "shares.json" = "[]"
    "audit_trail.json" = "[]"
}

foreach ($directory in @($dataDir, $logDir, $encryptedDir, $uploadsDir)) {
    Assert-InProjectRoot -ProjectRoot $projectRoot -TargetPath $directory
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
}

foreach ($name in $jsonDefaults.Keys) {
    $target = Join-Path $dataDir $name
    Assert-InProjectRoot -ProjectRoot $projectRoot -TargetPath $target
    Set-Content -Path $target -Value $jsonDefaults[$name] -Encoding UTF8
}

foreach ($directory in @($encryptedDir, $uploadsDir)) {
    Assert-InProjectRoot -ProjectRoot $projectRoot -TargetPath $directory
    Get-ChildItem -LiteralPath $directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item -LiteralPath $_.FullName -Recurse -Force
    }
}

foreach ($logName in @("security.log", "access.log")) {
    $logPath = Join-Path $logDir $logName
    Assert-InProjectRoot -ProjectRoot $projectRoot -TargetPath $logPath
    Set-Content -Path $logPath -Value "" -Encoding UTF8
}

Write-Output "Project runtime state has been reset."
Write-Output "Reset files:"
$jsonDefaults.Keys | Sort-Object | ForEach-Object { Write-Output " - data/$_" }
Write-Output "Cleared directories:"
Write-Output " - data/encrypted"
Write-Output " - data/uploads"
Write-Output " - logs/security.log"
Write-Output " - logs/access.log"
