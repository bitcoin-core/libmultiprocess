param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactRoot
)

# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

$ErrorActionPreference = "Stop"
# Prevent PowerShell 7 from turning native-command stderr into a terminating
# error before we get a chance to see it.
$PSNativeCommandUseErrorActionPreference = $false

$artifactPath = (Resolve-Path $ArtifactRoot).Path
$env:PATH = "$artifactPath;$env:PATH"

$mptest = Join-Path $artifactPath "test\mptest.exe"
& $mptest 2>&1 | ForEach-Object { "$_" }
$code = $LASTEXITCODE
Write-Host ("mptest exit code: {0} (0x{0:X8})" -f $code)
if ($code -ne 0) {
    exit $code
}

$exampleDir = Join-Path $artifactPath "example"
Push-Location $exampleDir
try {
    $output = "2+2`nexit`n" | & ".\mpexample.exe" 2>&1 | Out-String
    Write-Host $output
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    if ($output -notmatch "mpprinter:" -or $output -notmatch "Bye!") {
        throw "Unexpected mpexample output."
    }
} finally {
    Pop-Location
}
