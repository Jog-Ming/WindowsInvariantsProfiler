param([string]$Version = '1.0.0')
$ErrorActionPreference = 'Stop'
& "$PSScriptRoot\build.ps1" -Version $Version
$hash = (Get-FileHash "$PSScriptRoot\dist\winvar.exe" -Algorithm SHA256).Hash.ToLower()
"$hash  winvar.exe" | Out-File "$PSScriptRoot\dist\SHA256SUMS" -Encoding ascii
Write-Output "SHA256: $hash"
