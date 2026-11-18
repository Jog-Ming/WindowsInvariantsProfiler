param([string]$Version = '1.0.0')
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$go = $null
if (-not $env:CI) {
  $local = Join-Path $root '.tools\go\bin\go.exe'
  if (Test-Path $local) { $go = $local }
}
if (-not $go) {
  $cmd = Get-Command go -ErrorAction SilentlyContinue
  if (-not $cmd) {
    throw "Go toolchain not found. Install it on PATH."
  }
  $go = $cmd.Source
}
$asset = Join-Path $root 'assets\tracelog.exe'
if (-not (Test-Path $asset)) {
  throw "assets\tracelog.exe is missing"
}
# rsrc_windows_amd64.syso embeds winvar.manifest (RT_MANIFEST asInvoker). Without
# it the loader honors a planted <exe>.manifest next to the staged installer.
$manifest = Join-Path $root 'winvar.manifest'
$resource = Join-Path $root 'rsrc_windows_amd64.syso'
if (-not (Test-Path $manifest)) {
  throw "winvar.manifest is missing"
}
if (-not (Test-Path $resource)) {
  throw "rsrc_windows_amd64.syso is missing; regenerate with: rsrc -manifest winvar.manifest -arch amd64 -o rsrc_windows_amd64.syso"
}
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$version = $Version

# Build the GUI-subsystem daemon first; the client embeds it.
$daemon = Join-Path $root 'assets\winvard.exe'
& $go build -tags daemon -trimpath -ldflags "-s -w -H windowsgui -X main.buildVersion=$version" -o $daemon $root
if ($LASTEXITCODE -ne 0) { throw "go build (daemon) failed" }

$out = Join-Path $dist 'winvar.exe'
& $go build -trimpath -ldflags "-s -w -X main.buildVersion=$version" -o $out $root
if ($LASTEXITCODE -ne 0) { throw "go build (client) failed" }

function Assert-EmbeddedManifest([string]$path) {
  $text = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($path))
  if (-not $text.Contains('requestedExecutionLevel')) {
    throw "embedded application manifest missing from $path"
  }
}
Assert-EmbeddedManifest $out
Assert-EmbeddedManifest $daemon

$size = (Get-Item $out).Length
$daemonSize = (Get-Item $daemon).Length
Write-Output ("built {0} ({1:N0} bytes, version {2}, single-file installer)" -f $out, $size, $version)
Write-Output ("daemon payload {0} ({1:N0} bytes, embedded)" -f $daemon, $daemonSize)
