<#
.SYNOPSIS
Build the Windows installer (dist\credstore-VERSION-x64.msi) from release binaries.

.DESCRIPTION
Needs the .NET SDK. Installs WiX 5 as a .NET global tool if it is missing. Run after
`cargo build --release -p credstore -p credstored`. The desktop app is included when
app\target\release\credstore-app.exe exists (cargo build --release in app\).
#>
param(
    [string]$BinDir = (Join-Path $PSScriptRoot '..\target\release'),
    [string]$OutDir = (Join-Path $PSScriptRoot '..\dist'),
    [string]$AppExe = (Join-Path $PSScriptRoot '..\app\target\release\credstore-app.exe')
)
$ErrorActionPreference = 'Stop'
$WixVersion = '5.0.2'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$version = (Select-String -Path (Join-Path $root 'Cargo.toml') -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    dotnet tool install --global wix --version $WixVersion
    if ($LASTEXITCODE -ne 0) { throw 'installing WiX failed' }
    $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
}
foreach ($ext in 'WixToolset.Util.wixext', 'WixToolset.UI.wixext') {
    wix extension add --global "$ext/$WixVersion"
    if ($LASTEXITCODE -ne 0) { throw "adding the WiX extension $ext failed" }
}

$withApp = if (Test-Path $AppExe) { '1' } else { '0' }
Write-Host "desktop app included: $withApp"

New-Item -ItemType Directory -Force $OutDir | Out-Null
$msi = Join-Path $OutDir "credstore-$version-x64.msi"
wix build -arch x64 -ext WixToolset.Util.wixext -ext WixToolset.UI.wixext `
    -d "Version=$version" -d "BinDir=$BinDir" -d "DeployDir=$(Join-Path $root 'deploy')" `
    -d "WithApp=$withApp" -d "AppExe=$AppExe" `
    -o $msi (Join-Path $PSScriptRoot 'wix\credstore.wxs')
if ($LASTEXITCODE -ne 0) { throw 'wix build failed' }
Write-Host "built $msi"
