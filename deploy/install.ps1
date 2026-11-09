#Requires -RunAsAdministrator
<#
.SYNOPSIS
Install credstore in installed mode on Windows (spec 8.1). Run from an elevated
PowerShell.

.DESCRIPTION
Creates the credstore service (virtual account NT SERVICE\credstore), the local groups
credstore-agents and credstore-approvers with -User in both, and %ProgramData%\credstore
readable only by SYSTEM, Administrators and the service. The daemon builds its pipe ACLs
from the group SIDs. Safe to re-run: the vault, policy and audit log are kept.

.PARAMETER Package
Called by the MSI: the binaries are already in place and the MSI owns them and the PATH
entry. -Uninstall then only removes the service.

.PARAMETER DeleteData
With -Uninstall: also delete %ProgramData%\credstore (vault, policy, audit log) and the
credstore groups. The secrets cannot be recovered afterwards. The MSI passes it when
removed with DELETEDATA=1.

.EXAMPLE
.\deploy\install.ps1
.\deploy\install.ps1 -From C:\Downloads\credstore -User MYPC\me
.\deploy\install.ps1 -Uninstall
.\deploy\install.ps1 -Uninstall -DeleteData
#>
param(
    # Directory with credstore.exe, credstored.exe and credstore-sandbox.exe.
    [string]$From = (Join-Path $PSScriptRoot '..\target\release'),
    # The human who approves requests and runs the agent.
    [string]$User = "$env:USERDOMAIN\$env:USERNAME",
    # '1' turns on page file encryption (fsutil), so paged-out secrets are not left on
    # disk. A string so the MSI can pass its property as is.
    [string]$EncryptPageFile = '0',
    [switch]$Package,
    [switch]$Uninstall,
    [switch]$DeleteData
)
$ErrorActionPreference = 'Stop'

$Service = 'credstore'
$Account = 'NT SERVICE\credstore'
$InstallDir = if ($Package) { $PSScriptRoot } else { Join-Path $env:ProgramFiles 'credstore' }
$DataDir = Join-Path $env:ProgramData 'credstore'
$Groups = @('credstore-agents', 'credstore-approvers')
$AgentPipe = '\\.\pipe\credstore-agent'

function Say([string]$Message) { Write-Host "==> $Message" }

function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments)
    $out = & $Exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$Exe $($Arguments -join ' ') failed ($LASTEXITCODE): $out"
    }
}

# Delete the data directory. SYSTEM (the MSI) can open everything in it. An elevated
# administrator may not: older versions created the run folder for SYSTEM and the
# service only, so take ownership of what cannot be opened, then grant Administrators.
function Remove-DataDir {
    if (-not (Test-Path $DataDir)) { return }
    Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
    for ($i = 0; ($i -lt 20) -and (Test-Path $DataDir); $i++) {
        $locked = @()
        Get-ChildItem -Recurse -Force $DataDir -ErrorAction SilentlyContinue -ErrorVariable denied | Out-Null
        foreach ($e in $denied) { if ($e.TargetObject) { $locked += "$($e.TargetObject)" } }
        if (-not $locked) { $locked = @($DataDir) }
        foreach ($item in $locked) {
            & takeown.exe /F $item /A 2>&1 | Out-Null
            & icacls.exe $item /grant '*S-1-5-32-544:(OI)(CI)F' /C 2>&1 | Out-Null
        }
        Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
    }
    if (Test-Path $DataDir) { throw "could not delete $DataDir" }
}

function Remove-FromMachinePath([string]$Dir) {
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $kept = ($path -split ';') | Where-Object { $_ -and $_ -ne $Dir }
    [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')
}

# ------------------------------- uninstall --------------------------------

if ($Uninstall) {
    if (Get-Service $Service -ErrorAction SilentlyContinue) {
        Stop-Service $Service -Force -ErrorAction SilentlyContinue
        Invoke-Native sc.exe @('delete', $Service)
    }
    if (-not $Package) {
        Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
        Remove-FromMachinePath $InstallDir
    }
    Say "removed the service and $InstallDir"
    if ($DeleteData) {
        Remove-DataDir
        foreach ($g in $Groups) { Remove-LocalGroup -Name $g -ErrorAction SilentlyContinue }
        Say "deleted $DataDir (vault, policy, audit log) and the credstore groups"
        return
    }
    Write-Host "Kept: $DataDir (vault, policy, audit log) and the credstore-agents and"
    Write-Host "credstore-approvers groups. To delete them too, run as administrator:"
    if ($Package) {
        Write-Host "  msiexec /x credstore-VERSION-x64.msi DELETEDATA=1"
    } else {
        Write-Host "  .\deploy\install.ps1 -Uninstall -DeleteData"
    }
    return
}

# -------------------------------- install ---------------------------------

if ($DeleteData) { throw '-DeleteData goes with -Uninstall' }
if ($Package) { $From = $InstallDir }
$binaries = 'credstore.exe', 'credstored.exe', 'credstore-sandbox.exe'
foreach ($b in $binaries) {
    if (-not (Test-Path (Join-Path $From $b))) {
        throw "missing $(Join-Path $From $b) (build with: cargo build --release)"
    }
}

# Stop a running copy so its binary can be replaced.
if (Get-Service $Service -ErrorAction SilentlyContinue) {
    Stop-Service $Service -Force
}

if (-not $Package) {
    Say "binaries -> $InstallDir"
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    Copy-Item ($binaries | ForEach-Object { Join-Path $From $_ }) $InstallDir -Force
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (($machinePath -split ';') -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable('Path', "$machinePath;$InstallDir", 'Machine')
    }
}

Say "groups"
foreach ($g in $Groups) {
    if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $g -Description "credstore: $g" | Out-Null
    }
    if (-not $User) { continue }
    try {
        # A bare name (the MSI passes LogonUser) resolves to a local, then domain account.
        Add-LocalGroupMember -Group $g -Member $User
    } catch [Microsoft.PowerShell.Commands.MemberExistsException] {
        # already a member
    }
}
if (-not $User) { Write-Host '    no user given: add yourself with install.ps1 -Package -User NAME' }

if ($EncryptPageFile -eq '1') {
    Say 'page file encryption (applies after a restart)'
    Invoke-Native fsutil.exe @('behavior', 'set', 'encryptpagingfile', '1')
}

Say "service ($Account)"
$exe = Join-Path $InstallDir 'credstored.exe'
if (-not (Get-Service $Service -ErrorAction SilentlyContinue)) {
    New-Service -Name $Service -BinaryPathName "`"$exe`" --service" `
        -DisplayName 'credstore secret broker' -StartupType Automatic `
        -Description 'Lets coding agents use secrets without seeing them.' | Out-Null
}
# The virtual account needs no password. A service SID lets ACLs name the service.
Invoke-Native sc.exe @('config', $Service, 'obj=', $Account)
Invoke-Native sc.exe @('sidtype', $Service, 'unrestricted')
Invoke-Native sc.exe @('failure', $Service, 'reset=', '86400', 'actions=', 'restart/5000')

Say "data directory $DataDir"
New-Item -ItemType Directory -Force $DataDir | Out-Null
# SYSTEM, Administrators and the service only; nothing inherited from ProgramData
# (which lets Users read and create). The service gets full control of what it creates
# (vault, index, audit log, run\), but on the folder itself only list, read and create:
# without "delete child" it cannot remove or replace files it does not own, such as the
# policy below.
Invoke-Native icacls.exe @(
    $DataDir, '/inheritance:r',
    '/grant:r', '*S-1-5-18:(OI)(CI)F',
    '/grant:r', '*S-1-5-32-544:(OI)(CI)F',
    '/grant:r', "${Account}:(OI)(CI)(IO)F"
)
Invoke-Native icacls.exe @($DataDir, '/grant', "${Account}:(RX,WD,AD,WEA,WA)")

# Files only an administrator may change; the service reads them. A daemon that was
# taken over cannot widen its own rules (policy) or let more accounts in (users). The
# app changes the policy through `credstore policy-apply`, which Windows runs as
# administrator after asking.
function Protect-AdminFile([string]$Path) {
    Invoke-Native icacls.exe @(
        $Path, '/inheritance:r',
        '/grant:r', '*S-1-5-18:F',
        '/grant:r', '*S-1-5-32-544:F',
        '/grant:r', "${Account}:R"
    )
}
if ($User) {
    # The daemon lets accounts listed here in directly: group membership reaches a token
    # only at logon, a per-user pipe ACE applies at once (M9).
    $users = Join-Path $DataDir 'users'
    if (-not (Test-Path $users)) {
        Set-Content -Path $users -Encoding ascii -Value @(
            '# Accounts allowed on the credstore endpoints without a new logon,',
            '# one per line. Written by the installer; restart the service after editing.'
        )
    }
    $listed = Get-Content $users | ForEach-Object { $_.Trim() }
    if ($listed -notcontains $User) { Add-Content -Path $users -Encoding ascii -Value $User }
}
$users = Join-Path $DataDir 'users'
if (Test-Path $users) { Protect-AdminFile $users }
$policy = Join-Path $DataDir 'policy.toml'
if (Test-Path $policy) {
    Write-Host '    keeping the existing policy'
} else {
    Copy-Item (Join-Path $PSScriptRoot 'policy.toml') $policy
}
Protect-AdminFile $policy

Say 'starting'
Start-Service $Service
$up = $false
for ($i = 0; $i -lt 100; $i++) {
    if ([System.IO.Directory]::GetFiles('\\.\pipe\') -contains $AgentPipe) { $up = $true; break }
    Start-Sleep -Milliseconds 200
}
if (-not $up) {
    $log = Join-Path $DataDir 'credstored.log'
    if (Test-Path $log) { Get-Content $log -Tail 40 | Write-Host }
    throw "credstored did not create $AgentPipe"
}

Write-Host @"

credstore is installed and running as $Account.

Next, as $User (in a new, non-elevated terminal):
  1. credstore setup         create the vault and connect Claude Code (asks first)
  2. credstore set NAME      add a secret (the value is prompted for)
  3. credstore grant DIR     let approved commands run in a project folder
  4. credstore doctor        check the install
"@
