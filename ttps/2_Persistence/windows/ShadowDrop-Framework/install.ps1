<#
.SYNOPSIS
Official installer for ShadowDrop Framework - Advanced Malware Dropper & Evasion Toolkit

.DESCRIPTION
This script automates the installation and configuration of ShadowDrop Framework.
It will verify system requirements, install dependencies, clone the repository,
and configure the environment for authorized red team operations.

.NOTES
Author: ShadowDrop Development Team
Version: 1.0.0
Requires: Windows 10/11, PowerShell 5.1+
#>

#region Initialization
Write-Host "`n   _____ __           __    ____                      __   " -ForegroundColor DarkRed
Write-Host "  / ___// /___  _____/ /___/ __ \____ ________  ____/ /__ " -ForegroundColor DarkRed
Write-Host "  \__ \/ __/ / / / __  / __/ / / / __ / ___/ _ \/ __  / _ \" -ForegroundColor DarkRed
Write-Host " ___/ / /_/ /_/ / /_/ / /_/ /_/ / /_/ / /  /  __/ /_/ /  __/" -ForegroundColor DarkRed
Write-Host "/____/\__/\__,_/\__,_/\__/_____/\__,_/_/   \___/\__,_/\___/ " -ForegroundColor DarkRed
Write-Host "`n                Advanced Red Team Framework`n" -ForegroundColor DarkRed

Write-Host "[*] Initializing ShadowDrop Framework installation..." -ForegroundColor Cyan
Write-Host "[!] LEGAL NOTICE: This software is for AUTHORIZED security research only" -ForegroundColor Yellow
Write-Host "[!] By continuing, you agree to the terms at: https://github.com/Untouchable17/ShadowDrop-Framework" -ForegroundColor Yellow

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] ERROR: Installation requires administrator privileges" -ForegroundColor Red
    Write-Host "[!] Please restart PowerShell as Administrator and rerun this script" -ForegroundColor Red
    exit 1
}

$os = Get-CimInstance -ClassName Win32_OperatingSystem
if ($os.Caption -notmatch "Windows 10|Windows 11") {
    Write-Host "[!] ERROR: Unsupported OS. ShadowDrop requires Windows 10/11" -ForegroundColor Red
    exit 1
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "[!] ERROR: PowerShell 5.1 or newer required" -ForegroundColor Red
    exit 1
}

Write-Host "`n[#] PHASE 1: SECURITY VERIFICATION" -ForegroundColor Green

$isVM = $false
try {
    $model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
    if ($model -match "Virtual|VMware|KVM|QEMU|Xen") {
        $isVM = $true
    }
    
    $hyperv = (Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent
    if ($hyperv) {
        $isVM = $true
    }
} catch {
    Write-Host "[!] WARNING: Virtualization check failed" -ForegroundColor Yellow
}

if ($isVM) {
    Write-Host "[!] WARNING: Running in virtualized environment" -ForegroundColor Yellow
    Write-Host "[!] Production operations should NEVER be conducted in VMs" -ForegroundColor Yellow
}

$domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
if ($domain -match "prod|production|corp") {
    Write-Host "[!] CRITICAL WARNING: This appears to be a PRODUCTION domain" -ForegroundColor Red
    Write-Host "[!] ABORTING installation to prevent accidental deployment" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Security checks passed" -ForegroundColor Green

Write-Host "`n[#] PHASE 2: DEPENDENCY INSTALLATION" -ForegroundColor Green

if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Installing Chocolatey package manager..." -ForegroundColor Cyan
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    refreshenv
}

# Install required components
$packages = @(
    "git",
    "python",
    "vcredist2015",
    "vcredist2017",
    "vcredist2019",
    "7zip"
)

foreach ($package in $packages) {
    if (-not (choco list -lo | Where-Object { $_ -match "^$package " })) {
        Write-Host "[*] Installing $package..." -ForegroundColor Cyan
        choco install $package -y --no-progress
    }
    else {
        Write-Host "[+] $package already installed" -ForegroundColor Green
    }
}

Write-Host "[*] Installing Python dependencies..." -ForegroundColor Cyan
pip install pycryptodome pefile pyinstaller

Write-Host "[*] Installing PowerShell modules..." -ForegroundColor Cyan
Install-Module -Name PSReadLine -Force -SkipPublisherCheck
Install-Module -Name ThreadJob -Force -SkipPublisherCheck

Write-Host "`n[#] PHASE 3: FRAMEWORK INSTALLATION" -ForegroundColor Green

$installPath = "$env:SystemDrive\ShadowDrop"
Write-Host "[*] Installing ShadowDrop to $installPath" -ForegroundColor Cyan

if (Test-Path $installPath) {
    Write-Host "[*] Updating existing installation..." -ForegroundColor Cyan
    Set-Location $installPath
    git pull origin main
}
else {
    Write-Host "[*] Cloning repository..." -ForegroundColor Cyan
    git clone https://github.com/Untouchable17/ShadowDrop-Framework.git $installPath
    Set-Location $installPath
}

$expectedFiles = @("Core", "Vectors", "Evasion", "C2", "Operations", "LICENSE", "SECURITY.md")
foreach ($file in $expectedFiles) {
    if (-not (Test-Path "$installPath\$file")) {
        Write-Host "[!] ERROR: Missing critical file: $file" -ForegroundColor Red
        Write-Host "[!] Repository may be corrupted" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[*] Building framework components..." -ForegroundColor Cyan
Set-Location "$installPath\Core"
.\build.bat

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] ERROR: Build process failed" -ForegroundColor Red
    Write-Host "[!] Check build.bat output for details" -ForegroundColor Red
    exit 1
}

Write-Host "`n[#] PHASE 4: ENVIRONMENT CONFIGURATION" -ForegroundColor Green

$path = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($path -notlike "*$installPath*") {
    Write-Host "[*] Adding ShadowDrop to system PATH..." -ForegroundColor Cyan
    $newPath = "$path;$installPath"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    $env:Path += ";$installPath"
}

$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = "$desktopPath\ShadowDrop.lnk"
$wshell = New-Object -ComObject WScript.Shell
$shortcut = $wshell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-NoExit -Command `"cd '$installPath'; .\start.ps1`""
$shortcut.IconLocation = "$installPath\Assets\icon.ico"
$shortcut.Description = "ShadowDrop Framework"
$shortcut.Save()

$startMenu = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\ShadowDrop"
if (-not (Test-Path $startMenu)) {
    New-Item -ItemType Directory -Path $startMenu | Out-Null
}
Copy-Item $shortcutPath "$startMenu\ShadowDrop.lnk"

Write-Host "`n[#] INSTALLATION COMPLETE" -ForegroundColor Green
Write-Host "[+] ShadowDrop Framework successfully installed" -ForegroundColor Green
Write-Host "`n[!] IMPORTANT OPERATIONAL NOTES:" -ForegroundColor Yellow
Write-Host "1. Always verify target authorization BEFORE operations" -ForegroundColor Yellow
Write-Host "2. Use VPN chaining and operational security measures" -ForegroundColor Yellow
Write-Host "3. Regularly update with 'git pull' from $installPath" -ForegroundColor Yellow
Write-Host "`n[>] Launch ShadowDrop from Desktop shortcut or Start Menu" -ForegroundColor Cyan
Write-Host "[>] Documentation: $installPath\DOCUMENTATION.md" -ForegroundColor Cyan

Write-Host "`n[*] Performing final environment verification..." -ForegroundColor Cyan
Start-Sleep 2
powershell -NoProfile -ExecutionPolicy Bypass -File "$installPath\Tools\env_check.ps1"
