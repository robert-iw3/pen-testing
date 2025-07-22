# example of loading tools into a container running on a windows system, teardown quickly if needed...
FROM mcr.microsoft.com/windows/servercore:ltsc2025-amd64

LABEL BaseImage="windows/servercore:ltsc2025-amd64"

ENV container docker
ENV chocolateyUseWindowsCompression false
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

RUN \
    iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')); \
    choco feature disable --name showDownloadProgress; \
    choco feature enable -n allowGlobalConfirmation; \
    \
    Import-Module $env:ChocolateyInstall\\helpers\\chocolateyProfile.psm1; \
    Write-Host "Install Latest Windows Updates" ; \
    choco install pswindowsupdate; \
    Set-Executionpolicy -ExecutionPolicy RemoteSigned -Force ; \
    Import-Module PSWindowsUpdate -Force ; \
    refreshenv; \
    Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false ; \
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install ; \
    Get-WuInstall -AcceptAll -IgnoreReboot -IgnoreUserInput -nottitle 'preview' ; \
    Get-WindowsUpdate -Install; \
    \
    Install-WindowsFeature -Name "NET-Framework-45-Core", "Web-Asp-Net45", "Web-Net-Ext45" -IncludeAllSubFeature ; \
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0; \
    Start-Service sshd; \
    New-Item c:\tools

WORKDIR /tools/

COPY azure/APEX/ .
COPY misc_windows/Check-LocalAdminHash/ .
COPY azure/GraphRunner/ .
COPY misc_windows/HVNC-windows-remote-toolkit/ .
COPY misc_windows/MailSniper/ .
COPY azure/MFASweep/ .
COPY active-directory/ShadowHound/ .

ENTRYPOINT [ "powershell.exe gci -Path c:/tools" ]
