FROM mcr.microsoft.com/windows/servercore:ltsc2025 as base

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
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')); \
    choco install visualstudio2022community --yes; \
    choco install visualstudio2022-workload-nativedesktop --yes; \
    choco install choco install msbuild.communitytasks --yes; \
    choco install nuget.commandline --yes; \
    choco install git --yes

COPY . .

RUN \
    nuget restore AlphabeticalPolyGen.sln; \
    msbuild AlphabeticalPolyGen.sln -p:Configuration=Release

CMD ["powershell.exe"]