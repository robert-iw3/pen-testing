FROM mcr.microsoft.com/windows/servercore:ltsc2025 as base

ENV container docker
ENV chocolateyUseWindowsCompression false
SHELL ["powershell.exe"]

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
    Get-WindowsUpdate -Install

FROM base as compile

# Set the working directory inside the container
WORKDIR /app

# Copy the Visual Studio project files into the container
COPY . .

SHELL ["powershell.exe"]

# Install Visual Studio Build Tools
RUN \
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_BuildTools.exe" -OutFile "vs_BuildTools.exe"; \
    Start-Process "vs_BuildTools.exe" -ArgumentList "--quiet", "--wait", "--norestart", "--nocache", "--installPath", "C:\BuildTools", "--add", "Microsoft.VisualStudio.Workload.VCTools", "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621", "--includeRecommended", "--force" -Verb RunAs -Wait; \
    Remove-Item "vs_BuildTools.exe"

# Set up the environment for MSBuild
ENV PATH="${PATH};C:\BuildTools\MSBuild\Current\Bin"

# Compile the Visual Studio project
RUN MSBuild "PAExec.sln" /p:Configuration=Release /p:Platform="x64"

FROM compile AS runtime
WORKDIR /app
COPY --from=compile /app/x64/Release/PAExec.exe .

# Command to run when the container starts
CMD ["PAExec.exe"]