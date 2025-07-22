$FormatEnumerationLimit = -1 # Make the final table be able to show as much ports in the array as needed. Default cap is 4 or something.

function scan {
<#
    .SYNOPSIS
    Small Portscanner mainly based on the work of Niklas Goude https://twitter.com/ngoude
    To directly run it in memory run:
    iex(new-object net.webclient).downloadstring("https://raw.githubusercontent.com/LuemmelSec/Pentest-Tools-Collection/main/tools/portscan.ps1")
        
    .PARAMETER IPStart
    Your starting IP

    .PARAMETER IPEnd
    Your ending IP

    .PARAMETER File
    Provide a file (one IP per line) instead of IPStart and IPEnd

    .PARAMETER DNS
    Try to get HostNames from IPs

    .PARAMETER forcedns
    Try to resolve DNS names, no matter if ping succeeded

    .PARAMETER PortScan
    Perform a PortScan. If no ports are specified with the -ports parameter, the default ports will be scanned
    
    .PARAMETER Ports
    Ports That should be scanned, default values are:
    21,22,23,53,80,139,389,443,445,636,1433,3128,8080,3389,5985 

    .PARAMETER forceportscan
    Port scan anyways, no matter if ping succeeded

    .PARAMETER outfile
    Where you want your CSV saved?

    .PARAMETER v
    Yep it is for verbose. Will give you the intermediate results - per host results during the scan

    .PARAMETER collectall
    Will give you all findings in the final results table. Default is to only collect findings where we have a hit.

    .PARAMETER ExportCSV
    Exports the final results table as CSV to the PWD

    .PARAMETER TimeOut
    Time (in MilliSeconds) before TimeOut, Default set to 100

    .EXAMPLE
    scan -IPStart 192.168.0.1 -IPEnd 192.168.0.10

    .EXAMPLE
    scan -IPStart 192.168.0.1 -IPEnd 192.168.0.10 -PortScan -DNS

    .EXAMPLE
    scan -file .\ips.txt -PortScan -Ports 22,3389,5985
    
    .EXAMPLE
    scan -File .\ips.txt -dns -forcedns -PortScan -forceportscan -TimeOut 10 -v
    
    .LINK
    https://github.com/LuemmelSec

    .NOTES
    LuemmelSec 2021
  #>


# All the parameters and switches and stuff
  Param(
    [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
    [string]$IPStart,
    [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
    [string]$IPEnd,
    [string]$File,
    [string]$outfile,
    [switch]$DNS,
    [switch]$PortScan,
    [switch]$forcedns,
    [switch]$forceportscan,
    [switch]$ExportCSV,
    [switch]$collectall,
    [switch]$v,
    [int[]]$Ports = @(21,22,23,53,80,139,389,443,445,636,1433,3128,8080,3389,5985),
    [int]$TimeOut = 100
  )

# Fancy logo shit
Write-Host -ForegroundColor DarkGray ""
Write-Host -ForegroundColor Gray ":::::::::   ::::::::   ::::::::  :::::::::       "
Write-Host -ForegroundColor Gray ":+:    :+: :+:    :+: :+:    :+: :+:    :+:      "
Write-Host -ForegroundColor Gray "+:+    +:+ +:+    +:+ +:+    +:+ +:+    +:+      "
Write-Host -ForegroundColor Gray "+#++:++#+  +#+    +:+ +#+    +:+ +#++:++#:       "
Write-Host -ForegroundColor Gray "+#+        +#+    +#+ +#+    +#+ +#+    +#+      "
Write-Host -ForegroundColor Gray "#+#        #+#    #+# #+#    #+# #+#    #+#      "
Write-Host -ForegroundColor Gray "###         ########   ########  ###    ###      "
Write-Host -ForegroundColor DarkCyan "                                             "
Write-Host -ForegroundColor Cyan "::::    ::::      :::     ::::    :::  ::::::::  "
Write-Host -ForegroundColor Cyan "+:+:+: :+:+:+   :+: :+:   :+:+:   :+: :+:    :+: "
Write-Host -ForegroundColor Cyan "+:+ +:+:+ +:+  +:+   +:+  :+:+:+  +:+ +:+        "
Write-Host -ForegroundColor Cyan "+#+  +:+  +#+ +#++:++#++: +#+ +:+ +#+ +#++:++#++ "
Write-Host -ForegroundColor Cyan "+#+       +#+ +#+     +#+ +#+  +#+#+#        +#+ "
Write-Host -ForegroundColor Cyan "#+#       #+# #+#     #+# #+#   #+#+# #+#    #+# "
Write-Host -ForegroundColor Cyan "###       ### ###     ### ###    ####  ########  "
Write-Host -ForegroundColor DarkCyan "                                                "
Write-Host -ForegroundColor DarkCyan "::::    ::: ::::    ::::      :::     :::::::::  "
Write-Host -ForegroundColor DarkCyan ":+:+:   :+: +:+:+: :+:+:+   :+: :+:   :+:    :+: "
Write-Host -ForegroundColor DarkCyan ":+:+:+  +:+ +:+ +:+:+ +:+  +:+   +:+  +:+    +:+ "
Write-Host -ForegroundColor DarkCyan "+#+ +:+ +#+ +#+  +:+  +#+ +#++:++#++: +#++:++#+  "
Write-Host -ForegroundColor DarkCyan "+#+  +#+#+# +#+       +#+ +#+     +#+ +#+   "     
Write-Host -ForegroundColor DarkCyan "#+#   #+#+# #+#       #+# #+#     #+# #+#  "      
Write-Host -ForegroundColor DarkCyan "###    #### ###       ### ###     ### ### "
Write-Host -ForegroundColor DarkCyan "                                                "
Write-Host -ForegroundColor DarkGray "A small and portable portscanner by @LuemmelSec "
Write-Host -ForegroundColor DarkGray ""
Write-Host -ForegroundColor DarkGray "Examples:"
Write-Host -ForegroundColor DarkGray "scan -IPStart 192.168.0.1 -IPEnd 192.168.0.10 -PortScan -DNS"
Write-Host -ForegroundColor DarkGray "scan -File .\ips.txt -dns -forcedns -PortScan -forceportscan -TimeOut 10 -v"
Write-Host -ForegroundColor DarkGray "scan -file .\ips.txt -PortScan -Ports 22,3389,5985 -collectall -exportcsv -outfile c:\temp\scan.csv"
Write-Host -ForegroundColor DarkGray ""

$totalresults=@() # define $totalresults as empty array. Otherwise it wouldn´t work for me

# loop procedure for when we give ipstart and ipend and parameters
if($IPStart -and $IPEnd){
    foreach($a in ($IPStart.Split(".")[0]..$IPEnd.Split(".")[0])) {
      foreach($b in ($IPStart.Split(".")[1]..$IPEnd.Split(".")[1])) {
        foreach($c in ($IPStart.Split(".")[2]..$IPEnd.Split(".")[2])) {
          foreach($d in ($IPStart.Split(".")[3]..$IPEnd.Split(".")[3])) {
            $ip = "$a.$b.$c.$d"
            dostuff
            if(($global:pingcheck -eq $TRUE) -or ($global:hostcheck -eq $TRUE) -or ($global:portcheck -eq $TRUE) -or ($collectall)){
                $totalresults += $Global:obj
            }
          }
        }
      }
    }
$totalresults | Format-Table -Property IP,DNS,PING,PORTS -AutoSize -Wrap
if($ExportCSV){
$totalresults | Select-Object IP,DNS,PING,@{Expression={$_.PORTS -join ';'}} | export-csv $outfile -NoTypeInformation
}
}

# loop procedure for when we give a file with IPs 
elseif($File){
    foreach($line in get-content $file){
        $ip = $line
        dostuff
        if(($global:pingcheck -eq $TRUE) -or ($global:hostcheck -eq $TRUE) -or ($global:portcheck -eq $TRUE) -or ($collectall)){
            $totalresults += $Global:obj
        }
    }
$totalresults | Format-Table -Property IP,DNS,PING,PORTS -AutoSize -Wrap
if($ExportCSV){
$totalresults | Select-Object IP,DNS,PING,@{Expression={$_.PORTS -join ';'}} | export-csv $outfile -NoTypeInformation
}
}
}

# the function that does all the scan things
function dostuff{
$ping = New-Object System.Net.Networkinformation.Ping

$Highlight = @{
    True = 'Red'
    False = 'Cyan'
}    
            
### Try to ping
try{
$pingStatus = $ping.Send($ip,$TimeOut)
$pingsuccess = $pingStatus.Status
if ($pingsuccess -eq "Success"){
    $Global:pingcheck = $True
    }
else{
    $Global:pingcheck = $False
    }

}
catch{

}
### End try to ping

### Try host DNS resolve
if($DNS){
    try{
        if($forcedns){
            $getHostEntry = [Net.DNS]::BeginGetHostEntry($ip, $null, $null)
            }
        else{
            $getHostEntry = [Net.DNS]::BeginGetHostEntry($pingStatus.Address, $null, $null)
            }
        $Global:hostcheck = $TRUE
    }
    catch{
        $hostname = "no DNS"
        $Global:hostcheck = $FALSE
    }
 }
 ### End Try host DNS resolve


 ### Portscan
 try{
 if($PortScan) {
    $openPorts = @()
    for($i = 1; $i -le $ports.Count;$i++) {
      $port = $Ports[($i-1)]
      $client = New-Object System.Net.Sockets.TcpClient
      if($forceportscan){
        $beginConnect = $client.BeginConnect($ip,$port,$null,$null)
        }
      else{
        $beginConnect = $client.BeginConnect($pingStatus.Address,$port,$null,$null)
        }
      if($client.Connected) {
        $openPorts += $port
      } else {
        # Wait
        Start-Sleep -Milli $TimeOut
        if($client.Connected) {
          $openPorts += $port
        }
      }
      $client.Close()
     }
     $Global:portcheck = $TRUE
  }
  }
  catch{
  $openPorts = "no open ports"
  $Global:portcheck = $FALSE
  }
  
  if($DNS) {
    try{
        $hostName = ([System.Net.DNS]::EndGetHostEntry([IAsyncResult]$getHostEntry)).HostName
         
        }
    catch{
        }
    }
### End Portscan 

### Format stuff          
$1 = $ip;
$2 = $hostName;
$3 = $pingsuccess;
$4 = $openPorts

# if we wanted verbose output we will have this section echo us the intermediate results - per host on the fly
if($v){
    Write-Host("`nHere is your intermediate results: ")
    if(($hostname -ne "no DNS" -and $hostname -ne ""-and $hostname -ne $null) -and ($pingsuccess -eq "Success") -and ($ports)){
    Write-Host "IP: $1 " -ForegroundColor green ;Write-Host "DNS: $2 " -ForegroundColor green ;Write-Host "PING: $3 " -ForegroundColor green ; Write-Host "PORTS: $4 " -ForegroundColor green 
    }
    elseif(($hostname -ne "no DNS" -and $hostname -ne ""-and $hostname -ne $null) -and ($pingsuccess -eq "Success") -and ($ports -eq "no open ports")){
    Write-Host "IP: $1 " -ForegroundColor green ;Write-Host "DNS: $2 " -ForegroundColor green ;Write-Host "PING: $3 " -ForegroundColor green ; Write-Host "PORTS: $4 " -ForegroundColor Red 
    }
    elseif(($hostname -eq "no DNS" -or $hostname -eq "" -or $hostname -eq $null) -and ($pingsuccess -eq "Success") -and ($ports -eq "no open ports")){
    Write-Host "IP: $1 " -ForegroundColor green ;Write-Host "DNS: $2 " -ForegroundColor Red ;Write-Host "PING: $3 " -ForegroundColor green ; Write-Host "PORTS: $4 " -ForegroundColor Red 
    }
    elseif(($hostname -eq "no DNS" -or $hostname -eq "" -or $hostname -eq $null) -and ($pingsuccess -eq "Success") -and ($ports)){
    Write-Host "IP: $1 " -ForegroundColor green ;Write-Host "DNS: $2 " -ForegroundColor Red ;Write-Host "PING: $3 " -ForegroundColor green ; Write-Host "PORTS: $4 " -ForegroundColor green  
    }
    else{
    Write-Host "IP: $1 " -ForegroundColor green ;Write-Host "DNS: $2 " -ForegroundColor Red ;Write-Host "PING: $3 " -ForegroundColor Red ; Write-Host "PORTS: $4 " -ForegroundColor Red  
    }
}
# Return Object to fill our endresults table
    $Global:obj = New-Object PSObject
    $Global:obj | Add-Member NoteProperty -Name IP -Value $1
    $Global:obj | Add-Member NoteProperty -Name DNS -Value $2
    $Global:obj | Add-Member NoteProperty -Name PING -Value $3
    $Global:obj | Add-Member NoteProperty -Name PORTS -Value $4

### Clean variables 
$openports = ""
$hostname = ""

### End Format stuff
}
