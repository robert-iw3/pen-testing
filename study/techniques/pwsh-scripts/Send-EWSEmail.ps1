<#
    Send Exchange Web Services Email
    Author: Steve Borosh (@rvrsh3ll)
    License: BSD 3-Clause
    Required Dependencies: Exchange Web Services (EWS) Managed API dll from https://www.microsoft.com/en-us/download/details.aspx?id=42951
    Optional Dependencies: None
#>
function Send-EWSEmail {
<#
    .DESCRIPTION
        Send an email using EWS
    
    .EXAMPLE
        Import-Module -Name 'C:\Program Files\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll'
        Import-Module .\Send-EWSEmail.ps1
        Send-EWSEmail -ServiceURL "https://outlook.office365.com/EWS/Exchange.asmx" -Recipient "me@me.com" -Subject "Important Message!" -EmailBody "All, <br> Check out the attachment." -Attachment .\WordDocument.rtf
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]
        $ServiceURL,

        [Parameter(Mandatory = $True)]
        [String]
        $Recipient,

        [Parameter(Mandatory = $True)]
        [String]
        $Subject,

        [Parameter(Mandatory = $False)]
        [String]
        $EmailBody,

        [Parameter(Mandatory = $False)]
        [String]
        $Attachment
    )
    BEGIN {
        $EXCHService = New-Object -TypeName Microsoft.Exchange.WebServices.Data.ExchangeService
        $Credential = Get-Credential
    }
    
    PROCESS {
        $Provider=New-Object Microsoft.CSharp.CSharpCodeProvider
        $Compiler=$Provider.CreateCompiler()
        $Params=New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable=$False
        $Params.GenerateInMemory=$True
        $Params.IncludeDebugInformation=$False
        $Params.ReferencedAssemblies.Add("System.DLL") | Out-Null
        $TASource=@'
namespace Local.ToolkitExtensions.Net.CertificatePolicy{
public class TrustAll : System.Net.ICertificatePolicy {
public TrustAll() { 
}
public bool CheckValidationResult(System.Net.ServicePoint sp,
System.Security.Cryptography.X509Certificates.X509Certificate cert, 
System.Net.WebRequest req, int problem) {
return true;
}
}
}
'@ 
        $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
        $TAAssembly=$TAResults.CompiledAssembly
        
        $TrustAll=$TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy=$TrustAll
        Write-Output "Sending...."
        $EXCHService.Credentials = New-Object -TypeName Microsoft.Exchange.WebServices.Data.WebCredentials -ArgumentList $Credential.UserName, $Credential.GetNetworkCredential().Password
        $EXCHService.AutodiscoverUrl($Credential.UserName, {$true})
        $EXCHService.Url = $ServiceURL
        
        $eMail = New-Object -TypeName Microsoft.Exchange.WebServices.Data.EmailMessage -ArgumentList $EXCHService
        $eMail.Subject = $Subject
        $eMail.Body = $EmailBody
        $eMail.ToRecipients.Add($Recipient) | Out-Null
        if ($Attachment) {
            $email.Attachments.AddFileAttachment($Attachment) | Out-Null
        }
        $eMail.Send()
    }

    END {
        Write-Output "Finished"
    }   
}
