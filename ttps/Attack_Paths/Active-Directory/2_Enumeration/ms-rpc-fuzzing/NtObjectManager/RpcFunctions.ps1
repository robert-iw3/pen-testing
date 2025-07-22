﻿#  Copyright 2021 Google Inc. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

$protseq_completer = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @("ncalrpc", "ncacn_np", "ncacn_ip_tcp", "ncacn_http", "ncacn_hvsocket") | Where-Object { $_ -like "$wordToComplete*" }
}

<#
.SYNOPSIS
Get a list of ALPC Ports that can be opened by a specified token.
.DESCRIPTION
This cmdlet checks for all ALPC ports on the system and tries to determine if one or more specified tokens can connect to them.
If no tokens are specified then the current process token is used. This function searches handles for existing ALPC Port servers as you can't directly open the server object and just connecting might show inconsistent results.
.PARAMETER ProcessId
Specify a list of process IDs to open for their tokens.
.PARAMETER ProcessName
Specify a list of process names to open for their tokens.
.PARAMETER ProcessCommandLine
Specify a list of command lines to filter on find for the process tokens.
.PARAMETER Token
Specify a list token objects.
.PARAMETER Process
Specify a list process objects to use for their tokens.
.INPUTS
None
.OUTPUTS
NtObjectManager.Cmdlets.Accessible.CommonAccessCheckResult
.NOTES
For best results run this function as an administrator with SeDebugPrivilege available.
.EXAMPLE
Get-AccessibleAlpcPort
Get all ALPC Ports connectable by the current token.
.EXAMPLE
Get-AccessibleAlpcPort -ProcessIds 1234,5678
Get all ALPC Ports connectable by the process tokens of PIDs 1234 and 5678
#>
function Get-AccessibleAlpcPort {
    Param(
        [alias("ProcessIds")]
        [Int32[]]$ProcessId,
        [alias("ProcessNames")]
        [string[]]$ProcessName,
        [alias("ProcessCommandLines")]
        [string[]]$ProcessCommandLine,
        [alias("Tokens")]
        [NtCoreLib.NtToken[]]$Token,
        [alias("Processes")]
        [NtCoreLib.NtProcess[]]$Process
    )
    $access = Get-NtAccessMask -AlpcPortAccess Connect -ToGenericAccess
    Get-AccessibleObject -FromHandle -ProcessId $ProcessId -ProcessName $ProcessName `
        -ProcessCommandLine $ProcessCommandLine -Token $Token -Process $Process -TypeFilter "ALPC Port" -AccessRights $access
}

<#
.SYNOPSIS
Gets the endpoints for a RPC interface from the local endpoint mapper or by brute force.
.DESCRIPTION
This cmdlet gets the endpoints for a RPC interface from the local endpoint mapper. Not all RPC interfaces
are registered in the endpoint mapper so it might not show. You can use the -FindAlpcPort command to try
and brute force an ALPC port for the interface.
.PARAMETER InterfaceId
The UUID of the RPC interface.
.PARAMETER InterfaceVersion
The version of the RPC interface.
.PARAMETER Server
Parsed NDR server.
.PARAMETER Binding
A RPC binding string to query all endpoints from.
.PARAMETER AlpcPort
An ALPC port name. Can contain a full path as long as the string contains \RPC Control\ (case sensitive).
.PARAMETER FindAlpcPort
Use brute force to find a valid ALPC endpoint for the interface.
.PARAMETER ProcessId
Used to find all ALPC ports in a process and get the supported interfaces.
.INPUTS
None or NtCoreLib.Ndr.Rpc.RpcServerInterface
.OUTPUTS
NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpoint[]
.EXAMPLE
Get-RpcEndpoint
Get all RPC registered RPC endpoints.
.EXAMPLE
Get-RpcEndpoint $Server
Get RPC endpoints for a parsed NDR server interface.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F"
Get RPC endpoints for a specified interface ID ignoring the version.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F" "1.0"
Get RPC endpoints for a specified interface ID and version.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F" "1.0" -FindAlpcPort
Get ALPC RPC endpoints for a specified interface ID and version by brute force.
.EXAMPLE
Get-RpcEndpoint -Binding "ncalrpc:[RPC_PORT]"
Get RPC endpoints for exposed over ncalrpc with name RPC_PORT.
.EXAMPLE
Get-RpcEndpoint -AlpcPort "RPC_PORT"
Get RPC endpoints for exposed over ALPC with name RPC_PORT.
.EXAMPLE
Get-RpcEndpoint -ProcessId 1234
Get RPC endpoints for exposed over ALPC for the process 1234.
#>
function Get-RpcEndpoint {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromId")]
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromIdAndVersion")]
        [Guid]$InterfaceId,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromIdAndVersion")]
        [NtCoreLib.Ndr.Rpc.RpcVersion]$InterfaceVersion,
        [parameter(Mandatory, ParameterSetName = "FromRpcServer", ValueFromPipeline)]
        $Server,
        [parameter(Mandatory, ParameterSetName = "FromBinding")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$Binding,
        [parameter(Mandatory, ParameterSetName = "FromAlpc")]
        [string]$AlpcPort,
        [parameter(Mandatory, ParameterSetName = "FromProcessId")]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(Mandatory, ParameterSetName = "FromServiceName")]
        [string]$ServiceName,
        [parameter(ParameterSetName = "FromIdAndVersion")]
        [parameter(ParameterSetName = "FromRpcServer")]
        [switch]$FindAlpcPort,
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromId")]
        [parameter(ParameterSetName = "FromIdAndVersion")]
        [parameter(ParameterSetName = "FromRpcClient")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$SearchBinding,
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromId")]
        [parameter(ParameterSetName = "FromIdAndVersion")]
        [parameter(ParameterSetName = "FromRpcClient")]
        [string[]]$ProtocolSequence = @(),
        [parameter(Mandatory, ParameterSetName = "FromRpcClient")]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client
    )

    PROCESS {
        $eps = switch ($PsCmdlet.ParameterSetName) {
            "All" {
                [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryAllEndpoints($SearchBinding)
            }
            "FromId" {
                [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryEndpointsForInterface($SearchBinding, $InterfaceId)
            }
            "FromIdAndVersion" {
                $syntax_id = [NtCoreLib.Ndr.Rpc.RpcSyntaxIdentifier]::new($InterfaceId, $InterfaceVersion)
                if ($FindAlpcPort) {
                    [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::FindAlpcEndpointForInterface($syntax_id)
                }
                else {
                    [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryEndpointsForInterface($SearchBinding, $syntax_id)
                }
            }
            "FromRpcServer" {
                if ($FindAlpcPort) {
                    [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::FindAlpcEndpointForInterface($Server.InterfaceId)
                }
                else {
                    [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryEndpointsForInterface($SearchBinding, $Server.InterfaceId)
                }
            }
            "FromBinding" {
                [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryEndpointsForBinding($Binding)
            }
            "FromAlpc" {
                [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryEndpointsForAlpcPort($AlpcPort)
            }
            "FromRpcClient" {
                [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryEndpointsForInterface($SearchBinding, $Client.InterfaceId)
            }
            "FromProcessId" {
                (Get-RpcAlpcServer -ProcessId $ProcessId).Endpoints
            }
            "FromServiceName" {
                try {
                    $service = Get-Win32Service -Name $ServiceName
                    if ($service.ProcessId -eq 0) {
                        throw "Service $ServiceName is not running."
                    }
                    Get-RpcEndPoint -ProcessId $service.ProcessId
                } catch {
                    Write-Error $_
                }
            }
        }

        if ($ProtocolSequence.Count -gt 0) {
            $eps = $eps | Where-Object {$_.ProtocolSequence -in $ProtocolSequence}
        }
        $eps | Write-Output
    }
}

Register-ArgumentCompleter -CommandName Get-RpcEndpoint -ParameterName ProtocolSequence -ScriptBlock $protseq_completer

<#
.SYNOPSIS
Get the RPC servers from a DLL.
.DESCRIPTION
This cmdlet parses the RPC servers from a DLL. Note that in order to parse 32 bit DLLs you must run this module in 32 bit PowerShell.
.PARAMETER FullName
The path to the DLL.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols. If not specified it will first use the _NT_SYMBOL_PATH environment variable then use the
default of 'srv*https://msdl.microsoft.com/download/symbols'
.PARAMETER AsText
Return the results as text rather than objects.
.PARAMETER RemoveComments
When outputing as text remove comments from the output.
.PARAMETER ParseClients
Also parse client interface information, otherwise only servers are returned.
.PARAMETER IgnoreSymbols
Don't resolve any symbol information.
.PARAMETER SerializedPath
Path to a serialized representation of the RPC servers.
.PARAMETER ResolveStructureNames
If private symbols available try and resolve the names of structures and parameters.
.PARAMETER SymSrvFallback
Specify to use a built-in fallback for symbol server resolving when using the system dbghelp DLL. You also need to specify a local cache directory in SymbolPath.
.PARAMETER ProcessId
Specify a process to extract the RPC servers from. This parses all the modules in a process for any available servers.
.PARAMETER ServiceName
Specify the name of a service to extract the RPC servers from.
.PARAMETER IgnoreNdr64
Specify to not parse NDR64 byte code.
.INPUTS
string[] List of paths to DLLs.
.OUTPUTS
RpcServer[] The parsed RPC servers.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll
Get the list of RPC servers from rpcss.dll.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -AsText
Get the list of RPC servers from rpcss.dll, return it as text.
.EXAMPLE
Get-ChildItem c:\windows\system32\*.dll | Get-RpcServer
Get the list of RPC servers from all DLLs in system32, return it as text.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -DbgHelpPath c:\windbg\x64\dbghelp.dll
Get the list of RPC servers from rpcss.dll, specifying a different DBGHELP for symbol resolving.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -SymbolPath c:\symbols
Get the list of RPC servers from rpcss.dll, specifying a different symbol path.
.EXAMPLE
Get-RpcServer -SerializedPath rpc.bin
Get the list of RPC servers from the serialized file rpc.bin.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -SymSrvFallback -SymbolPath c:\symbols
Get the list of RPC servers from rpcss.dll, use symbol server fallback with c:\symbols as the cache directory.
#>
function Get-RpcServer {
    [CmdletBinding(DefaultParameterSetName = "FromDll")]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = "FromDll")]
        [alias("Path")]
        [string]$FullName,
        [parameter(Mandatory, ParameterSetName = "FromSerialized")]
        [string]$SerializedPath,
        [parameter(Mandatory, ParameterSetName = "FromProcessId")]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(Mandatory, ParameterSetName = "FromServiceName")]
        [string]$ServiceName,
        [parameter(ParameterSetName = "FromDll")]
        [parameter(ParameterSetName = "FromProcessId")]
        [parameter(ParameterSetName = "FromServiceName")]
        [string]$DbgHelpPath,
        [parameter(ParameterSetName = "FromDll")]
        [parameter(ParameterSetName = "FromProcessId")]
        [parameter(ParameterSetName = "FromServiceName")]
        [string]$SymbolPath,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$ParseClients,
        [parameter(ParameterSetName = "FromDll")]
        [parameter(ParameterSetName = "FromProcessId")]
        [parameter(ParameterSetName = "FromServiceName")]
        [switch]$IgnoreSymbols,
        [parameter(ParameterSetName = "FromDll")]
        [parameter(ParameterSetName = "FromProcessId")]
        [parameter(ParameterSetName = "FromServiceName")]
        [switch]$ResolveStructureNames,
        [parameter(ParameterSetName = "FromDll")]
        [parameter(ParameterSetName = "FromProcessId")]
        [parameter(ParameterSetName = "FromServiceName")]
        [switch]$SymSrvFallback,
        [parameter(ParameterSetName = "FromDll")]
        [parameter(ParameterSetName = "FromProcessId")]
        [parameter(ParameterSetName = "FromServiceName")]
        [switch]$IgnoreNdr64,
        [switch]$AsText,
        [switch]$RemoveComments
    )

    BEGIN {
        $ParserFlags = [NtCoreLib.Win32.Rpc.Server.RpcServerParserFlags]::None
        if ($ParseClients) {
            $ParserFlags = $ParserFlags -bor [NtCoreLib.Win32.Rpc.Server.RpcServerParserFlags]::ParseClients
        }
        if ($IgnoreSymbols) {
            $ParserFlags = $ParserFlags -bor [NtCoreLib.Win32.Rpc.Server.RpcServerParserFlags]::IgnoreSymbols
        }
        if ($ResolveStructureNames) {
            $ParserFlags = $ParserFlags -bor [NtCoreLib.Win32.Rpc.Server.RpcServerParserFlags]::ResolveStructureNames
        }
        if ($SymSrvFallback) {
            $ParserFlags = $ParserFlags -bor [NtCoreLib.Win32.Rpc.Server.RpcServerParserFlags]::SymSrvFallback
        }
        if ($IgnoreNdr64) {
            $ParserFlags = $ParserFlags -bor [NtCoreLib.Win32.Rpc.Server.RpcServerParserFlags]::IgnoreNdr64
        }
    }

    PROCESS {
        try {
            $servers = switch($PSCmdlet.ParameterSetName) {
                "FromDll" {
                    $FullName = Resolve-Path -LiteralPath $FullName -ErrorAction Stop
                    Write-Progress -Activity "Parsing RPC Servers" -CurrentOperation "$FullName"
                    [NtCoreLib.Win32.Rpc.Server.RpcServer]::ParsePeFile($FullName, $DbgHelpPath, $SymbolPath, $ParserFlags)
                }
                "FromSerialized" {
                    $FullName = Resolve-Path -LiteralPath $SerializedPath -ErrorAction Stop
                    Use-NtObject($stm = [System.IO.File]::OpenRead($FullName)) {
                        while ($stm.Position -lt $stm.Length) {
                            [NtCoreLib.Win32.Rpc.Server.RpcServer]::Deserialize($stm) | Write-Output
                        }
                    }
                }
                "FromProcessId" {
                    $proc = Get-Process -PID $ProcessId
                    if ($null -eq $proc.SafeHandle) {
                        throw "Can't open process $ProcessId"
                    }
                    $proc.Modules | 
                    % { 
                        Get-RpcServer -FullName $_.FileName -DbgHelpPath $DbgHelpPath -SymbolPath $SymbolPath `
                            -IgnoreSymbols:$IgnoreSymbols -ResolveStructureNames:$ResolveStructureNames -SymSrvFallback:$SymSrvFallback 
                    }
                }
                "FromServiceName" {
                    $service = Get-Win32Service -Name $ServiceName
                    if ($service.ProcessId -eq 0) {
                        throw "Service $ServiceName is not running."
                    } else {
                        Get-RpcServer -ProcessId $service.ProcessId -DbgHelpPath $DbgHelpPath -SymbolPath $SymbolPath `
                            -IgnoreSymbols:$IgnoreSymbols -ResolveStructureNames:$ResolveStructureNames -SymSrvFallback:$SymSrvFallback 
                    }
                }
            }

            if ($null -ne $servers) {
                if ($AsText) {
                    foreach ($server in $servers) {
                        $text = $server.FormatAsText($RemoveComments)
                        Write-Output $text
                    }
                }
                else {
                    Write-Output $servers
                }
            }
        }
        catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Set a list RPC servers to a file for storage.
.DESCRIPTION
This cmdlet serializes a list of RPC servers to a file. This can be restored using Get-RpcServer -SerializedPath.
.PARAMETER Path
The path to the output file.
.PARAMETER Server
The list of servers to serialize.
.INPUTS
RpcServer[] List of paths to DLLs.
.OUTPUTS
None
.EXAMPLE
Set-RpcServer -Server $server -Path rpc.bin
Serialize servers to file rpc.bin.
#>
function Set-RpcServer {
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Server.RpcServer[]]$Server,
        [parameter(Mandatory = $true, Position = 1)]
        [string]$Path
    )

    BEGIN {
        "" | Set-Content -Path $Path
        $Path = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        $stm = [System.IO.File]::Create($Path)
    }

    PROCESS {
        try {
            foreach ($s in $Server) {
                $s.Serialize($stm)
            }
        }
        catch {
            Write-Error $_
        }
    }

    END {
        $stm.Close()
    }
}

<#
.SYNOPSIS
Format the RPC servers as text.
.DESCRIPTION
This cmdlet formats a list of RPC servers as text.
.PARAMETER RpcServer
The RPC servers to format.
.PARAMETER RemoveComments
Specify to remove comments from the output.
.PARAMETER DisableTypeDefs
Specify to not use typedefs in the output.
.PARAMETER Format
Format output in a different language type.
.INPUTS
RpcServer[] The RPC servers to format.
.OUTPUTS
string[] The formatted RPC servers.
.EXAMPLE
Format-RpcServer $rpc
Format list of RPC servers in $rpc.
.EXAMPLE
Format-RpcServer $rpc -RemoveComments
Format list of RPC servers in $rpc without comments.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll | Format-RpcServer
Get the list of RPC servers from rpcss.dll and format them.
#>
function Format-RpcServer {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Server.RpcServer[]]$RpcServer,
        [switch]$RemoveComments,
        [switch]$DisableTypeDefs,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl"
    )

    PROCESS {
        $flags = if ($DisableTypeDefs) {
            [NtCoreLib.Ndr.Formatter.NdrFormatterFlags]::None
        } else {
            [NtCoreLib.Ndr.Formatter.NdrFormatterFlags]::EnableTypeDefs
        }
        if ($RemoveComments) {
            $flags = $flags -bor [NtCoreLib.Ndr.Formatter.NdrFormatterFlags]::RemoveComments
        }
        foreach ($server in $RpcServer) {
            $server.FormatAsText($flags, $Format) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets a list of ALPC RPC servers.
.DESCRIPTION
This cmdlet gets a list of ALPC RPC servers. This relies on being able to access the list of ALPC ports in side a process so might need elevated privileges.
.PARAMETER ProcessId
The ID of a process to query for ALPC servers.
.PARAMETER AlpcPort
The path to the ALPC port to query.
.PARAMETER IgnoreComInterface
Ignore COM only interfaces.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Server.RpcAlpcServer[]
.EXAMPLE
Get-RpcAlpcServer
Get all ALPC RPC servers.
.EXAMPLE
Get-RpcAlpcServer -ProcessId 1234
Get all ALPC RPC servers in process ID 1234.
.EXAMPLE
Get-RpcAlpcServer -AlpcPort "\RPC Control\srvsvc"
Get the ALPC RPC servers for the srvsvc ALPC port. Needs Windows 10 19H1 and above to work.
#>
function Get-RpcAlpcServer {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcessId")]
        [int]$ProcessId,
        [parameter(Mandatory, ParameterSetName = "FromAlpc")]
        [string]$AlpcPort,
        [switch]$IgnoreComInterface
    )

    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null
    switch ($PsCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Rpc.Server.RpcAlpcServer]::GetAlpcServers($IgnoreComInterface)
        }
        "FromProcessId" {
            [NtCoreLib.Win32.Rpc.Server.RpcAlpcServer]::GetAlpcServers($ProcessId, $IgnoreComInterface)
        }
        "FromAlpc" {
            [NtCoreLib.Win32.Rpc.Server.RpcAlpcServer]::GetAlpcServer($AlpcPort, $IgnoreComInterface)
        }
    }
}

<#
.SYNOPSIS
Get a RPC client object based on a parsed RPC server.
.DESCRIPTION
This cmdlet creates a new RPC client from a parsed RPC server. The client object contains methods
to call RPC methods. The client starts off disconnected. You need to pass the client to Connect-RpcClient to
connect to the server. If you specify an interface ID and version then a generic client will be created which
allows simple calls to be made without requiring the NDR data.
.PARAMETER Server
Specify the RPC server to base the client on.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER ClientName
Specify the class name of the compiled client.
.PARAMETER IgnoreCache
Specify to ignore the compiled client cache and regenerate the source code.
.PARAMETER InterfaceId
Specify the interface ID for a generic client.
.PARAMETER InterfaceVersion
Specify the interface version for a generic client.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Flags
Specify optional flags for the built client class.
.PARAMETER EnableDebugging
Specify to enable debugging on the compiled code.
.PARAMETER UseAddType
Specify to try and use the Add-Type command instead of the C# compiler to build the client.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Client.RpcClientBase
.EXAMPLE
Get-RpcClient -Server $Server
Create a new RPC client from a parsed RPC server.
#>
function Get-RpcClient {
    [CmdletBinding(DefaultParameterSetName = "FromServer")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromServer", ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Server.RpcServer]$Server,
        [parameter(ParameterSetName = "FromServer")]
        [string]$NamespaceName,
        [parameter(ParameterSetName = "FromServer")]
        [string]$ClientName,
        [parameter(ParameterSetName = "FromServer")]
        [switch]$IgnoreCache,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromIdAndVersion")]
        [string]$InterfaceId,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromIdAndVersion")]
        [NtCoreLib.Ndr.Rpc.RpcVersion]$InterfaceVersion,
        [parameter(ParameterSetName = "FromServer")]
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [parameter(ParameterSetName = "FromServer")]
        [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderFlags]$Flags = "GenerateConstructorProperties, StructureReturn, HideWrappedMethods, UnsignedChar, NoNamespace, MarshalPipesAsArrays, GenerateTypeStrictHandles",
        [switch]$EnableDebugging,
        [switch]$UseAddType
    )

    BEGIN {
        if (Get-IsPSCore) {
            if ($null -ne $Provider) {
                Write-Warning "PowerShell Core doesn't support arbitrary providers. Using in-built C#."
            }
            if ([NtObjectManager.Utils.CoreCSharpCodeProvider]::IsSupported) {
                $Provider = New-Object NtObjectManager.Utils.CoreCSharpCodeProvider
            } else {
                $UseAddType = $true
                $AsmName = [NtCoreLib.Win32.Rpc.Client.RpcClientBase].Assembly.FullName
            }
        }
        if ($UseAddType) {
            $Flags = $Flags -band (-bnot [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderFlags]::NoNamespace)
            $flags = $Flags -bor [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderFlags]::ExcludeVariableSourceText
        }
    }

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromServer") {
            if ($UseAddType) {
                $src = Format-RpcClient -Server $Server -ClientName $ClientName -Flags $Flags
                $ts = Add-Type -TypeDefinition $src -ReferencedAssemblies $AsmName,'mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089','System.Collections, Version=0.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a' -PassThru
                foreach($t in $ts) {
                    if ($t.BaseType -eq [NtCoreLib.Win32.Rpc.Client.RpcClientBase]) {
                        New-Object $t.AssemblyQualifiedName
                        break
                    }
                }
            } else {
                $args = [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderArguments]::new();
                $args.NamespaceName = $NamespaceName
                $args.ClientName = $ClientName
                $args.Flags = $Flags
                $args.EnableDebugging = $EnableDebugging

                [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilder]::CreateClient($Server, $args, $IgnoreCache, $Provider)
            }
        }
        else {
            [NtCoreLib.Win32.Rpc.Client.RpcClient]::new($InterfaceId, $InterfaceVersion)
        }
    }
}

<#
.SYNOPSIS
Connects a RPC client to an endpoint.
.DESCRIPTION
This cmdlet connects a RPC client to an endpoint. You can specify what transport to use based on the protocol sequence.
.PARAMETER Client
Specify the RPC client to connect.
.PARAMETER ProtocolSequence
Specify the RPC protocol sequence this client will connect through.
.PARAMETER EndpointPath
Specify the endpoint string. If not specified this will lookup the endpoint from the endpoint mapper.
.PARAMETER NetworkAddress
Specify the network address. If not specified the local system will be used.
.PARAMETER SecurityQualityOfService
Specify the security quality of service for the connection.
.PARAMETER Credentials
Specify user credentials for the RPC client authentication.
.PARAMETER ServicePrincipalName
Specify service principal name for the RPC client authentication.
.PARAMETER AuthenticationLevel
Specify authentication level for the RPC client authentication.
.PARAMETER AuthenticationType
Specify authentication type for the RPC client authentication.
.PARAMETER AuthenticationCapabilities
Specify authentication capabilities for the RPC client authentication.
.PARAMETER PassThru
Specify to the pass the client object to the output.
.PARAMETER FindAlpcPort
Specify to search for an ALPC port for the RPC client.
.PARAMETER Force
Specify to for the client to connect even if the client is already connected to another transport.
.PARAMETER Configuration
Specify low-level transport configuration.
.INPUTS
NtCoreLib.Win32.Rpc.Client.RpcClientBase[]
.OUTPUTS
NtCoreLib.Win32.Rpc.Client.RpcClientBase[]
.EXAMPLE
Connect-RpcClient -Client $Client
Connect an RPC ALPC client, looking up the path using the endpoint mapper.
.EXAMPLE
Connect-RpcClient -Client $Client -EndpointPath "\RPC Control\ABC"
Connect an RPC ALPC client with an explicit path.
.EXAMPLE
Connect-RpcClient -Client $Client -SecurityQualityOfService $(New-NtSecurityQualityOfService -ImpersonationLevel Anonymous)
Connect an RPC ALPC client with anonymous impersonation level.
.EXAMPLE
Connect-RpcClient -Client $Client -ProtocolSequence "ncalrpc"
Connect an RPC ALPC client from a specific protocol sequence.
.EXAMPLE
Connect-RpcClient -Client $Client -Endpoint $ep
Connect an RPC client to a specific endpoint.
.EXAMPLE
Connect-RpcClient -Client $Client -FindAlpcPort
Connect an RPC ALPC client, looking up the path using brute force.
#>
function Connect-RpcClient {
    [CmdletBinding(DefaultParameterSetName = "FromProtocol")]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client,
        [parameter(Position = 1, ParameterSetName = "FromProtocol")]
        [string]$EndpointPath,
        [parameter(ParameterSetName = "FromProtocol")]
        [string]$ProtocolSequence = "ncalrpc",
        [parameter(ParameterSetName = "FromProtocol")]
        [string]$NetworkAddress,
        [parameter(Position = 1, Mandatory, ParameterSetName = "FromEndpoint")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpoint]$Endpoint,
        [parameter(Mandatory, ParameterSetName = "FromFindEndpoint")]
        [switch]$FindAlpcPort,
        [parameter(ParameterSetName = "FromBindingString")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$StringBinding,
        [NtCoreLib.Security.Token.SecurityQualityOfService]$SecurityQualityOfService,
        [NtCoreLib.Win32.Security.Authentication.AuthenticationCredentials]$Credentials,
        [string]$ServicePrincipalName,
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationLevel]$AuthenticationLevel = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationType]$AuthenticationType = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationCapabilities]$AuthenticationCapabilities = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcClientTransportConfiguration]$Configuration,
        [switch]$PassThru,
        [switch]$Force
    )

    BEGIN {
        $security = New-RpcTransportSecurity -SecurityQualityOfService $SecurityQualityOfService `
            -Credentials $Credentials -ServicePrincipalName $ServicePrincipalName `
            -AuthenticationLevel $AuthenticationLevel -AuthenticationType $AuthenticationType `
            -AuthenticationCapabilities $AuthenticationCapabilities
    }

    PROCESS {
        if ($Force) {
            Disconnect-RpcClient -Client $Client
        }
        switch ($PSCmdlet.ParameterSetName) {
            "FromProtocol" {
                $Client.Connect($ProtocolSequence, $EndpointPath, $NetworkAddress, $security, $Configuration)
            }
            "FromEndpoint" {
                $Client.Connect($Endpoint, $security, $Configuration)
            }
            "FromFindEndpoint" {
                foreach ($ep in $(Get-ChildItem "NtObject:\RPC Control")) {
                    try {
                        $name = $ep.Name
                        Write-Progress -Activity "Finding ALPC Endpoint" -CurrentOperation "$name"
                        $Client.Connect("ncalrpc", $name, [NullString]::Value, $security)
                    }
                    catch {
                        Write-Information $_
                    }
                }
            }
            "FromBindingString" {
                $Client.Connect($StringBinding, $security, $Configuration)
            }
        }

        if ($PassThru) {
            $Client | Write-Output
        }
    }
}

Register-ArgumentCompleter -CommandName Connect-RpcClient -ParameterName ProtocolSequence -ScriptBlock $protseq_completer

<#
.SYNOPSIS
Disconnect an RPC client.
.DESCRIPTION
This cmdlet disconnects a RPC client from an endpoint.
.PARAMETER Client
Specify the RPC client to disconnect.
.PARAMETER PassThru
Specify to the pass the client object to the output.
.INPUTS
NtCoreLib.Win32.Rpc.Client.RpcClientBase[]
.OUTPUTS
NtCoreLib.Win32.Rpc.Client.RpcClientBase[]
.EXAMPLE
Disconnect-RpcClient -Client $Client
Disconnect an RPC ALPC client.
#>
function Disconnect-RpcClient {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client,
        [switch]$PassThru
    )

    PROCESS {
        $Client.Disconnect()

        if ($PassThru) {
            $Client | Write-Output
        }
    }
}

<#
.SYNOPSIS
Format a RPC client as source code based on a parsed RPC server.
.DESCRIPTION
This cmdlet gets source code for a RPC client from a parsed RPC server.
.PARAMETER Server
Specify the RPC server to base the client on.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER ClientName
Specify the class name of the compiled client.
.PARAMETER Flags
Specify to flags for the source creation.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Options
Specify optional options for the code generation if Provider is also specified.
.PARAMETER OutputPath
Specify optional output directory to write formatted client.
.PARAMETER GroupByName
Specify when outputting to a directory to group by the name of the server executable.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-RpcClient -Server $Server
Get the source code for a RPC client from a parsed RPC server.
.EXAMPLE
$servers | Format-RpcClient
Get the source code for RPC clients from a list of parsed RPC servers.
.EXAMPLE
$servers | Format-RpcClient -OutputPath rpc_output
Get the source code for RPC clients from a list of parsed RPC servers and output as separate source code files.
#>
function Format-RpcClient {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Server.RpcServer[]]$Server,
        [string]$NamespaceName,
        [string]$ClientName,
        [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderFlags]$Flags = 0,
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [System.CodeDom.Compiler.CodeGeneratorOptions]$Options,
        [string]$OutputPath,
        [switch]$GroupByName
    )

    BEGIN {
        $file_ext = "cs"
        if ($null -ne $Provider) {
            $file_ext = $Provider.FileExtension
        }

        if ("" -ne $OutputPath) {
            mkdir $OutputPath -ErrorAction Ignore | Out-Null
        }
    }

    PROCESS {
        $args = [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderArguments]::new();
        $args.NamespaceName = $NamespaceName
        $args.ClientName = $ClientName
        $args.Flags = $Flags

        foreach ($s in $Server) {
            $src = if ($null -eq $Provider) {
                [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilder]::BuildSource($s, $args)
            }
            else {
                [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilder]::BuildSource($s, $args, $Provider, $Options)
            }

            if ("" -eq $OutputPath) {
                $src | Write-Output
            }
            else {
                if ($GroupByName) {
                    $path = Join-Path -Path $OutputPath -ChildPath $s.Name.ToLower()
                    mkdir $path -ErrorAction Ignore | Out-Null
                } else {
                    $path = $OutputPath
                }
                $path = Join-Path -Path $path -ChildPath "$($s.InterfaceId)_$($s.InterfaceVersion).$file_ext"
                $src | Set-Content -Path $path
            }
        }
    }
}

<#
.SYNOPSIS
Format RPC complex types to an encoder/decoder source code file.
.DESCRIPTION
This cmdlet gets source code for encoding and decoding RPC complex types.
.PARAMETER ComplexType
Specify the list of complex types to format.
.PARAMETER Server
Specify the server containing the list of complex types to format.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER EncoderName
Specify the class name of the encoder.
.PARAMETER DecoderName
Specify the class name of the decoder.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Options
Specify optional options for the code generation if Provider is also specified.
.PARAMETER Pointer
Specify to always wrap complex types in an unique pointer.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-RpcComplexType -Server $Server
Get the source code for RPC complex types client from a parsed RPC server.
.EXAMPLE
Format-RpcComplexType -ComplexType $ComplexTypes
Get the source code for RPC complex types client from a list of types.
#>
function Format-RpcComplexType {
    [CmdletBinding(DefaultParameterSetName = "FromTypes")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromTypes")]
        [NtCoreLib.Ndr.Dce.NdrComplexTypeReference[]]$ComplexType,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromServer")]
        [NtCoreLib.Win32.Rpc.Server.RpcServer]$Server,
        [string]$NamespaceName,
        [string]$EncoderName,
        [string]$DecoderName,
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [System.CodeDom.Compiler.CodeGeneratorOptions]$Options,
        [switch]$Pointer
    )

    PROCESS {
        $types = switch ($PsCmdlet.ParameterSetName) {
            "FromTypes" { $ComplexType }
            "FromServer" { $Server.ComplexTypes }
        }
        if ($null -eq $Provider) {
            [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilder]::BuildSource([NtCoreLib.Ndr.Dce.NdrComplexTypeReference[]]$types, $EncoderName, $DecoderName, $NamespaceName, $Pointer) | Write-Output
        }
        else {
            [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilder]::BuildSource([NtCoreLib.Ndr.Dce.NdrComplexTypeReference[]]$types, $EncoderName, $DecoderName, $NamespaceName, $Pointer, $Provider, $Options) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get a new RPC context handle.
.DESCRIPTION
This cmdlet creates a new RPC context handle for calling RPC APIs.
.PARAMETER Uuid
The UUID for the context handle.
.PARAMETER Attributes
The attribute flags for the context handle.
.INPUTS
None
.OUTPUTS
NtCoreLib.Ndr.Marshal.NdrContextHandle
.EXAMPLE
New-RpcContextHandle
Creates a new RPC context handle.
#>
function New-RpcContextHandle {
    param(
        [guid]$Uuid = [guid]::Empty,
        [int]$Attributes = 0
    )
    [NtCoreLib.Ndr.Marshal.NdrContextHandle]::new($Attributes, $Uuid)
}

<#
.SYNOPSIS
Get an RPC string binding from its parts.
.DESCRIPTION
This cmdlet gets an RPC string binding based on its component parts.
.PARAMETER ProtocolSequence
Specify the RPC protocol sequence .
.PARAMETER Endpoint
Specify the endpoint string.
.PARAMETER NetworkAddress
Specify the network address.
.PARAMETER ObjectUuid
Specify the object UUID.
.PARAMETER Options
Specify the options.
.PARAMETER AsObject
Specify to return the binding as an object.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Get-RpcStringBinding -ProtocolSequence "ncalrpc"
Connect an RPC ALPC string binding from a specific protocol sequence.
#>
function Get-RpcStringBinding {
    [CmdletBinding(DefaultParameterSetName = "FromProtocol")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$ProtocolSequence,
        [parameter(Position = 1)]
        [string]$Endpoint,
        [parameter(Position = 2)]
        [string]$NetworkAddress,
        [parameter(Position = 3)]
        [System.Nullable[Guid]]$ObjectUuid,
        [parameter(Position = 4)]
        [string]$Options,
        [switch]$AsObject
    )

    $binding = [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]::new($ProtocolSequence, $NetworkAddress, $Endpoint, $Options, $ObjectUuid)
    if ($AsObject) {
        $binding
    } else {
        $binding.ToString()
    }
}

Register-ArgumentCompleter -CommandName Get-RpcStringBinding -ParameterName ProtocolSequence -ScriptBlock $protseq_completer

<#
.SYNOPSIS
Creates a NDR parser for a process.
.DESCRIPTION
This cmdlet creates a new NDR parser for the given process.
.PARAMETER Process
The process to create the NDR parser on. If not specified then the current process is used.
.PARAMETER SymbolResolver
Specify a symbol resolver for the parser. Note that this should be a resolver for the same process as we're parsing.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
NtCoreLib.Ndr.Parser.NdrParser - The NDR parser.
.EXAMPLE
$ndr = New-NdrParser
Get an NDR parser for the current process.
.EXAMPLE
New-NdrParser -Process $p -SymbolResolver $resolver
Get an NDR parser for a specific process with a known resolver.
#>
function New-NdrParser {
    Param(
        [NtCoreLib.NtProcess]$Process,
        [NtCoreLib.Win32.Debugger.Symbols.ISymbolResolver]$SymbolResolver,
        [NtCoreLib.Ndr.Parser.NdrParserFlags]$ParserFlags = 0
    )
    [NtCoreLib.Ndr.Parser.NdrParser]::new($Process, $SymbolResolver, $ParserFlags)
}

function Convert-HashTableToIidNames {
    Param(
        [Hashtable]$IidToName,
        [NtCoreLib.Ndr.Com.NdrComProxy[]]$Proxy
    )
    $dict = [System.Collections.Generic.Dictionary[Guid, string]]::new()
    if ($null -ne $IidToName) {
        foreach ($pair in $IidToName.GetEnumerator()) {
            $guid = [Guid]::new($pair.Key)
            $dict.Add($guid, $pair.Value)
        }
    }

    if ($null -ne $Proxy) {
        foreach ($p in $Proxy.Interfaces) {
            $dict.Add($p.Iid, $p.Name)
        }
    }

    if (!$dict.ContainsKey("00000000-0000-0000-C000-000000000046")) {
        $dict.Add("00000000-0000-0000-C000-000000000046", "IUnknown")
    }

    if (!$dict.ContainsKey("00020400-0000-0000-C000-000000000046")) {
        $dict.Add("00020400-0000-0000-C000-000000000046", "IDispatch")
    }

    return $dict
}

<#
.SYNOPSIS
Parses COM proxy information from a DLL.
.DESCRIPTION
This cmdlet parses the COM proxy information from a specified DLL.
.PARAMETER Path
The path to the DLL containing the COM proxy information.
.PARAMETER Clsid
Optional CLSID for the object used to find the proxy information.
.PARAMETER Iids
Optional list of IIDs to parse from the proxy information.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
The parsed proxy information and complex types.
.EXAMPLE
$p = Get-NdrComProxy c:\path\to\proxy.dll
Parse the proxy information from c:\path\to\proxy.dll
.EXAMPLE
$p = Get-NdrComProxy $env:SystemRoot\system32\combase.dll -Clsid "00000320-0000-0000-C000-000000000046"
Parse the proxy information from combase.dll with a specific proxy CLSID.
.EXAMPLE
$p = Get-NdrComProxy $env:SystemRoot\system32\combase.dll -Clsid "00000320-0000-0000-C000-000000000046" -Iid "00000001-0000-0000-c000-000000000046"
Parse the proxy information from combase.dll with a specific proxy CLSID, only returning a specific IID.
#>
function Get-NdrComProxy {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [Guid]$Clsid = [Guid]::Empty,
        [NtCoreLib.Win32.Debugger.Symbols.ISymbolResolver]$SymbolResolver,
        [Guid[]]$Iid,
        [NtCoreLib.Ndr.Parser.NdrParserFlags]$ParserFlags = 0
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver -NdrParserFlags $ParserFlags) {
        $proxies = $parser.ReadFromComProxyFile($Path, $Clsid, $Iid) | Write-Output
        $props = @{
            Path         = $Path;
            Proxies      = $proxies;
            IidToNames   = Convert-HashTableToIidNames -Proxy $proxies;
        }
        $obj = New-Object -TypeName PSObject -Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Format an NDR procedure.
.DESCRIPTION
This cmdlet formats a parsed NDR procedure.
.PARAMETER Procedure
The procedure to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.PARAMETER Format
The output text format.
.OUTPUTS
string - The formatted procedure.
.EXAMPLE
Format-NdrProcedure $proc
Format a procedure.
.EXAMPLE
$procs | Format-NdrProcedure
Format a list of procedures from a pipeline.
.EXAMPLE
Format-NdrProcedure $proc -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a procedure with a known IID to name mapping.
#>
function Format-NdrProcedure {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline = $true)]
        [NtCoreLib.Ndr.Dce.NdrProcedureDefinition]$Procedure,
        [Hashtable]$IidToName,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl"
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
        $formatter = [NtCoreLib.Ndr.Formatter.NdrFormatter]::Create($Format, $dict)
    }

    PROCESS {
        $fmt = $formatter.FormatProcedure($Procedure)
        Write-Output $fmt
    }
}

<#
.SYNOPSIS
Format an NDR complex type.
.DESCRIPTION
This cmdlet formats a parsed NDR complex type.
.PARAMETER ComplexType
The complex type to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.PARAMETER Format
The output text format.
.OUTPUTS
string - The formatted complex type.
.EXAMPLE
Format-NdrComplexType $type
Format a complex type.
.EXAMPLE
$cts | Format-NdrComplexType
Format a list of complex types from a pipeline.
.EXAMPLE
Format-NdrComplexType $type -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a complex type with a known IID to name mapping.
#>
function Format-NdrComplexType {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Ndr.Dce.NdrComplexTypeReference[]]$ComplexType,
        [Hashtable]$IidToName,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl"
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
        $formatter = [NtCoreLib.Ndr.Formatter.NdrFormatter]::Create($Format, $dict)
    }

    PROCESS {
        foreach ($t in $ComplexType) {
            $formatter.FormatComplexType($t) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Format an NDR COM proxy.
.DESCRIPTION
This cmdlet formats a parsed NDR COM proxy.
.PARAMETER Proxy
The proxy to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.PARAMETER DemangleComName
A script block which demangles a COM name (for WinRT types)
.PARAMETER Format
The output text format.
.OUTPUTS
string - The formatted proxy.
.EXAMPLE
Format-NdrComProxy $proxy
Format a COM proxy.
.EXAMPLE
$proxies | Format-NdrComProxy
Format a list of COM proxies from a pipeline.
.EXAMPLE
Format-NdrComProxy $proxy -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a COM proxy with a known IID to name mapping.
#>
function Format-NdrComProxy {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Ndr.Com.NdrComProxy]$Proxy,
        [Hashtable]$IidToName,
        [ScriptBlock]$DemangleComName,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl"
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
    }

    PROCESS {
         $formatter = if ($null -eq $DemangleComName) {
            [NtCoreLib.Ndr.Formatter.NdrFormatter]::Create($Format, $dict)
        }
        else {
            [NtCoreLib.Ndr.Formatter.NdrFormatter]::Create($Format, $dict, [Func[string, string]]$DemangleComName)
        }
        $formatter.ComProxies.AddRange($Proxy.Interfaces)
        $formatter.ComplexTypes.AddRange($Proxy.ComplexTypes)
        $formatter.Format() | Write-Output
    }
}

<#
.SYNOPSIS
Parses RPC server information from an executable.
.DESCRIPTION
This cmdlet parses the RPC server information from a specified executable with a known offset.
.PARAMETER Path
The path to the executable containing the RPC server information.
.PARAMETER Offset
The offset into the executable where the RPC_SERVER_INTERFACE structure is loaded.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
The parsed RPC server information and complex types.
.EXAMPLE
$p = Get-NdrRpcServerInterface c:\path\to\server.dll 0x18000
Parse the RPC server information from c:\path\to\proxy.dll with offset 0x18000
#>
function Get-NdrRpcServerInterface {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [parameter(Mandatory, Position = 1)]
        [int]$Offset,
        [NtCoreLib.Win32.Debugger.Symbols.ISymbolResolver]$SymbolResolver,
        [NtCoreLib.Ndr.Parser.NdrParserFlags]$ParserFlags = 0
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver -ParserFlags $ParserFlags) {
        $rpc_server = $parser.ReadFromRpcServerInterface($Path, $Offset)
        $props = @{
            Path         = $Path;
            RpcServer    = $rpc_server;
        }
        $obj = New-Object -TypeName PSObject -Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Format an RPC server interface type.
.DESCRIPTION
This cmdlet formats a parsed RPC server interface type.
.PARAMETER RpcServer
The RPC server interface to format.
.PARAMETER Format
The output text format.
.OUTPUTS
string - The formatted RPC server interface.
.EXAMPLE
Format-NdrRpcServerInterface $type
Format an RPC server interface type.
#>
function Format-NdrRpcServerInterface {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [NtCoreLib.Ndr.Rpc.RpcServerInterface]$RpcServer,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl"
    )

    BEGIN {
        $formatter = [NtCoreLib.Ndr.Formatter.NdrFormatter]::Create($Format)
    }

    PROCESS {
        $fmt = $formatter.FormatRpcServerInterface($RpcServer)
        Write-Output $fmt
    }
}

<#
.SYNOPSIS
Get NDR complex types from memory.
.DESCRIPTION
This cmdlet parses NDR complex type information from a location in memory.
.PARAMETER PicklingInfo
Specify pointer to the MIDL_TYPE_PICKLING_INFO structure.
.PARAMETER StubDesc
Specify pointer to the MIDL_STUB_DESC structure.
.PARAMETER StublessProxy
Specify pointer to the MIDL_STUBLESS_PROXY_INFO structure.
.PARAMETER OffsetTable
Specify pointer to type offset table.
.PARAMETER TypeIndex
Specify list of type index into type offset table.
.PARAMETER TypeFormat
Specify list of type format string addresses for the types.
.PARAMETER TypeOffset
Specify list of type offsets into the format string for the types.
.PARAMETER Process
Specify optional process which contains the types.
.PARAMETER Module
Specify optional module base address for the types. If set all pointers
are relative offsets from the module address.
.INPUTS
None
.OUTPUTS
NdrComplexTypeReference[]
#>
function Get-NdrComplexType {
    [CmdletBinding(DefaultParameterSetName="FromDecode3")]
    Param(
        [Parameter(Mandatory)]
        [long]$PicklingInfo,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2")]
        [Parameter(Mandatory, ParameterSetName = "FromDecode2Offset")]
        [long]$StubDesc,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2")]
        [long[]]$TypeFormat,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2Offset")]
        [int[]]$TypeOffset,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [long]$StublessProxy,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [long]$OffsetTable,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [int[]]$TypeIndex,
        [NtCoreLib.Win32.Loader.SafeLoadLibraryHandle]$Module,
        [NtCoreLib.NtProcess]$Process,
        [NtCoreLib.Ndr.Parser.NdrParserFlags]$Flags = "IgnoreUserMarshal"
    )

    $base_address = 0
    if ($null -ne $Module) {
        $base_address = $Module.DangerousGetHandle().ToInt64()
    }

    switch($PSCmdlet.ParameterSetName) {
        "FromDecode2" {
            $type_offset = $TypeFormat | % { [intptr]($_ + $base_address) }
            [NtCoreLib.Ndr.Parser.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StubDesc+$base_address, $type_offset, $Flags) | Write-Output
        }
        "FromDecode2Offset" {
            [NtCoreLib.Ndr.Parser.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StubDesc+$base_address, $TypeOffset, $Flags) | Write-Output
        }
        "FromDecode3" {
            [NtCoreLib.Ndr.Parser.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StublessProxy+$base_address, $OffsetTable+$base_address, $TypeIndex, $Flags) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets an ALPC server port.
.DESCRIPTION
This cmdlet gets an ALPC server port by name. As you can't directly open the server end of the port this function goes through
all handles and tries to extract the port from the hosting process. This might require elevated privileges, especially debug
privilege, to work correctly.
.PARAMETER Path
The path to the ALPC server port to get.
.PARAMETER ProcessId
The process ID of the process to query for ALPC servers.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtAlpc
.EXAMPLE
Get-NtAlpcServer
Gets all ALPC server objects accessible to the current process.
.EXAMPLE
Get-NtAlpcServer "\RPC Control\atsvc"
Gets the "\RPC Control\atsvc" ALPC server.
.EXAMPLE
Get-NtAlpcServer -ProcessId 1234
Gets all ALPC servers from PID 1234.
#>
function Get-NtAlpcServer {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcessId")]
        [alias("pid")]
        [int]$ProcessId
    )

    if (![NtCoreLib.NtToken]::EnableDebugPrivilege()) {
        Write-Warning "Can't enable debug privilege, results might be incomplete"
    }

    if ($PSCmdlet.ParameterSetName -ne "FromProcessId") {
        $ProcessId = -1
    }
    $hs = Get-NtHandle -ObjectTypes "ALPC Port" -ProcessId $ProcessId | Where-Object Name -ne ""

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            Write-Output $hs.GetObject()
        }
        "FromProcessId" {
            Write-Output $hs.GetObject()
        }
        "FromPath" {
            foreach ($h in $hs) {
                if ($h.Name -eq $Path) {
                    Write-Output $h.GetObject()
                    break
                }
            }
        }
    }
}

<#
.SYNOPSIS
Add a RPC security context to a client.
.DESCRIPTION
This cmdlet adds a RPC security context to an endpoint.
.PARAMETER Client
Specify the RPC client to add the context to.
.PARAMETER SecurityQualityOfService
Specify the security quality of service for the connection.
.PARAMETER Credentials
Specify user credentials for the RPC client authentication.
.PARAMETER ServicePrincipalName
Specify service principal name for the RPC client authentication.
.PARAMETER AuthenticationLevel
Specify authentication level for the RPC client authentication.
.PARAMETER AuthenticationType
Specify authentication type for the RPC client authentication.
.PARAMETER AuthenticationCapabilities
Specify authentication capabilities for the RPC client authentication.
.PARAMETER PassThru
Specify to the pass the security context object to the output. If you don't specify this
the security context will be set as the current context before returning.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurityContext
#>
function Add-RpcClientSecurityContext {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client,
        [NtCoreLib.Security.Token.SecurityQualityOfService]$SecurityQualityOfService,
        [NtCoreLib.Win32.Security.Authentication.AuthenticationCredentials]$Credentials,
        [string]$ServicePrincipalName,
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationLevel]$AuthenticationLevel = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationType]$AuthenticationType = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationCapabilities]$AuthenticationCapabilities = "None",
        [switch]$PassThru
    )

    try {
        $security = New-RpcTransportSecurity -SecurityQualityOfService $SecurityQualityOfService `
            -Credentials $Credentials -ServicePrincipalName $ServicePrincipalName `
            -AuthenticationLevel $AuthenticationLevel -AuthenticationType $AuthenticationType `
            -AuthenticationCapabilities $AuthenticationCapabilities
        $ctx = $Client.Transport.AddSecurityContext($security)
        if ($PassThru) {
            $ctx
        } else {
            Set-RpcClientSecurityContext -Client $Client -SecurityContext $ctx
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Set a RPC security context on a client.
.DESCRIPTION
This cmdlet sets the current RPC security context for a client.
.PARAMETER Client
Specify the RPC client to set the context to.
.PARAMETER SecurityContext
Specify the security context to set.
.PARAMETER ContextId
Specify the ID of the security context to set.
.INPUTS
None
.OUTPUTS
None
#>
function Set-RpcClientSecurityContext {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromContext")]
        [NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurityContext]$SecurityContext,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromId")]
        [int]$ContextId
    )

    if ($PSCmdlet.ParameterSetName -eq "FromId") {
        $SecurityContext = Get-RpcClientSecurityContext -Client $Client -ContextId $ContextId
    }

    $Client.Transport.CurrentSecurityContext = $SecurityContext
}

<#
.SYNOPSIS
Get a RPC security contexts from a client.
.DESCRIPTION
This cmdlet gets the current RPC security context for a client.
.PARAMETER Client
Specify the RPC client to set the context to.
.PARAMETER Current
Specify to return the current context only.
.PARAMETER ContextId
Specify to return the context with the specified ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurityContext[]
#>
function Get-RpcClientSecurityContext {
    [CmdletBinding(DefaultParameterSetName="All")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client,
        [parameter(Mandatory, ParameterSetName="FromCurrent")]
        [switch]$Current,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromId")]
        [int]$ContextId
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            $Client.Transport.SecurityContext | Write-Output
        }
        "FromCurrent" {
            $Client.Transport.CurrentSecurityContext
        }
        "FromId" {
            $Client.Transport.SecurityContext | Where-Object ContextId -eq $ContextId
        }
    }
}

<#
.SYNOPSIS
Get the registered service principal name for a RPC server.
.DESCRIPTION
This cmdlet gets the registered service principal name for a RPC server.
.PARAMETER Binding
Specify the server binding.
.PARAMETER AuthenticationType
Specify the authentication type.
.PARAMETER UseManagedClient
Specify to use a managed client.
.PARAMETER Security
Specify security to use with a managed client.
.INPUTS
None
.OUTPUTS
string
#>
function Get-RpcServicePrincipalName {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$Binding,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationType]$AuthenticationType,
        [switch]$UseManagedClient,
        [NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurity]$Security = (New-RpcTransportSecurity)
    )

    $intf = [NtCoreLib.Win32.Rpc.Management.RpcManagementInterface]::new($Binding, $UseManagedClient, $Security)
    $intf.QueryServicePrincipalName($AuthenticationType)
}

<#
.SYNOPSIS
Create a transport security object a RPC client.
.DESCRIPTION
This cmdlet creates a transport security object for a RPC client.
.PARAMETER Binding
Specify the server binding.
.PARAMETER AuthenticationType
Specify the authentication type.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurity
#>
function New-RpcTransportSecurity {
    Param(
        [NtCoreLib.Security.Token.SecurityQualityOfService]$SecurityQualityOfService,
        [NtCoreLib.Win32.Security.Authentication.AuthenticationCredentials]$Credentials,
        [string]$ServicePrincipalName,
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationLevel]$AuthenticationLevel = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationType]$AuthenticationType = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationCapabilities]$AuthenticationCapabilities = "None"
    )

    $security = New-Object NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurity
    $security.SecurityQualityOfService = $SecurityQualityOfService
    $security.Credentials = $Credentials
    $security.ServicePrincipalName = $ServicePrincipalName
    $security.AuthenticationLevel = $AuthenticationLevel
    $security.AuthenticationType = $AuthenticationType
    $security.AuthenticationCapabilities = $AuthenticationCapabilities
    $security
}

<#
.SYNOPSIS
Get the listening interfaces for a RPC server.
.DESCRIPTION
This cmdlet gets the listening interfaces for a RPC server.
.PARAMETER Binding
Specify the server binding.
.PARAMETER UseManagedClient
Specify to use a managed client.
.PARAMETER Security
Specify security to use with a managed client.
.INPUTS
None
.OUTPUTS
NtCoreLib.Ndr.Rpc.RpcSyntaxIdentifier
#>
function Get-RpcInterface {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$Binding,
        [switch]$UseManagedClient,
        [NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurity]$Security = (New-RpcTransportSecurity)
    )

    $intf = [NtCoreLib.Win32.Rpc.Management.RpcManagementInterface]::new($Binding, $UseManagedClient, $Security)
    $intf.QueryInterfaces() | Write-Output
}

<#
.SYNOPSIS
Create a configuration a RPC client transport.
.DESCRIPTION
This cmdlet creates a new configuration for and RPC client transport.
.PARAMETER Binding
Specify the string binding.
.PARAMETER ProtocolSequence
Specify the protocol sequence.
.PARAMETER Endpoint
Specify the endpoint.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Transport.RpcClientTransportConfiguration
#>
function New-RpcClientTransportConfig {
        [CmdletBinding(DefaultParameterSetName="FromProtocol")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProtocol")]
        [string]$ProtocolSequence,
        [parameter(Mandatory, ParameterSetName = "FromBinding")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$Binding,
        [parameter(Mandatory, ParameterSetName = "FromEndpoint")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpoint]$Endpoint
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromProtocol" {
            [NtCoreLib.Win32.Rpc.Transport.RpcClientTransportConfiguration]::Create($ProtocolSequence)
        }
        "FromBinding" {
            [NtCoreLib.Win32.Rpc.Transport.RpcClientTransportConfiguration]::Create($Binding)
        }
        "FromEndpoint" {
            [NtCoreLib.Win32.Rpc.Transport.RpcClientTransportConfiguration]::Create($Endpoint)
        }
    }
}

Register-ArgumentCompleter -CommandName New-RpcClientTransportConfig -ParameterName ProtocolSequence -ScriptBlock $protseq_completer

<#
.SYNOPSIS
Get the association group ID for a client.
.DESCRIPTION
This cmdlet gets the association group ID for a client.
.PARAMETER Client
Specify the RPC client.
.INPUTS
None
.OUTPUTS
int
#>
function Get-RpcClientAssociationGroupId {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client
    )
    if ($Client.Transport -is [NtCoreLib.Win32.Rpc.Transport.RpcConnectedClientTransport]) {
        $Client.Transport.AssociationGroupId
    } else {
        0
    }
}

<#
.SYNOPSIS
Parses COM proxy information.
.DESCRIPTION
This cmdlet parses the COM proxy information for an interface.
.PARAMETER Path
The path to the DLL containing the COM proxy information.
.PARAMETER Clsid
CLSID for the object used to find the proxy information.
.PARAMETER Iid
IID for the proy used to find the proxy information.
.OUTPUTS
NtCoreLib.Win32.Com.Proxy.ComProxyFile
#>
function Get-ComProxyFile {
    [CmdletBinding(DefaultParameterSetName="FromFile")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromFile")]
        [string]$Path,
        [parameter(ParameterSetName="FromFile")]
        [parameter(Mandatory, ParameterSetName="FromClsid")]
        [Guid]$Clsid = [Guid]::Empty,
        [parameter(Mandatory, ParameterSetName="FromIid")]
        [Guid]$Iid
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromFile" {
            $Path = Resolve-Path $Path -ErrorAction Stop
            [NtCoreLib.Win32.Com.Proxy.ComProxyFile]::FromFile($Path, $Clsid)
        }
        "FromClsid" {
            [NtCoreLib.Win32.Com.Proxy.ComProxyFile]::FromClsid($Clsid)
        }
        "FromIid" {
            [NtCoreLib.Win32.Com.Proxy.ComProxyFile]::FromIid($Iid)
        }
    }
}

<#
.SYNOPSIS
Format an NDR COM proxy file.
.DESCRIPTION
This cmdlet formats a parsed COM proxy file.
.PARAMETER Proxy
The proxy to format.
.PARAMETER Format
The output text format.
.PARAMETER RemoveComments
Specify to remove comments.
.OUTPUTS
string - The formatted proxy.
.EXAMPLE
Format-ComProxyFile $proxy
Format a COM proxy.
.EXAMPLE
$proxies | Format-ComProxyFile
Format a list of COM proxies from a pipeline.
#>
function Format-ComProxyFile {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Com.Proxy.ComProxyFile]$Proxy,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl",
        [switch]$RemoveComments
    )

    PROCESS {
        $flags = 0
        if ($RemoveComments) {
            $flags = "RemoveComments"
        }
        $Proxy.FormatAsText($flags, $Format)
    }
}