

function Underlay-Copy {
	param(
		[Parameter(Mandatory=$true)][ValidateSet("MFT", "Metadata")][String]$Mode,
		[Parameter(Mandatory=$true)][string]$SourceFile,
		[Parameter(Mandatory=$true)][string]$DestinationFile
    )

	$Volume = "\\.\C:"

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Must run as Administrator."
    }

	# Ensure output directory exists
	$outDir = [System.IO.Path]::GetDirectoryName($DestinationFile)
	if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

	function Get-NtfsFileInfo {
		[CmdletBinding()]
		param(
			[Parameter(Mandatory=$true, Position=0)]
			[string]$Path
		)

		$cs = @"
			using System;
			using System.Runtime.InteropServices;

			public static class NtfsNative
			{
				public const uint FILE_READ_ATTRIBUTES = 0x80;
				public const uint FILE_SHARE_READ  = 0x00000001;
				public const uint FILE_SHARE_WRITE = 0x00000002;
				public const uint FILE_SHARE_DELETE= 0x00000004;
				public const uint OPEN_EXISTING    = 3;
				public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000; // needed for directories

				[StructLayout(LayoutKind.Sequential)]
				public struct FILETIME { public uint dwLowDateTime; public uint dwHighDateTime; }

				[StructLayout(LayoutKind.Sequential)]
				public struct BY_HANDLE_FILE_INFORMATION
				{
					public uint FileAttributes;
					public FILETIME CreationTime;
					public FILETIME LastAccessTime;
					public FILETIME LastWriteTime;
					public uint VolumeSerialNumber;
					public uint FileSizeHigh;
					public uint FileSizeLow;
					public uint NumberOfLinks;
					public uint FileIndexHigh;
					public uint FileIndexLow;
				}

				[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
				public static extern IntPtr CreateFileW(
					string lpFileName,
					uint dwDesiredAccess,
					uint dwShareMode,
					IntPtr lpSecurityAttributes,
					uint dwCreationDisposition,
					uint dwFlagsAndAttributes,
					IntPtr hTemplateFile
				);

				[DllImport("kernel32.dll", SetLastError=true)]
				[return: MarshalAs(UnmanagedType.Bool)]
				public static extern bool GetFileInformationByHandle(
					IntPtr hFile,
					out BY_HANDLE_FILE_INFORMATION lpFileInformation
				);

				[DllImport("kernel32.dll", SetLastError=true)]
				[return: MarshalAs(UnmanagedType.Bool)]
				public static extern bool CloseHandle(IntPtr hObject);
			}
"@

		try {
			Add-Type -TypeDefinition $cs -ErrorAction Stop
		}
		catch {
			if (-not $_.Exception.Message.Contains("The type name 'NtfsNative' already exists")) {
				throw
			}
		}

		$norm = if ($Path.StartsWith("\\?\")) { $Path } else { "\\?\$Path" }

		$access  = [NtfsNative]::FILE_READ_ATTRIBUTES
		$share   = [NtfsNative]::FILE_SHARE_READ -bor [NtfsNative]::FILE_SHARE_WRITE -bor [NtfsNative]::FILE_SHARE_DELETE
		$disp    = [NtfsNative]::OPEN_EXISTING
		$flags   = [NtfsNative]::FILE_FLAG_BACKUP_SEMANTICS

		$h = [NtfsNative]::CreateFileW($norm, $access, $share, [IntPtr]::Zero, $disp, $flags, [IntPtr]::Zero)

		if (($h -eq [IntPtr]::Zero) -or ($h.ToInt64() -eq -1)) {
			$err = New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error())
			throw "CreateFileW failed for '$Path': $($err.Message)"
		}

		try {
			$info = New-Object NtfsNative+BY_HANDLE_FILE_INFORMATION
			$ok = [NtfsNative]::GetFileInformationByHandle($h, [ref]$info)
			if (-not $ok) {
				$err = New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error())
				throw "GetFileInformationByHandle failed for '$Path': $($err.Message)"
			}

			[UInt64]$frn = (([UInt64]$info.FileIndexHigh) -shl 32) -bor [UInt64]$info.FileIndexLow
			[UInt64]$mftRecord   = $frn -band 0x0000FFFFFFFFFFFF
			[UInt64]$sequenceNum = ($frn -shr 48) -band 0xFFFF
			[UInt64]$size = (([UInt64]$info.FileSizeHigh) -shl 32) -bor [UInt64]$info.FileSizeLow

			return [PSCustomObject]@{
				Path                = $Path
				VolumeSerialNumber  = ('0x{0:X8}' -f $info.VolumeSerialNumber)
				FileId_FRN_64       = $frn
				FileId_FRN_Hex      = ('0x{0:X16}' -f $frn)
				MftRecordNumber     = $mftRecord
				MftRecord_Hex       = ('0x{0:X12}' -f $mftRecord)
				SequenceNumber      = $sequenceNum
				IsDirectory         = [bool]($info.FileAttributes -band [IO.FileAttributes]::Directory.value__)
				Links               = $info.NumberOfLinks
				Size                = $size
			}
		}
		finally {
			[void][NtfsNative]::CloseHandle($h)
		}
	}

	function Get-NtfsBoot {
        param([System.IO.FileStream]$fs)
        $buffer = New-Object byte[] 512
        $fs.Read($buffer,0,512)|Out-Null

        $bytesPerSector = [BitConverter]::ToUInt16($buffer,11)
        $sectorsPerCluster = $buffer[13]
        $clusterSize = $bytesPerSector * $sectorsPerCluster
        $mftCluster = [BitConverter]::ToInt64($buffer,48)
        return @{
            # BytesPerSector      = [BitConverter]::ToUInt16($buffer, 11)
			# SectorsPerCluster   = $buffer[13]
			BytesPerSector = $bytesPerSector
            SectorsPerCluster = $sectorsPerCluster
            ClusterSize = $clusterSize
            MftCluster = $mftCluster
        }
    }

	function Get-FileExtents-Fsutil {
		param([Parameter(Mandatory=$true)][string]$SourceFile)

		$raw = fsutil file queryextents $SourceFile 2>&1
		if ($LASTEXITCODE -ne 0 -and -not $raw) { throw "fsutil failed; run PowerShell as Administrator." }

		$extents = @()
		foreach ($line in ($raw -split "`n")) {
			$l = $line.Trim()
			if ($l -match '^VCN:\s*0x[0-9A-Fa-f]+\s+Clusters:\s*0x([0-9A-Fa-f]+)\s+LCN:\s*0x([0-9A-Fa-f]+)') {
				$clusters = [Convert]::ToInt64($matches[1],16)
				$lcn      = [Convert]::ToInt64($matches[2],16)
				$extents += [PSCustomObject]@{ Lcn = $lcn; LengthClusters = $clusters }
			}
		}
		if ($extents.Count -eq 0) { throw "No extents parsed from fsutil output. Raw:`n$raw" }
		return $extents
	}

	function Copy-FileByExtents {
		param(
			[Parameter(Mandatory=$true)][string]$Volume,
			[Parameter(Mandatory=$true)][array]$Extents,
			[Parameter(Mandatory=$true)][long]$ClusterSize,
			[Parameter(Mandatory=$true)][long]$TotalFileSize,
			[Parameter(Mandatory=$true)][string]$DestinationFile,
			[int]$ChunkSize = 4MB
		)

		# Open device for reading once, open out file once for writing
		$deviceFs = [System.IO.FileStream]::new($Volume, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
		$outFs = [System.IO.File]::Open($DestinationFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

		try {
			$bytesRemaining = $TotalFileSize

			foreach ($ext in $Extents) {
				$lcn = [int64]$ext.Lcn
				$clusters = [int64]$ext.LengthClusters
				$extentBytes = $clusters * $ClusterSize

				# Do not copy more than file's remaining bytes (last extent often shorter)
				$toCopy = [Math]::Min($extentBytes, $bytesRemaining)
				if ($toCopy -le 0) { break }

				$startOffset = $lcn * $ClusterSize
				$deviceFs.Seek($startOffset, [System.IO.SeekOrigin]::Begin) | Out-Null

				$copied = 0
				$bufferSize = $ChunkSize
				$buffer = New-Object byte[] $bufferSize

				while ($copied -lt $toCopy) {
					$readSize = [int][Math]::Min($bufferSize, $toCopy - $copied)
					$read = 0
					while ($read -lt $readSize) {
						$r = $deviceFs.Read($buffer, $read, $readSize - $read)
						if ($r -le 0) { throw "Unexpected end of device read" }
						$read += $r
					}
					# Write exactly read bytes
					$outFs.Write($buffer, 0, $read)
					$copied += $read
				}

				$bytesRemaining -= $copied
				if ($bytesRemaining -le 0) { break }
			}
		}
		finally {
			$deviceFs.Close()
			$outFs.Close()
		}
	}

	function Read-MftRecord {
        param([System.IO.FileStream]$fs, $ntfs, [int]$recNum)
        $MftRecordSize = 1024
        $mftOffset = $ntfs.MftCluster * $ntfs.ClusterSize
        $recOffset = $mftOffset + ($recNum * $MftRecordSize)
        $fs.Seek($recOffset,'Begin')|Out-Null
        $record = New-Object byte[] $MftRecordSize
        $fs.Read($record,0,$MftRecordSize)|Out-Null
        return $record
    }

	function Parse-DataRuns {
        param([byte[]]$attr)
        $runs = @()
        $pos = 0
        $curLCN = 0
        while ($pos -lt $attr.Length -and $attr[$pos] -ne 0x00) {
            $header = $attr[$pos]
            $lenSize = $header -band 0x0F
            $offSize = ($header -shr 4) -band 0x0F
            $pos++

            # Length
            $len = 0
            for ($i=0;$i -lt $lenSize;$i++){
                $len += [int]$attr[$pos] -shl (8*$i)
                $pos++
            }

            # Offset (relative LCN)
            $off = 0
            if ($offSize -gt 0){
                for ($i=0;$i -lt $offSize;$i++){
                    $off += [int]$attr[$pos] -shl (8*$i)
                    $pos++
                }
                # Two's complement sign extension
                if (($attr[$pos-1] -band 0x80) -ne 0){
                    $off -= [math]::Pow(2,8*$offSize)
                }
            }

            $curLCN += $off
            $runs += [PSCustomObject]@{ Length=$len; LCN=$curLCN }
        }
        return $runs
    }

	function Get-FileInfoFromRecord {
        param([byte[]]$record)
        $attrOffset = [BitConverter]::ToUInt16($record,20)
        $info = @{
            FileName = "<unknown>"
            ParentRef = 5
            FileSize = 0
            Runs = $null
        }
        while ($attrOffset -lt $record.Length) {
            $type = [BitConverter]::ToInt32($record,$attrOffset)
            if ($type -eq -1){ break }
            $len = [BitConverter]::ToInt32($record,$attrOffset+4)
            $nonResident = $record[$attrOffset+8]

            if ($type -eq 0x30) { # FILE_NAME
                $parentRef = [BitConverter]::ToInt64($record,$attrOffset+24)
                $info.ParentRef = ($parentRef -band 0xFFFFFFFFFFFF)
                $nameLen = $record[$attrOffset+88]
                $nameBytes = $record[($attrOffset+90)..($attrOffset+90+$nameLen*2-1)]
                $info.FileName = [System.Text.Encoding]::Unicode.GetString($nameBytes)
            }

            if ($type -eq 0x80) { # $DATA
                if ($nonResident -eq 0){
                    $info.FileSize = [BitConverter]::ToInt64($record,$attrOffset+16)
                } else {
                    $info.FileSize = [BitConverter]::ToInt64($record,$attrOffset+48)
                    $dataOff = [BitConverter]::ToUInt16($record,$attrOffset+32)
                    $dataRuns = $record[($attrOffset+$dataOff)..($attrOffset+$len-1)]
                    $info.Runs = Parse-DataRuns $dataRuns
                }
            }
            $attrOffset += $len
        }
        return $info
    }

	function Resolve-PathFromMft {
        param($fs,$ntfs,[int]$recNum)
        $parts=@()
        $cur=$recNum
        while ($cur -ne 5 -and $cur -ne 0){
            $rec=Read-MftRecord -fs $fs -ntfs $ntfs -recNum $cur
            $info=Get-FileInfoFromRecord $rec
            $parts+=$info.FileName
            $cur=$info.ParentRef
        }
        return ($parts[-1..-($parts.Count)] -join "\")
    }

	$fileInfo = Get-Item $SourceFile
    $size = $fileInfo.Length

	$fs = [System.IO.File]::Open($Volume,'Open','Read','ReadWrite')
    $ntfs = Get-NtfsBoot -fs $fs

    $clusterSize = $ntfs.BytesPerSector * $ntfs.SectorsPerCluster

	Write-Host "Source Full Path : $SourceFile"
	Write-Host "Source File Size : $($size) bytes"
	Write-Host "Cluster size: $clusterSize bytes"

	if ($mode -eq "MFT")
	{
		[int]$MftRecordNumber = (Get-NtfsFileInfo -Path $SourceFile).MftRecordNumber

		$record = Read-MftRecord -fs $fs -ntfs $ntfs -recNum $MftRecordNumber

		Write-Host "MFT Record #$MftRecordNumber"

		$info = Get-FileInfoFromRecord $record
		#$fullPath = Resolve-PathFromMft -fs $fs -ntfs $ntfs -recNum $MftRecordNumber

		$out = [System.IO.File]::Create($DestinationFile)
		$bytesWritten=0

		if ($info.Runs) {
			foreach ($r in $info.Runs){
				$toRead = [math]::Min($r.Length * $ntfs.ClusterSize, $info.FileSize - $bytesWritten)

				if ($r.LCN -eq 0) {
					# Sparse cluster
					$buffer = New-Object byte[] $toRead
					$out.Write($buffer,0,$toRead)
					$bytesWritten += $toRead
					continue
				}

				$diskOffset = $r.LCN * $ntfs.ClusterSize
				if ($diskOffset -lt 0){
					Write-Warning "Skipping invalid LCN: $($r.LCN)"
					continue
				}

				$fs.Seek($diskOffset,'Begin')|Out-Null
				$buffer = New-Object byte[] $toRead
				$fs.Read($buffer,0,$toRead)|Out-Null
				$out.Write($buffer,0,$toRead)
				$bytesWritten += $toRead

				if ($bytesWritten -ge $info.FileSize){ break }
			}
		} elseif ($info.FileSize -gt 0) {
			# Resident $DATA
			$attrOffset = [BitConverter]::ToUInt16($record,20)
			while ($attrOffset -lt $record.Length) {
				$type = [BitConverter]::ToInt32($record,$attrOffset)
				if ($type -eq 0x80){
					$valLen = [BitConverter]::ToInt64($record,$attrOffset+16)
					$valOff = [BitConverter]::ToUInt16($record,$attrOffset+20)
					$data = $record[$valOff..($valOff+$valLen-1)]
					$out.Write($data,0,$data.Length)
					break
				}
				$len = [BitConverter]::ToInt32($record,$attrOffset+4)
				$attrOffset += $len
			}
		}
		$out.Close()
		$fs.Close()
	}
	if ($mode -eq "Metadata")
	{
		$extents = Get-FileExtents-Fsutil -SourceFile $SourceFile
		Write-Host "Found $($extents.Count) extent(s)"
		foreach ($e in $extents) { Write-Host ("LCN={0}  LengthClusters={1}" -f $e.Lcn, $e.LengthClusters) }
		Copy-FileByExtents -Volume $Volume -Extents $extents -ClusterSize $clusterSize -TotalFileSize $size -DestinationFile $DestinationFile
	}

	Write-Host "File copied successfully to $DestinationFile"

}

