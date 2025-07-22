@ECHO OFF

cl.exe /nologo /Od /MT /W2 /GS- /DNDEBUG /Tpdontlookhere.cpp /link /OUT:totally-safe.exe /SUBSYSTEM:CONSOLE /MACHINE:x64