### DefenderWrite

This is a tool that performs brute force on all executable files in the specified folder to identify files that are whitelisted by the Antivirus and have permission to write into the AV's executable folder.

### Command Line Syntax

**DefenderWrite.exe `<TargetExePath`> `<FullDLLPath`> `<FileToWrite`>**

*__DefenderWrite__ will execute the file at __TargetExePath__ and inject the __FullDLLPath__ DLL into the newly created process.
The DLL will perform the action of creating the __FileToWrite__ and will return a success or failure result.*

**DefenderWrite.exe `<TargetExePath`> `<FullDLLPath`> `<FileToWrite`> c**

*__DefenderWrite__ will execute the file at __TargetExePath__ and inject the __FullDLLPath__ DLL into the newly created process.
The DLL will perform the action of __copying__ the __FullDLLPath__ to the destination __FileToWrite__.
This is applicable when you want to copy the payload into the installation folder of the Antivirus.*

### Brute-Force with Run-Check.ps1

You can modify __line 60__ of the script to change parameters such as the path to __DefenderWrite__, __FullDLLPath__, and __FileToWrite__ to suit the environment you need to test.

```
CMD (RunAs Administrator)
powershell -c "path to Run-Check.ps1" > result.txt
```
Check the output log file (**result.txt**) and look for executable files that have the result "**successfully**".

### Some Antivirus have been successfully tested

- Microsoft Windows Defender
- BitDefender Antivirus
- TrendMicro Antivirus Plus
- Avast Antivirus
