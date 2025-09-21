### EDR-Freeze

This is a tool that exploits the software vulnerability of WerFaultSecure to suspend the processes of EDRs and antimalware without needing to use the BYOVD (Bring Your Own Vulnerable Driver) attack method.

EDR-Freeze operates in user mode, so you don't need to install any additional drivers. It can run on the latest version of Windows.

*The experiment was conducted with the latest version of Windows at the time of the project creation: __Windows 11 24H2__*

### Command Line Syntax

**EDR-Freeze.exe [TargetPID] [SleepTime]**

*Example: __EDR-Freeze.exe 1234 10000__*

*Freeze the target for 10000 milliseconds*

