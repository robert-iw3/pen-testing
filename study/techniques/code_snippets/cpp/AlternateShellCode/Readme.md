# This ist a copy of https://github.com/S4R1N/AlternativeShellcodeExec

# Alternative Code Execution 

This is gaining more popularity than expected, so I just wanted to give a shoutout to [alfarom256](https://github.com/alfarom256) for informing me about callback functions and showing me the CreateThreadPoolWait technique. I also wanted to give a shoutout to [ch3rn0byl](https://github.com/ch3rn0byl) for encouraging me to get this project going.

According to Microsoft, a callback function is code within a managed application that helps an unmanaged DLL function complete a task. Calls to a callback function pass indirectly from a managed application, through a DLL function, and back to the managed implementation. This repository contains a list of callback functions that can be used to execute position independent shellcode so that CreateThread would be a thing of the past :P.  
