# InlineWhispers3
InlineWhispers3 is an updated version of [InlineWhispers2](https://github.com/Sh0ckFR/InlineWhispers2), designed to work with Indirect System Calls in Cobalt Strike's Beacon Object Files (BOFs) using [SysWhispers3](https://github.com/klezVirus/SysWhispers3). This tool helps changing SysWhispers3 generated files to be BOF compatible.

### Why InlineWhispers3?
The reason for developing InlineWhispers3 (an updated version of InlineWhispers/InlineWhispers2) is to leverage the advanced features of SysWhispers3, such as indirect syscalls, in red teaming with Beacon Object Files. InlineWhispers2 often gets detected due to its use of direct system calls by certain EDR systems. Indirect system calls provide a more sophisticated method for executing system calls on Windows, significantly enhancing EDR evasion.

## How to set this up and run this?


1. Clone the repo to your device
2. Generate stubs with SysWhispers3
3. Make SysWhispers3 output BOF compatible

See commands:
```bash
git clone https://github.com/tdeerenberg/InlineWhispers3 && cd InlineWhispers3
cd SysWhispers3/ && python3 syswhispers.py -p all -a x64 -m jumper -o syscalls_all && cd ..
python3 InlineWhispers3.py --aio
```

This generates the required syscalls.c/h files and then runs InlineWhispers3 to make the files compatible with BOFs.

> At the moment of writing this, the latest SysWhispers3 commit [`31cfc93`](https://github.com/klezVirus/SysWhispers3/commit/31cfc93c9466b52ae79d60925b0b5e0a1f653b88) is used, from Dec 23, 2023 <br><br>
> The `--aio` flag is optional and merges all output files into one `.h` file, which can also be used instead of using `syscalls.c`, `syscalls.h`, and `syscalls-asm.h`

## How to use indirect syscalls in your BOF

Import `syscalls.h`, `syscalls.c`, and `syscalls-asm.h` (or only `syscalls-aio.h`) in your project and include `syscalls.c` (or `syscalls-aio.h`) in your C code to start using syscalls.

An example BOF for reference (creates a new process using `NtCreateProcessEx`):

```c
#include <windows.h>
#include "beacon.h"
#include "syscalls.c"

void go(char* args, int length) {
    HANDLE hProcess;
    OBJECT_ATTRIBUTES oa = {sizeof(oa)};

    NTSTATUS status = Sw3NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, &oa, 
        (HANDLE)(LONG_PTR)-1, 0, NULL, NULL, NULL, 0);

    if (status == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] NtCreateProcessEx successful");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtCreateProcessEx failed: 0x%X\n", status);
        return;
    }
}
```

## Credits
- [@klezVirus](https://github.com/klezVirus) for SysWhispers3
- [@Sh0ckFR](https://github.com/Sh0ckFR) for InlineWhispers2
- [@outflanknl](https://github.com/outflanknl) for the first version of InlineWhispers and their informative blog post about it
- The Cyber Security Community for all the articles and resources
