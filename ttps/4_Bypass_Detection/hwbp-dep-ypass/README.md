# HWBP-DEP-Bypass

A proof-of-concept implementation demonstrating how to execute code from non-executable memory on Windows x64 systems by combining hardware breakpoints, vectored exception handling (VEH), and instruction emulation—bypassing DEP/NX protection without modifying memory permissions.

## Overview

Data Execution Prevention (DEP) and No-Execute (NX) are memory protection mechanisms that prevent code execution from pages marked as non-executable. This proof-of-concept demonstrates a technique to bypass these protections by exploiting the timing of hardware breakpoint checks in the CPU pipeline.

### How It Works

This technique bypasses DEP/NX by exploiting the timing of CPU hardware breakpoint checks, which occur *before* memory protection validation:

**1. Hardware Breakpoints Trigger First**
- CPU checks debug registers (DR0-DR7) before instruction fetch
- EXCEPTION_SINGLE_STEP fires before MMU examines page permissions
- NX bit is never checked

**2. VEH Captures Exceptions**
- Vectored Exception Handler gets first-chance notification
- Full access to CPU context (all registers, RIP, RSP, etc.)
- Can modify context and control execution flow

**3. Software Emulation**
- Read instruction bytes as data from non-executable memory
- Decode opcode and emulate behavior
- Update CPU context (increment RIP, adjust RSP for RET, etc.)
- Set next hardware breakpoint at new RIP

**The Result**: Each instruction triggers this cycle. Code executes from `.data` section (PAGE_READWRITE) without ever changing memory protection. DEP/NX remains active but is bypassed through software emulation.

<img width="1338" height="1275" alt="image" src="https://github.com/user-attachments/assets/e5b7feb9-0a33-48bb-8a63-190869d2651f" />

