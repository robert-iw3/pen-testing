## Manifest dependencies for [winapi](https://docs.rs/winapi/latest/winapi/) to test and execute

**Copy the dependencics in Cargo.toml file**

```rust
[dependencies]
winapi = { version = "0.3", features = [
    "winuser",
    "setupapi",
    "dbghelp",
    "wlanapi",
    "winnls",
    "wincon",
    "fileapi",
    "sysinfoapi",
    "fibersapi",
    "debugapi",
    "winerror",
    "wininet",
    "winhttp",
    "synchapi",
    "securitybaseapi",
    "wincrypt",
    "psapi",
    "tlhelp32",
    "heapapi",
    "shellapi",
    "memoryapi",
    "processthreadsapi",
    "errhandlingapi",
    "winbase",
    "handleapi",
    "synchapi",
] }
ntapi = "0.4"

```

> Tips for Rust Beginners: Copy and save the dependencies in Cargo.toml File. Versions may be different. Just copy the features when testing. 

To Go [Back](./README.md).