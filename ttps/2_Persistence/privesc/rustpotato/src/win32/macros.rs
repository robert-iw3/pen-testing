use core::arch::global_asm;

unsafe extern "C" {
    // Declaration of an external syscall function with a variadic argument list
    pub fn isyscall(ssn: u16, addr: usize, n_args: u32, ...) -> i32;
}

/// Macro to define a syscall structure and its associated implementations.
///
/// This macro generates a struct with the given name and a specified hash value.
/// It also implements the `NtSyscall` trait, `Send`, `Sync`, and `Default` traits for the generated
/// struct.
///
/// # Arguments
///
/// * `$name` - The identifier for the syscall struct.
/// * `$hash` - The hash value associated with the syscall.
///
/// # Generated Struct
///
/// The generated struct will have the following fields:
/// * `number` - A `u16` representing the syscall number.
/// * `address` - A mutable pointer to `u8` representing the address of the syscall.
/// * `hash` - A `usize` representing the hash value of the syscall.
#[macro_export]
macro_rules! define_nt_syscall {
    ($name:ident, $hash:expr) => {
        pub struct $name {
            pub number: u16,
            pub address: *mut u8,
            pub hash: usize,
        }

        impl NtSyscall for $name {
            fn new() -> Self {
                Self {
                    number: 0,
                    address: core::ptr::null_mut(),
                    hash: $hash,
                }
            }

            fn number(&self) -> u16 {
                self.number
            }

            fn address(&self) -> *mut u8 {
                self.address
            }

            fn hash(&self) -> usize {
                self.hash
            }
        }

        // Safety: This is safe because the struct $name does not contain any non-thread-safe data.
        unsafe impl Send for $name {}
        // Safety: This is safe because the struct $name does not contain any non-thread-safe data.
        unsafe impl Sync for $name {}

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

#[macro_export]
macro_rules! resolve_native_functions {
    ($module_base:expr, $( $syscall:expr ),* ) => {
        $(
            // Resolve both the System Service Number (SSN) and the address of the syscall.
            $syscall.number = $crate::win32::ssn::get_ssn($syscall.hash(), &mut $syscall.address) as u16;
        )*
    };
}

#[macro_export]
macro_rules! resolve_functions {
    ($module_base:expr, [ $( ($syscall:expr, $hash:expr, $f:ty) ),* ]) => {
        $(
            // Resolve the address of the API call using the provided hash
            let apicall_addr = $crate::win32::ldr::ldr_function($module_base, $hash);

            // Cast the resolved address to the specified function signature and assign it
            $syscall = core::mem::transmute::<*mut u8, $f>(apicall_addr);
        )*
    };
}

#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! run_syscall {
    ($ssn:expr, $addr:expr, $($y:expr), +) => {
        {
            let mut cnt: u32 = 0;

            // Count the number of arguments passed
            $(
                let _ = $y;
                cnt += 1;
            )+

            // Perform the syscall with the given number, address (offset by 0x12),
            // argument count, and the arguments
            unsafe { $crate::win32::macros::isyscall($ssn, $addr + 0x12, cnt, $($y), +) }
        }
    }
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    "
.globl isyscall

.section .text

isyscall:
    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi
    mov [rsp - 0x18], r12

    xor r10, r10			
    mov rax, rcx			
    mov r10, rax

    mov eax, ecx

    mov r12, rdx
    mov rcx, r8

    mov r10, r9
    mov rdx,  [rsp + 0x28]
    mov r8,   [rsp + 0x30]
    mov r9,   [rsp + 0x38]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x40]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:
    mov rcx, r12

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]

    jmp rcx
"
);
