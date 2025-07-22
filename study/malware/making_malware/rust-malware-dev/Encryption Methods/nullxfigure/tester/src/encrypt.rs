use std::collections::HashMap;

pub fn encrypt_shellcode(shellcode: &[u8], false_byte: u8) -> Vec<u8>{
    let mut encrypted_shellcode=  Vec::with_capacity(shellcode.len() * 2);

    for &byte in shellcode{
        encrypted_shellcode.push(byte);
        encrypted_shellcode.push(false_byte);
    }

    encrypted_shellcode
}


pub fn store_shellcode(map: &mut HashMap<String, Vec<u8>>, key: &str, shellcode: &[u8]){
    map.insert(key.to_string(), shellcode.to_vec());
}

