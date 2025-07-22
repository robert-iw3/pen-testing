use std::collections::HashMap;

pub fn decrypt_shellcode(encrypted_shellcode: &[u8]) -> Vec<u8> {
    encrypted_shellcode
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 2 == 0) // Take every second byte (original bytes)
        .map(|(_, &byte)| byte)
        .collect()
}

pub fn get_original_shellcode(map: &HashMap<String, Vec<u8>>, key: &str) -> Option<Vec<u8>> {
    map.get(key).cloned()
}
