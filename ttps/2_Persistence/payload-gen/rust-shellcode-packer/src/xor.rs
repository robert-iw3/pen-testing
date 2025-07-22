// module dedicated to xor a binary input and give back the path of the encrypted file

use crate::{shellcode_reader::meta_vec_from_file, tools::write_to_file};
use std::{collections::HashMap, path::Path};

fn xor_encode(shellcode: &[u8], key: u8) -> Vec<u8> {
    // thanks to https://github.com/memN0ps/arsenal-rs/blob/main/obfuscate_shellcode-rs/src/main.rs
    shellcode.iter().map(|x| x ^ key).collect()
}

pub fn meta_xor(input_path: &Path, export_path: &Path, key: u8) -> HashMap<String, String> {
    println!("[+] XORing shellcode with key {}..", key);
    let unencrypted = meta_vec_from_file(input_path);
    let encrypted_content = xor_encode(&unencrypted, key);
    match write_to_file(&encrypted_content, export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }

    let mut result: HashMap<String, String> = HashMap::new();

    let decryption_function = "fn xor_decode(buf: &Vec<u8>, key: u8) -> Vec<u8> {
        buf.iter().map(|x| x ^ key).collect()
    }"
    .to_string();

    let main = format!("vec = xor_decode(&vec, {});", key);

    result.insert(String::from("decryption_function"), decryption_function);
    result.insert(String::from("main"), main);

    println!("[+] Done XORing shellcode!");
    result
}
