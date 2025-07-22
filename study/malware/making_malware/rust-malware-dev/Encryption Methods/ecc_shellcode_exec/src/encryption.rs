use k256::{
    elliptic_curve::{AffinePoint, Field},
    EncodedPoint, ProjectivePoint, Scalar, Secp256k1,
};

use k256::elliptic_curve::group::GroupEncoding;
use sha2::{Digest, Sha256};

fn encode_shellcode(
    shellcode: &[u8],
    public_key: &AffinePoint<Secp256k1>,
) -> (EncodedPoint, Vec<u8>) {
    let mut rng = rand::rngs::OsRng;

    let k = Scalar::random(&mut rng);
    let r = (ProjectivePoint::generator() * k).to_affine();

    let shared_secret = *public_key * k;
    let shared_secret_bytes = shared_secret.to_bytes();

    let mut hasher = Sha256::new();
    hasher.update(shared_secret_bytes);
    let encryption_key = hasher.finalize();

    let encrypted_shellcode: Vec<u8> = shellcode
        .iter()
        .zip(encryption_key.iter().cycle())
        .map(|(&byte, &key)| byte ^ key)
        .collect();

    (EncodedPoint::from(&r), encrypted_shellcode)
}

pub fn encrypt_shellcode(shellcode: &[u8], public_key: &AffinePoint<Secp256k1>) -> (EncodedPoint, Vec<u8>){

    let (r, encrypted_shellcode) = encode_shellcode(shellcode, &public_key);

    println!("R Point: {:?}\n\n", r);
    println!("Encrypted Shellcode: {:?}\n", encrypted_shellcode);

    (r, encrypted_shellcode)
}

