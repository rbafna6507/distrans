use spake2::{Ed25519Group, Identity, Password, Spake2, Error as Spake2Error};
use sha2::{Digest, Sha256};
use hkdf::Hkdf;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use chacha20poly1305::aead::Error as AeadError;
pub use chacha20poly1305::aead::Error as EncryptionError;

pub const KEY_SIZE: usize = 32;

pub fn create_session_id(shared_room_key: u32) -> Identity {
    let mut hasher = Sha256::default();
    hasher.update(shared_room_key.to_ne_bytes());
    let result = hasher.finalize();
    Identity::new(&result)
}

pub fn generate_initial_pake_message(shared_room_key: u32, identity: &Identity) -> (Spake2<Ed25519Group>, Vec<u8>) {
    let pw = Password::new(shared_room_key.to_ne_bytes());
    Spake2::<Ed25519Group>::start_symmetric(&pw, identity)
}

pub fn derive_session_key(
    spake: Spake2<Ed25519Group>, 
    inbound_message: &[u8]
) -> Result<[u8; KEY_SIZE], Spake2Error> {
    let shared_secret = spake.finish(inbound_message)?;

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
    let mut encryption_key = [0u8; KEY_SIZE];
    hkdf.expand(b"croc-like-file-encryption", &mut encryption_key)
        .expect("32 bytes is a valid length for HKDF");

    Ok(encryption_key)
}


pub fn encrypt_chunk(
    key: &[u8; KEY_SIZE],
    chunk: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes); // Create a Nonce object
    
    // The `encrypt` method handles everything: encryption and generating the auth tag.
    cipher.encrypt(nonce, chunk)
}

pub fn decrypt_chunk(
    key: &[u8; KEY_SIZE],
    encrypted_chunk: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    // The `decrypt` method handles both decryption and authentication tag verification.
    // If the tag is invalid, it will return an error, preventing tampered data from being processed.
    cipher.decrypt(nonce, encrypted_chunk)
}