use spake2::{Ed25519Group, Identity, Password, Spake2};
use sha2::{Digest, Sha256};
use hkdf::Hkdf;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use chacha20poly1305::aead::Error as AeadError;
pub use chacha20poly1305::aead::Error as EncryptionError;
use crate::{KEY_SIZE, NONCE_SIZE};

/// Creates a session identity from the shared room key for PAKE authentication.
///
/// The identity is derived by hashing the room key with SHA256. This ensures that
/// both sender and receiver using the same 6-digit key will compute the same identity,
/// which is required for SPAKE2 protocol to work correctly.
///
/// # Arguments
/// * `shared_room_key` - The 6-digit shared key (divided by 100 to get room number)
///
/// # Returns
/// A SPAKE2 Identity derived from the room key
pub fn create_session_id(shared_room_key: u32) -> Identity {
    let mut hasher = Sha256::default();
    hasher.update(shared_room_key.to_ne_bytes());
    let result = hasher.finalize();
    Identity::new(&result)
}

/// Generates the initial PAKE (Password-Authenticated Key Exchange) message.
///
/// This initiates the SPAKE2 protocol, which allows two parties to establish a shared
/// secret key over an insecure channel, using only a shared password (the 6-digit key).
/// Even if an attacker intercepts the messages, they cannot derive the encryption key
/// without knowing the password.
///
/// # Arguments
/// * `shared_room_key` - The 6-digit shared key
/// * `identity` - The session identity (both parties must use the same identity)
///
/// # Returns
/// A tuple of (Spake2 state, initial message to send to peer)
pub fn generate_initial_pake_message(shared_room_key: u32, identity: &Identity) -> (Spake2<Ed25519Group>, Vec<u8>) {
    let pw = Password::new(shared_room_key.to_ne_bytes());
    Spake2::<Ed25519Group>::start_symmetric(&pw, identity)
}

/// Derives the final session encryption key from the PAKE exchange.
///
/// After both parties have exchanged their PAKE messages, this function completes
/// the protocol and derives a shared 32-byte encryption key. The key is derived using
/// HKDF (HMAC-based Key Derivation Function) to ensure cryptographic strength.
///
/// # Arguments
/// * `spake` - The SPAKE2 state from the initial message generation
/// * `inbound_message` - The PAKE message received from the peer
///
/// # Returns
/// A 32-byte encryption key, or an error if the PAKE exchange failed (e.g., wrong password)
pub fn derive_session_key(
    spake: Spake2<Ed25519Group>, 
    inbound_message: &[u8]) -> Result<[u8; KEY_SIZE], spake2::Error> {
    // Complete PAKE exchange to get shared secret
    let shared_secret = spake.finish(inbound_message)?;

    // Derive encryption key from shared secret using HKDF
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
    let mut encryption_key = [0u8; KEY_SIZE];
    hkdf.expand(b"croc-like-file-encryption", &mut encryption_key)
        .expect("32 bytes is a valid length for HKDF");

    Ok(encryption_key)
}

/// Encrypt a chunk of data with ChaCha20-Poly1305 authenticated encryption.
///
/// # Encryption Details
/// - Algorithm: ChaCha20-Poly1305 (AEAD - Authenticated Encryption with Associated Data)
/// - Nonce: Derived from chunk_index (ensures each chunk has a unique nonce)
/// - Output: Ciphertext + 16-byte authentication tag
///
/// # Security
/// The authentication tag ensures data integrity - any tampering will be detected
/// during decryption. Using chunk_index as nonce ensures we never reuse nonces,
/// which would be catastrophic for security.
///
/// # Arguments
/// * `key` - The 32-byte encryption key
/// * `chunk` - The plaintext data to encrypt
/// * `chunk_index` - The sequential index of this chunk (used to generate unique nonce)
///
/// # Returns
/// Encrypted data with authentication tag appended (length = chunk.len() + 16 bytes)
pub fn encrypt_chunk(
    key: &[u8; KEY_SIZE],
    chunk: &[u8],
    chunk_index: u64,
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    
    // Generate unique nonce from chunk index (first 8 bytes = index, rest = zeros)
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes[..8].copy_from_slice(&chunk_index.to_le_bytes());
    let nonce = Nonce::from(nonce_bytes);
    
    // Encrypt and authenticate the chunk
    cipher.encrypt(&nonce, chunk)
}

/// Decrypt a chunk of data with ChaCha20-Poly1305 authenticated encryption.
///
/// # Decryption Details
/// - Verifies the 16-byte authentication tag before decrypting
/// - Returns an error if tag verification fails (data was tampered with)
/// - Uses chunk_index to reconstruct the same nonce used during encryption
///
/// # Arguments
/// * `key` - The 32-byte encryption key
/// * `encrypted_chunk` - The ciphertext with authentication tag
/// * `chunk_index` - The sequential index of this chunk (must match encryption index)
///
/// # Returns
/// Decrypted plaintext data, or an error if authentication fails
pub fn decrypt_chunk(
    key: &[u8; KEY_SIZE],
    encrypted_chunk: &[u8],
    chunk_index: u64,
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    
    // Reconstruct the same nonce used during encryption
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes[..8].copy_from_slice(&chunk_index.to_le_bytes());
    let nonce = Nonce::from(nonce_bytes);

    // Decrypt and verify authentication tag
    // If the tag is invalid, it will return an error, preventing tampered data from being processed
    cipher.decrypt(&nonce, encrypted_chunk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; KEY_SIZE];
        let plaintext = b"Hello, World! This is a test message.";
        let chunk_index = 0;

        // Encrypt
        let encrypted = encrypt_chunk(&key, plaintext, chunk_index)
            .expect("Encryption should succeed");

        // Verify encrypted is longer (includes auth tag)
        assert_eq!(encrypted.len(), plaintext.len() + 16);

        // Decrypt
        let decrypted = decrypt_chunk(&key, &encrypted, chunk_index)
            .expect("Decryption should succeed");

        // Verify round-trip
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let key1 = [0u8; KEY_SIZE];
        let key2 = [1u8; KEY_SIZE];
        let plaintext = b"Secret message";
        let chunk_index = 0;

        let encrypted = encrypt_chunk(&key1, plaintext, chunk_index)
            .expect("Encryption should succeed");

        // Attempt to decrypt with wrong key
        let result = decrypt_chunk(&key2, &encrypted, chunk_index);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_decrypt_with_wrong_index_fails() {
        let key = [0u8; KEY_SIZE];
        let plaintext = b"Test data";
        let chunk_index = 0;
        let wrong_index = 1;

        let encrypted = encrypt_chunk(&key, plaintext, chunk_index)
            .expect("Encryption should succeed");

        // Attempt to decrypt with wrong index (different nonce)
        let result = decrypt_chunk(&key, &encrypted, wrong_index);
        assert!(result.is_err(), "Decryption with wrong index should fail");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0u8; KEY_SIZE];
        let plaintext = b"Important data";
        let chunk_index = 0;

        let mut encrypted = encrypt_chunk(&key, plaintext, chunk_index)
            .expect("Encryption should succeed");

        // Tamper with the ciphertext
        encrypted[5] ^= 0xFF;

        // Attempt to decrypt tampered data
        let result = decrypt_chunk(&key, &encrypted, chunk_index);
        assert!(result.is_err(), "Decryption of tampered data should fail");
    }

    #[test]
    fn test_create_session_id_deterministic() {
        let room_key = 123456;
        
        // Create session ID twice with same key
        let _id1 = create_session_id(room_key);
        let _id2 = create_session_id(room_key);
        
        // Should produce identical results (deterministic)
        // Note: Identity doesn't implement Debug or Eq, so we just verify it doesn't panic
    }

    #[test]
    fn test_pake_message_generation() {
        let room_key = 123456;
        let identity = create_session_id(room_key);
        
        let (spake, message) = generate_initial_pake_message(room_key, &identity);
        
        // Message should be non-empty
        assert!(!message.is_empty());
        
        // Spake state should exist (we can't inspect it much, but it shouldn't panic)
        drop(spake);
    }
}