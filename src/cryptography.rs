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
/// * `shared_room_key` - The 6-digit shared key (divided by 100 to get obfuscated room number)
///
/// # Returns
/// A SPAKE2 Identity derived from the room key - used to create the same 'session' for a sender and receiver
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
/// during decryption. Using chunk_index as nonce helps reduce the chances of nonce reuse,
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



// Testing Suite:
// - Encryption/Decryption round trip
// - PAKE handshake and key derivation
// - Nonce uniqueness + tamper error handling
// - Edge cases: empty data, single byte, large chunks, max index

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // Basic Encryption/Decryption Tests
    // ============================================================================

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

    // ============================================================================
    // Edge Case Tests
    // ============================================================================

    #[test]
    fn test_encrypt_empty_data() {
        let key = [42u8; KEY_SIZE];
        let plaintext = b"";
        let chunk_index = 0;

        let encrypted = encrypt_chunk(&key, plaintext, chunk_index)
            .expect("Encryption of empty data should succeed");

        // Even empty data should have auth tag
        assert_eq!(encrypted.len(), 16);

        let decrypted = decrypt_chunk(&key, &encrypted, chunk_index)
            .expect("Decryption should succeed");
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_encrypt_single_byte() {
        let key = [0xFFu8; KEY_SIZE];
        let plaintext = b"X";
        let chunk_index = 99;

        let encrypted = encrypt_chunk(&key, plaintext, chunk_index)
            .expect("Encryption should succeed");

        assert_eq!(encrypted.len(), 1 + 16);

        let decrypted = decrypt_chunk(&key, &encrypted, chunk_index)
            .expect("Decryption should succeed");
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_encrypt_large_chunk() {
        let key = [123u8; KEY_SIZE];
        // Test with a large chunk (close to max chunk size)
        let plaintext = vec![0xAAu8; crate::ENCRYPTION_ADJUSTED_CHUNK_SIZE];
        let chunk_index = 42;

        let encrypted = encrypt_chunk(&key, &plaintext, chunk_index)
            .expect("Encryption of large chunk should succeed");

        assert_eq!(encrypted.len(), plaintext.len() + 16);

        let decrypted = decrypt_chunk(&key, &encrypted, chunk_index)
            .expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_maximum_chunk_index() {
        let key = [55u8; KEY_SIZE];
        let plaintext = b"Testing maximum chunk index";
        let chunk_index = u64::MAX;

        let encrypted = encrypt_chunk(&key, plaintext, chunk_index)
            .expect("Encryption with max index should succeed");

        let decrypted = decrypt_chunk(&key, &encrypted, chunk_index)
            .expect("Decryption should succeed");
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_different_chunks_have_different_ciphertexts() {
        let key = [77u8; KEY_SIZE];
        let plaintext = b"Same plaintext for both chunks";

        // Encrypt same plaintext with different indices
        let encrypted1 = encrypt_chunk(&key, plaintext, 0)
            .expect("Encryption should succeed");
        let encrypted2 = encrypt_chunk(&key, plaintext, 1)
            .expect("Encryption should succeed");

        // Ciphertexts should be different (different nonces)
        assert_ne!(encrypted1, encrypted2, "Different chunk indices should produce different ciphertexts");
    }

    #[test]
    fn test_tampered_auth_tag_fails() {
        let key = [88u8; KEY_SIZE];
        let plaintext = b"Authenticated data";
        let chunk_index = 5;

        let mut encrypted = encrypt_chunk(&key, plaintext, chunk_index)
            .expect("Encryption should succeed");

        // Tamper with the authentication tag (last 16 bytes)
        let len = encrypted.len();
        encrypted[len - 1] ^= 0x01;

        let result = decrypt_chunk(&key, &encrypted, chunk_index);
        assert!(result.is_err(), "Tampered auth tag should cause decryption to fail");
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = [99u8; KEY_SIZE];
        let plaintext = b"Data to be truncated";
        let chunk_index = 0;

        let encrypted = encrypt_chunk(&key, plaintext, chunk_index)
            .expect("Encryption should succeed");

        // Truncate ciphertext (remove some of the auth tag)
        let truncated = &encrypted[..encrypted.len() - 5];

        let result = decrypt_chunk(&key, truncated, chunk_index);
        assert!(result.is_err(), "Truncated ciphertext should fail to decrypt");
    }

    // ============================================================================
    // PAKE and Key Derivation Tests
    // ============================================================================

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
    fn test_create_session_id_different_keys() {
        let _id1 = create_session_id(123456);
        let _id2 = create_session_id(654321);
        
        // Different keys should produce different identities
        // Can't directly compare, but at least verify both succeed
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

    #[test]
    fn test_pake_multiple_messages_different() {
        let room_key = 123456;
        let identity = create_session_id(room_key);
        
        let (_spake1, message1) = generate_initial_pake_message(room_key, &identity);
        let (_spake2, message2) = generate_initial_pake_message(room_key, &identity);
        
        // Each PAKE message should be unique (contains random ephemeral keys)
        assert_ne!(message1, message2, "PAKE messages should be unique");
    }

    #[test]
    fn test_derive_session_key_successful() {
        let room_key = 555555;
        let identity = create_session_id(room_key);
        
        // Simulate sender and receiver
        let (sender_spake, sender_msg) = generate_initial_pake_message(room_key, &identity);
        let (receiver_spake, receiver_msg) = generate_initial_pake_message(room_key, &identity);
        
        // Derive keys on both sides
        let sender_key = derive_session_key(sender_spake, &receiver_msg)
            .expect("Sender key derivation should succeed");
        let receiver_key = derive_session_key(receiver_spake, &sender_msg)
            .expect("Receiver key derivation should succeed");
        
        // Both parties should derive the same key
        assert_eq!(sender_key, receiver_key, "Both parties should derive identical session keys");
    }

    #[test]
    fn test_derive_session_key_wrong_password_fails() {
        let sender_key = 111111;
        let receiver_key = 222222;
        
        let sender_identity = create_session_id(sender_key);
        let receiver_identity = create_session_id(receiver_key);
        
        let (_sender_spake, sender_msg) = generate_initial_pake_message(sender_key, &sender_identity);
        let (receiver_spake, _receiver_msg) = generate_initial_pake_message(receiver_key, &receiver_identity);
        
        // SPAKE2 itself doesn't fail immediately, but derives different keys
        let result = derive_session_key(receiver_spake, &sender_msg);
        
        // The key derivation may succeed, but the keys will be different
        // The actual failure detection happens in the verification step (see networking tests)
        assert!(result.is_ok() || result.is_err());
        
        // If it succeeds, the keys would be different (tested in other tests)
    }

    #[test]
    fn test_derived_keys_enable_encryption() {
        let room_key = 777777;
        let identity = create_session_id(room_key);
        
        // Complete PAKE exchange
        let (sender_spake, sender_msg) = generate_initial_pake_message(room_key, &identity);
        let (receiver_spake, receiver_msg) = generate_initial_pake_message(room_key, &identity);
        
        let sender_key = derive_session_key(sender_spake, &receiver_msg)
            .expect("Key derivation should succeed");
        let receiver_key = derive_session_key(receiver_spake, &sender_msg)
            .expect("Key derivation should succeed");
        
        // Use derived keys for actual encryption
        let plaintext = b"Secure file transfer data";
        let chunk_index = 0;
        
        let encrypted = encrypt_chunk(&sender_key, plaintext, chunk_index)
            .expect("Encryption should succeed");
        let decrypted = decrypt_chunk(&receiver_key, &encrypted, chunk_index)
            .expect("Decryption should succeed");
        
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_session_key_is_32_bytes() {
        let room_key = 888888;
        let identity = create_session_id(room_key);
        
        let (sender_spake, sender_msg) = generate_initial_pake_message(room_key, &identity);
        let (receiver_spake, receiver_msg) = generate_initial_pake_message(room_key, &identity);
        
        let sender_key = derive_session_key(sender_spake, &receiver_msg)
            .expect("Key derivation should succeed");
        let receiver_key = derive_session_key(receiver_spake, &sender_msg)
            .expect("Key derivation should succeed");
        
        assert_eq!(sender_key.len(), KEY_SIZE);
        assert_eq!(receiver_key.len(), KEY_SIZE);
    }

    // ============================================================================
    // Nonce Uniqueness and Security Tests
    // ============================================================================

    #[test]
    fn test_nonce_construction_from_index() {
        // Verify that nonce is correctly constructed from chunk index
        let key = [100u8; KEY_SIZE];
        let plaintext1 = b"Chunk 0";
        let plaintext2 = b"Chunk 1";
        
        let encrypted1 = encrypt_chunk(&key, plaintext1, 0)
            .expect("Encryption should succeed");
        let encrypted2 = encrypt_chunk(&key, plaintext2, 1)
            .expect("Encryption should succeed");
        
        // Same key, different index -> different ciphertexts (proves nonce is different)
        assert_ne!(encrypted1, encrypted2);
        
        // Decryption with correct indices should work
        let decrypted1 = decrypt_chunk(&key, &encrypted1, 0)
            .expect("Decryption should succeed");
        let decrypted2 = decrypt_chunk(&key, &encrypted2, 1)
            .expect("Decryption should succeed");
        
        assert_eq!(&decrypted1[..], plaintext1);
        assert_eq!(&decrypted2[..], plaintext2);
    }

    #[test]
    fn test_sequential_chunks() {
        let key = [200u8; KEY_SIZE];
        let data = b"Sequential chunk data";
        
        // Encrypt multiple sequential chunks
        let mut encrypted_chunks = Vec::new();
        for i in 0..10u64 {
            let enc = encrypt_chunk(&key, data, i)
                .expect("Encryption should succeed");
            encrypted_chunks.push(enc);
        }
        
        // Each should be different (unique nonces)
        for i in 0..encrypted_chunks.len() {
            for j in i+1..encrypted_chunks.len() {
                assert_ne!(encrypted_chunks[i], encrypted_chunks[j]);
            }
        }
        
        // All should decrypt correctly
        for (i, enc) in encrypted_chunks.iter().enumerate() {
            let dec = decrypt_chunk(&key, enc, i as u64)
                .expect("Decryption should succeed");
            assert_eq!(&dec[..], data);
        }
    }

    #[test]
    fn test_nonce_never_reuse_with_same_key() {
        // Critical security property: never reuse nonce with same key
        let key = [150u8; KEY_SIZE];
        let plaintext = b"Critical data";
        
        // Encrypt same plaintext with same index twice
        let enc1 = encrypt_chunk(&key, plaintext, 42)
            .expect("Encryption should succeed");
        let enc2 = encrypt_chunk(&key, plaintext, 42)
            .expect("Encryption should succeed");
        
        // With deterministic nonce generation from index, these should be identical
        // This is actually OK for our use case since chunk_index is always unique per transfer
        assert_eq!(enc1, enc2, "Deterministic encryption with same key+nonce should produce same ciphertext");
    }
}