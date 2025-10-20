//! # Rift - Distributed File Transfer
//!
//! A secure peer-to-peer file transfer application with relay fallback.
//!
//! ## Architecture Overview
//!
//! This library provides the core functionality for secure, encrypted file transfers
//! between peers, with automatic peer-to-peer (P2P) connection attempts and relay fallback.
//!
//! ## Module Structure
//!
//! - `commands`: High-level command handlers for send, receive, and relay operations
//! - `networking`: TCP connection management, P2P hole punching, and PAKE handshake
//! - `cryptography`: ChaCha20-Poly1305 encryption/decryption and SPAKE2 key exchange
//! - `bytes`: File I/O, chunking, compression, and decompression utilities
//! - `utils`: Data structures for messages and metadata
//! - `relay_utils`: Relay server connection management and room coordination

pub mod cryptography;
pub mod networking;
pub mod bytes;
pub mod utils;
pub mod relay_utils;
pub mod commands;


/// Size of the encryption key in bytes.
///
/// ChaCha20-Poly1305 uses a 256-bit (32-byte) key for symmetric encryption.
pub const KEY_SIZE: usize = 32;

/// Size of the nonce in bytes for ChaCha20-Poly1305.
///
/// ChaCha20 uses a 96-bit (12-byte) nonce. We derive this from the chunk index
/// (8 bytes) plus 4 bytes of zeros to ensure unique nonces for each chunk.
pub const NONCE_SIZE: usize = 12;


/// Size of each data chunk in bytes (before encryption).
///
/// Files are split into 1024-byte chunks for streaming transfer. This size was chosen
/// to balance memory usage with network efficiency. Smaller chunks = more overhead,
/// larger chunks = more memory pressure.
pub const CHUNK_SIZE: usize = 1024;

/// Size of the authentication tag added by ChaCha20-Poly1305 encryption.
///
/// Poly1305 adds a 128-bit (16-byte) authentication tag to verify data integrity.
pub const ENCRYPTION_OVERHEAD: usize = 16;

/// Maximum plaintext chunk size that can be encrypted without exceeding CHUNK_SIZE.
/// 
/// Since encryption adds a 16-byte auth tag, we read chunks of (1024 - 16 = 1008) bytes,
/// which become 1024 bytes after encryption. This ensures consistent encrypted chunk sizes.
pub const ENCRYPTION_ADJUSTED_CHUNK_SIZE: usize = CHUNK_SIZE - ENCRYPTION_OVERHEAD;


/// Default relay server address for coordinating peer connections.
/// Users can override this by running their own relay with `rift relay`
pub const RELAY_ADDR: &str = "45.55.102.56:8080";