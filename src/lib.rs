pub mod cryptography;
pub mod networking;
pub mod bytes;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const CHUNK_SIZE: usize = 1024;
pub const ENCRYPTION_OVERHEAD: usize = 16;

pub const RELAY_ADDR: &str = "45.55.102.56:8080";