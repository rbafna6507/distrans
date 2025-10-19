pub mod cryptography;
pub mod networking;
pub mod bytes;
pub mod utils;
pub mod relay_utils;
pub mod commands;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const CHUNK_SIZE: usize = 1024;
pub const ENCRYPTION_OVERHEAD: usize = 16;
pub const ENCRYPTION_ADJUSTED_CHUNK_SIZE: usize = CHUNK_SIZE - ENCRYPTION_OVERHEAD;

pub const RELAY_ADDR: &str = "45.55.102.56:8080";