//! # Commands Module
//!
//! This module contains the three main command handlers for rift:
//!
//! ## `send`
//! Handles sending files or folders to a receiver:
//! - Generates a random 6-digit shared key
//! - Connects to relay and attempts P2P connection
//! - Compresses folders into zip archives
//! - Chunks and encrypts data
//! - Streams encrypted chunks to receiver
//!
//! ## `receive`
//! Handles receiving files or folders from a sender:
//! - Takes the 6-digit shared key from sender
//! - Connects to relay and attempts P2P connection
//! - Receives and decrypts data chunks
//! - Writes files or decompresses folders
//!
//! ## `relay`
//! Runs a relay server that coordinates connections:
//! - Accepts connections from senders and receivers
//! - Groups them into "rooms" based on shared keys
//! - Exchanges peer address information
//! - Proxies data if P2P connection fails

pub mod send;
pub mod receive;
pub mod relay;
