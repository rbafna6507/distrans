use clap::{Parser, command};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};

/// Contains general purpose utilities for file transfer
/// - Structs that organize message data
///     - Init message (intro to relay) struct
///     - FileMetadata struct
///     - Peer Addresses
/// - CLI parsing helper structs

/// Packages an initialization message from Sender/Receiver to the Relay
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Init{
    pub is_sender: bool,
    pub room: u32,
    pub local_addr: Option<SocketAddr>,
}

/// Packages FileMetadata to send from the Sender to the Receiver
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileMetadata {
    pub filename: String,
    pub file_size: u64,
    pub is_folder: bool
}

/// Simple struct to make Peer Address more readable
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerAddresses {
    pub external_addr: SocketAddr,
    pub local_addr: Option<SocketAddr>,
}

/// Helper struct used to parse file/folder name from the command line for Sender
#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct CliSender {
    // Path to the file to transfer
    pub filename: String
}
/// Helper struct used to parse shared_key from the command line for Receiver
#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct CliReceiver {
    pub shared_key: u32
}