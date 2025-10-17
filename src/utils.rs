use clap::{Parser, command};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Init{
    pub is_sender: bool,
    pub room: u32,
    pub local_addr: Option<SocketAddr>,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct CliReceiver {
    // Six digit number to receive from the sender
    pub shared_key: u32
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct CliSender {
    // Path to the file to transfer
    pub filename: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileMetadata {
    pub filename: String,
    pub file_size: u64,
    pub is_folder: bool
}