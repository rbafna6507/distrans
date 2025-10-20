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
/// Packages FileMetadata to send from the Sender to the Receiver
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileMetadata {
    pub filename: String,
    pub file_size: u64,
    pub is_folder: bool
}

/// Simple struct to make Peer Address more readable
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_struct() {
        let init = Init {
            is_sender: true,
            room: 12345,
            local_addr: None,
        };

        assert_eq!(init.is_sender, true);
        assert_eq!(init.room, 12345);
        assert!(init.local_addr.is_none());
    }

    #[test]
    fn test_file_metadata() {
        let metadata = FileMetadata {
            filename: "test.txt".to_string(),
            file_size: 1024,
            is_folder: false,
        };

        assert_eq!(metadata.filename, "test.txt");
        assert_eq!(metadata.file_size, 1024);
        assert_eq!(metadata.is_folder, false);
    }

    #[test]
    fn test_peer_addresses() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        
        let external = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8080);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        let peer_addrs = PeerAddresses {
            external_addr: external,
            local_addr: Some(local),
        };

        assert_eq!(peer_addrs.external_addr, external);
        assert_eq!(peer_addrs.local_addr, Some(local));
    }
}