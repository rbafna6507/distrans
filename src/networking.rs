use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, TcpSocket, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::{error::Error, net::SocketAddr};
use std::time::Duration;
use crate::cryptography::{generate_initial_pake_message, create_session_id, derive_session_key};
use crate::utils::{FileMetadata, Init, PeerAddresses};
use crate::KEY_SIZE;
use log::{debug};

/// Creates a reusable TCP socket with SO_REUSEADDR and SO_REUSEPORT enabled.
///
/// These socket options allow multiple sockets to bind to the same port, which is
/// essential for TCP hole punching - we need one socket for listening and another
/// for connecting, both using the same local port.
///
/// # Arguments
/// * `local_addr` - The local address to bind the socket to
///
/// # Returns
/// A configured TcpSocket ready to either listen or connect
pub fn create_reusable_socket(local_addr: SocketAddr) -> Result<TcpSocket, Box<dyn Error>> {
    let listen_socket = match local_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    listen_socket.set_reuseaddr(true)?;
    listen_socket.set_reuseport(true)?;
    listen_socket.bind(local_addr)?;
    
    Ok(listen_socket)
}

/// Attempts to establish a direct peer-to-peer (P2P) TCP connection using hole punching.
///
/// # TCP Hole Punching Strategy
/// This function simultaneously:
/// 1. Listens for incoming connections from the peer
/// 2. Attempts to connect to the peer
/// Both operations use the same local port (via SO_REUSEPORT), which allows the connection
/// to traverse NAT devices by creating outbound NAT mappings.
///
/// # Arguments
/// * `local_addr` - Our local address (the port we're binding to)
/// * `receiver_addr` - The peer's address (either external or local network)
///
/// # Returns
/// - Ok(TcpStream) if P2P connection succeeds (either direction)
/// - Err if both attempts fail within 150ms timeout
pub async fn attempt_p2p_connection(local_addr: SocketAddr, receiver_addr: SocketAddr) -> Result<TcpStream, Box<dyn Error>> {
    debug!("Attempting P2P connection from {} to {}", local_addr, receiver_addr);
    // Open a listening socket to accept the TCP hole punch from peer
    let listen_socket: TcpSocket = create_reusable_socket(local_addr)?;
    let listener: TcpListener = listen_socket.listen(1024)?;
    debug!("Created listening socket on {}", local_addr);

    // Open a new socket connection to connect to the other peer
    let connect_socket:TcpSocket = create_reusable_socket(local_addr)?;

    tokio::select! {
        // Try to accept peer's connection
        Ok((p2p_stream, _addr)) = listener.accept() => {
            debug!("P2P connection accepted from peer");
            return Ok(p2p_stream);
        }

        // Try connecting to peer (TCP hole punch) 
        Ok(p2p_stream) = connect_socket.connect(receiver_addr) => {
            debug!("P2P connection established to peer");
            return Ok(p2p_stream);
        }

        // Timeout after 150ms, keep the relay stream
        _ = tokio::time::sleep(Duration::from_millis(150)) => {
            debug!("P2P connection attempt timed out");
            return Err("Could not create P2P connection".into())
        }
    };
}

/// Establishes a connection to the relay server and attempts P2P connection with peer.
///
/// # Process Flow
/// 1. Connect to relay server
/// 2. Send Init message (sender/receiver status, room number, local address)
/// 3. Receive peer's address information from relay
/// 4. Attempt P2P connection (3 attempts with 150ms timeout each)
/// 5. If P2P succeeds, return P2P stream; otherwise fallback to relay stream
///
/// # Arguments
/// * `relay_addr` - Address of the relay server (e.g., "45.55.102.56:8080")
/// * `init` - Initialization message containing room number and sender/receiver status
///
/// # Returns
/// A TcpStream connected to either the peer directly (P2P) or via relay
pub async fn establish_connection(relay_addr: &str, mut init: Init) -> Result<TcpStream, Box<dyn Error>> {
    debug!("Establishing connection to relay server at {}", relay_addr);
    // Connect to relay server
    let mut relay_stream: TcpStream = TcpStream::connect(relay_addr).await?;
    println!("Connected to relay server at {}", relay_addr);
    debug!("Connected to relay server at {}", relay_addr);

    // Capture our local address before sending to relay
    let local_addr = relay_stream.local_addr()?;
    debug!("Local address: {}", local_addr);
    init.local_addr = Some(local_addr);

    // Send Init message to relay with our metadata
    let encoded_init: Vec<u8> = bincode::serialize(&init).unwrap();
    relay_stream.write_all(&encoded_init).await?;

    // Receive the peer's addresses (both external and local) from relay
    let mut buffer = vec![0; 1024];
    let peer_addresses = match relay_stream.read(&mut buffer).await {
        Ok(0) => return Err("Relay server closed connection".into()),
        Ok(n) => {
            let addresses: PeerAddresses = serde_json::from_slice(&buffer[..n])?;
            debug!("Received peer addresses - External: {}, Local: {:?}", 
                     addresses.external_addr, addresses.local_addr);
            addresses
        }
        Err(e) => return Err(e.into()),
    };

    // Determine which address to use for P2P connection (LAN vs WAN)
    let target_addr = determine_target_address(&peer_addresses, &local_addr)?;
    debug!("Target address for P2P: {}", target_addr);

    // Three attempts at connecting to the peer directly
    for attempt in 1..=3 {
        debug!("P2P connection attempt {}/3", attempt);
        match attempt_p2p_connection(local_addr, target_addr).await {
            Ok(p2p_stream) => {
                println!("P2P connection established, closing relay");
                debug!("P2P connection established successfully");
                return Ok(p2p_stream);
            }
            Err(e) => {
                println!("P2P attempt {} failed: {}", attempt, e);
                debug!("P2P attempt {} failed: {}", attempt, e);
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            }
        }
    }

    // If P2P failed after all attempts, fallback to relay
    println!("P2P failed, using relay connection");
    debug!("P2P connection failed, falling back to relay");
    Ok(relay_stream)
}

/// Determines which address to use for P2P connection based on network topology.
///
/// # Strategy
/// - If both peers are on the same local network (same /24 subnet), use local addresses
/// - Otherwise, use external (relay-visible) addresses for WAN connection
///
/// This optimization allows for faster transfers on the same LAN without going through NAT.
///
/// # Arguments
/// * `peer_addresses` - The peer's external and optional local address
/// * `my_local_addr` - Our own local address
///
/// # Returns
/// The most appropriate address to use for P2P connection attempt
fn determine_target_address(
    peer_addresses: &PeerAddresses,
    my_local_addr: &SocketAddr,
) -> Result<SocketAddr, Box<dyn Error>> {
    let my_local_ip = my_local_addr.ip();
    
    // If we have the peer's local address, check if we're on the same network
    if let Some(peer_local_addr) = peer_addresses.local_addr {
        let peer_local_ip = peer_local_addr.ip();
        
        // Compare IPs to determine if we're on the same network
        let same_network = match (my_local_ip, peer_local_ip) {
            (std::net::IpAddr::V4(my_ip), std::net::IpAddr::V4(peer_ip)) => {
                // Simple check: see if we're on the same /24 network
                let my_octets = my_ip.octets();
                let peer_octets = peer_ip.octets();
                
                // Same /24 network (first 3 octets match)
                my_octets[0] == peer_octets[0] 
                    && my_octets[1] == peer_octets[1] 
                    && my_octets[2] == peer_octets[2]
            }
            _ => false,
        };
        
        // If sender/receiver on same network, use local addresses for better performance
        if same_network {
            return Ok(peer_local_addr);
        }
    }
    
    // Different networks or no local address available, use external address
    Ok(peer_addresses.external_addr)
}

/// Performs Password-Authenticated Key Exchange (PAKE) to establish a shared encryption key.
///
/// # Process
/// 1. Creates a session identity from the shared room key
/// 2. Generates our PAKE message
/// 3. Exchanges PAKE messages with peer
/// 4. Derives a shared encryption key that both parties compute independently
///
/// # Security
/// PAKE ensures that only parties who know the shared 6-digit key can derive the
/// encryption key, preventing man-in-the-middle attacks even over an untrusted relay.
///
/// # Arguments
/// * `write_half` - TCP write half for sending data to peer
/// * `read_half` - TCP read half for receiving data from peer
/// * `shared_key` - The 6-digit shared key known to both sender and receiver
///
/// # Returns
/// A tuple containing (encryption_key, write_half, read_half)
pub async fn perform_pake(
    mut write_half: OwnedWriteHalf,
    mut read_half: OwnedReadHalf,
    shared_key: u32,
) -> Result<([u8; KEY_SIZE], OwnedWriteHalf, OwnedReadHalf), Box<dyn std::error::Error>> {
    // Create session identity and generate PAKE message
    let identity = create_session_id(shared_key);
    let (spake, message) = generate_initial_pake_message(shared_key, &identity);

    // Send our PAKE message to peer
    let encoded_message = bincode::serialize(&message)?;
    let len = encoded_message.len() as u32;
    write_half.write_u32(len).await?;
    write_half.write_all(&encoded_message).await?;

    // Receive the peer's PAKE message
    let len = read_half.read_u32().await?;
    let mut buffer = vec![0; len as usize];
    read_half.read_exact(&mut buffer).await?;
    let received_message: Vec<u8> = bincode::deserialize(&buffer)?;

    // Derive shared encryption key from PAKE exchange
    let key = derive_session_key(spake, &received_message)
        .map_err(|e| format!("PAKE key derivation failed: {:?}", e))?;
    
    Ok((key, write_half, read_half))
}

/// Sends file metadata to the peer.
///
/// # Arguments
/// * `write_half` - TCP write half
/// * `metadata` - File metadata (filename, size in bytes, is_folder flag)
///
/// # Returns
/// The write_half (for method chaining)
pub async fn send_metadata (
    mut write_half: OwnedWriteHalf,
    metadata: &FileMetadata) -> Result<OwnedWriteHalf, Box<dyn Error>> {
    // Send metadata with length prefix (same pattern as PAKE)
    let encoded_metadata: Vec<u8> = bincode::serialize(&metadata)?;
    let len = encoded_metadata.len() as u32;
    write_half.write_u32(len).await?;
    write_half.write_all(&encoded_metadata).await?;
    write_half.flush().await?;
    
    Ok(write_half)
}

/// Receives file metadata from the peer.
///
/// # Returns
/// A tuple containing (FileMetadata, read_half)
pub async fn receive_metadata(mut read_half: OwnedReadHalf) -> Result<(FileMetadata, OwnedReadHalf), Box<dyn Error>> {
    let mut buffer = vec![0; 1024];
    
    let metadata = match read_half.read(&mut buffer).await {
        Ok(0) => return Err("Relay server closed connection".into()),
        Ok(n) => {
            let metadata: FileMetadata = bincode::deserialize(&buffer[..n])?;
            metadata
        }
        Err(e) => {
            println!("Error reading message metadata");
            return Err(e.into())
        }
    };
    Ok((metadata, read_half))
}

pub async fn receive_message_metadata(mut read_half: OwnedReadHalf) -> Result<(FileMetadata, OwnedReadHalf), Box<dyn Error>> {
    // Read metadata with length prefix (same pattern as PAKE)
    let len = read_half.read_u32().await?;
    let mut buffer = vec![0; len as usize];
    read_half.read_exact(&mut buffer).await?;
    let metadata: FileMetadata = bincode::deserialize(&buffer)?;

    Ok((metadata, read_half))
}

/// Read the size of the next encrypted chunk from the network.
///
/// # Returns
/// - Some(size) if a chunk size was read successfully (size in bytes)
/// - None if EOF is reached (graceful connection close)
/// - Err if a network error occurred
pub async fn read_chunk_size(read_half: &mut OwnedReadHalf) -> Result<Option<usize>, String> {
    match read_half.read_u32().await {
        Ok(size) => Ok(Some(size as usize)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(format!("Failed to read chunk size: {}", e)),
    }
}

/// Read an encrypted chunk of the specified size from the network.
///
/// # Arguments
/// * `read_half` - TCP read half
/// * `chunk_size` - Number of bytes to read
///
/// # Returns
/// A Vec<u8> containing the encrypted chunk data
pub async fn read_encrypted_chunk(read_half: &mut OwnedReadHalf, chunk_size: usize) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0; chunk_size];
    read_half.read_exact(&mut buffer).await
        .map_err(|e| format!("Failed to read chunk data: {}", e))?;
    Ok(buffer)
}