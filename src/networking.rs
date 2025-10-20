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
/// 5. Verifies both parties derived the same key (password verification)
///
/// # Security
/// PAKE ensures that only parties who know the shared 6-digit key can derive the
/// encryption key, preventing man-in-the-middle attacks even over an untrusted relay.
/// The verification step ensures that wrong passwords are detected immediately.
///
/// # Arguments
/// * `write_socket` - TCP write half for sending data to peer
/// * `read_socket` - TCP read half for receiving data from peer
/// * `shared_key` - The 6-digit shared key known to both sender and receiver
///
/// # Returns
/// A tuple containing (encryption_key, write_socket, read_socket)
pub async fn perform_pake(
    mut write_socket: OwnedWriteHalf,
    mut read_socket: OwnedReadHalf,
    shared_key: u32,
) -> Result<([u8; KEY_SIZE], OwnedWriteHalf, OwnedReadHalf), Box<dyn std::error::Error>> {
    use crate::cryptography::encrypt_chunk;
    
    // Create session identity and generate PAKE message
    let identity = create_session_id(shared_key);
    let (spake, message) = generate_initial_pake_message(shared_key, &identity);

    // Send our PAKE message to peer
    let encoded_message = bincode::serialize(&message)?;
    let len = encoded_message.len() as u32;
    write_socket.write_u32(len).await?;
    write_socket.write_all(&encoded_message).await?;

    // Receive the peer's PAKE message
    let len = read_socket.read_u32().await?;
    let mut buffer = vec![0; len as usize];
    read_socket.read_exact(&mut buffer).await?;
    let received_message: Vec<u8> = bincode::deserialize(&buffer)?;

    // Derive shared encryption key from PAKE exchange
    let key = derive_session_key(spake, &received_message)
        .map_err(|e| format!("PAKE key derivation failed: {:?}", e))?;
    
    // VERIFICATION STEP: Ensure both parties derived the same key
    // Encrypt a known verification message and exchange it
    let verification_msg = b"PAKE_VERIFICATION_v1";
    let encrypted_verification = encrypt_chunk(&key, verification_msg, 0)
        .map_err(|e| format!("Failed to encrypt verification message: {:?}", e))?;
    
    // Send our encrypted verification
    let verify_len = encrypted_verification.len() as u32;
    write_socket.write_u32(verify_len).await?;
    write_socket.write_all(&encrypted_verification).await?;
    write_socket.flush().await?;
    
    // Receive peer's encrypted verification
    let peer_verify_len = read_socket.read_u32().await?;
    let mut peer_verification = vec![0; peer_verify_len as usize];
    read_socket.read_exact(&mut peer_verification).await?;
    
    // Try to decrypt peer's verification message
    use crate::cryptography::decrypt_chunk;
    let decrypted = decrypt_chunk(&key, &peer_verification, 0)
        .map_err(|_| "Authentication failed: Incorrect password. The 6-digit key does not match.")?;
    
    // Verify the decrypted message matches what we expect
    if &decrypted[..] != verification_msg {
        return Err("Authentication failed: Key verification mismatch. Wrong password.".into());
    }
    
    Ok((key, write_socket, read_socket))
}

/// Sends file metadata to the peer.
///
/// # Arguments
/// * `write_socket` - TCP write half
/// * `metadata` - File metadata (filename, size in bytes, is_folder flag)
///
/// # Returns
/// The write_socket (for method chaining)
pub async fn send_metadata (
    mut write_socket: OwnedWriteHalf,
    metadata: &FileMetadata) -> Result<OwnedWriteHalf, Box<dyn Error>> {
    // Send metadata with length prefix (same pattern as PAKE)
    let encoded_metadata: Vec<u8> = bincode::serialize(&metadata)?;
    let len = encoded_metadata.len() as u32;
    write_socket.write_u32(len).await?;
    write_socket.write_all(&encoded_metadata).await?;
    write_socket.flush().await?;
    
    Ok(write_socket)
}


pub async fn receive_metadata(mut read_socket: OwnedReadHalf) -> Result<(FileMetadata, OwnedReadHalf), Box<dyn Error>> {
    // Read metadata with length prefix (same pattern as PAKE)
    let len = read_socket.read_u32().await?;
    let mut buffer = vec![0; len as usize];
    read_socket.read_exact(&mut buffer).await?;
    let metadata: FileMetadata = bincode::deserialize(&buffer)?;

    Ok((metadata, read_socket))
}

/// Read the size of the next encrypted chunk from the network.
///
/// # Returns
/// - Some(size) if a chunk size was read successfully (size in bytes)
/// - None if EOF is reached (graceful connection close)
/// - Err if a network error occurred
pub async fn read_chunk_size(read_socket: &mut OwnedReadHalf) -> Result<Option<usize>, String> {
    match read_socket.read_u32().await {
        Ok(size) => Ok(Some(size as usize)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(format!("Failed to read chunk size: {}", e)),
    }
}

/// Read an encrypted chunk of the specified size from the network.
///
/// # Arguments
/// * `read_socket` - TCP read half
/// * `chunk_size` - Number of bytes to read
///
/// # Returns
/// A Vec<u8> containing the encrypted chunk data
pub async fn read_encrypted_chunk(read_socket: &mut OwnedReadHalf, chunk_size: usize) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0; chunk_size];
    read_socket.read_exact(&mut buffer).await
        .map_err(|e| format!("Failed to read chunk data: {}", e))?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use std::net::{IpAddr, Ipv4Addr};

    // ============================================================================
    // Socket Creation Tests
    // ============================================================================

    #[tokio::test]
    async fn test_create_reusable_socket_v4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let result = create_reusable_socket(addr);
        assert!(result.is_ok(), "Should create IPv4 socket successfully");
    }

    #[tokio::test]
    async fn test_create_reusable_socket_v6() {
        let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0);
        let result = create_reusable_socket(addr);
        assert!(result.is_ok(), "Should create IPv6 socket successfully");
    }

    // ============================================================================
    // Target Address Determination Tests
    // ============================================================================

    #[test]
    fn test_determine_target_address_same_network() {
        // Peers on same /24 network
        let my_local_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 
            8080
        );
        let peer_external = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(45, 55, 102, 56)), 
            9000
        );
        let peer_local = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)), 
            9000
        );
        
        let peer_addresses = PeerAddresses {
            external_addr: peer_external,
            local_addr: Some(peer_local),
        };
        
        let target = determine_target_address(&peer_addresses, &my_local_addr)
            .expect("Should determine target address");
        
        // Should use local address (same network)
        assert_eq!(target, peer_local);
    }

    #[test]
    fn test_determine_target_address_different_network() {
        // Peers on different networks
        let my_local_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 
            8080
        );
        let peer_external = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(45, 55, 102, 56)), 
            9000
        );
        let peer_local = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)), 
            9000
        );
        
        let peer_addresses = PeerAddresses {
            external_addr: peer_external,
            local_addr: Some(peer_local),
        };
        
        let target = determine_target_address(&peer_addresses, &my_local_addr)
            .expect("Should determine target address");
        
        // Should use external address (different networks)
        assert_eq!(target, peer_external);
    }

    #[test]
    fn test_determine_target_address_no_local_address() {
        let my_local_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 
            8080
        );
        let peer_external = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(45, 55, 102, 56)), 
            9000
        );
        
        let peer_addresses = PeerAddresses {
            external_addr: peer_external,
            local_addr: None,
        };
        
        let target = determine_target_address(&peer_addresses, &my_local_addr)
            .expect("Should determine target address");
        
        // Should fallback to external address
        assert_eq!(target, peer_external);
    }

    #[test]
    fn test_determine_target_address_same_subnet_boundary() {
        // Test edge of /24 subnet
        let my_local_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 
            8080
        );
        let peer_local = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)), 
            9000
        );
        let peer_external = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(45, 55, 102, 56)), 
            9000
        );
        
        let peer_addresses = PeerAddresses {
            external_addr: peer_external,
            local_addr: Some(peer_local),
        };
        
        let target = determine_target_address(&peer_addresses, &my_local_addr)
            .expect("Should determine target address");
        
        // Should use local (same /24)
        assert_eq!(target, peer_local);
    }

    #[test]
    fn test_determine_target_address_different_subnet() {
        // Different /24 subnet
        let my_local_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 
            8080
        );
        let peer_local = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 100)), // Different third octet
            9000
        );
        let peer_external = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(45, 55, 102, 56)), 
            9000
        );
        
        let peer_addresses = PeerAddresses {
            external_addr: peer_external,
            local_addr: Some(peer_local),
        };
        
        let target = determine_target_address(&peer_addresses, &my_local_addr)
            .expect("Should determine target address");
        
        // Should use external (different subnets)
        assert_eq!(target, peer_external);
    }

    // ============================================================================
    // PAKE Handshake Tests
    // ============================================================================

    #[tokio::test]
    async fn test_pake_handshake_symmetric() {
        use tokio::net::{TcpListener, TcpStream};
        
        let shared_key = 123456u32;
        
        // Create a local server for testing
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Spawn server task
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_socket, write_socket) = stream.into_split();
            let result = perform_pake(write_socket, read_socket, shared_key).await;
            match result {
                Ok((key, _, _)) => Some(key),
                Err(_) => None,
            }
        });
        
        // Client connects
        let client_stream = TcpStream::connect(addr).await.unwrap();
        let (read_socket, write_socket) = client_stream.into_split();
        let client_result = perform_pake(write_socket, read_socket, shared_key).await;
        
        // Wait for server
        let server_key = server_handle.await.unwrap();
        
        // Both should succeed
        assert!(client_result.is_ok(), "Client PAKE should succeed");
        assert!(server_key.is_some(), "Server PAKE should succeed");
        
        // Both should derive the same key
        let (client_key, _, _) = client_result.unwrap();
        assert_eq!(client_key, server_key.unwrap(), "Both parties should derive same key");
    }

    #[tokio::test]
    async fn test_pake_handshake_wrong_password() {
        use tokio::net::{TcpListener, TcpStream};
        
        let server_key = 123456u32;
        let client_key = 654321u32;
        
        // Create a local server for testing
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Spawn server task
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_socket, write_socket) = stream.into_split();
            let result = perform_pake(write_socket, read_socket, server_key).await;
            result.is_err()
        });
        
        // Client connects with different key
        let client_stream = TcpStream::connect(addr).await.unwrap();
        let (read_socket, write_socket) = client_stream.into_split();
        let client_result = perform_pake(write_socket, read_socket, client_key).await;
        
        // Wait for server
        let server_failed = server_handle.await.unwrap();
        
        // With password verification, at least one should fail
        // (Both will fail because decryption will fail on both sides)
        assert!(
            client_result.is_err() || server_failed,
            "PAKE with different passwords should fail during verification"
        );
    }

    // ============================================================================
    // Metadata Exchange Tests
    // ============================================================================

    #[tokio::test]
    async fn test_send_receive_metadata() {
        use tokio::net::{TcpListener, TcpStream};
        
        let metadata = FileMetadata {
            filename: "test.txt".to_string(),
            file_size: 1024,
            is_folder: false,
        };
        
        let metadata_clone = metadata.clone();
        
        // Create a local server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Spawn receiver task
        let receiver_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_socket, _write_socket) = stream.into_split();
            let result = receive_metadata(read_socket).await;
            match result {
                Ok((metadata, _)) => Some(metadata),
                Err(_) => None,
            }
        });
        
        // Sender connects and sends metadata
        let sender_stream = TcpStream::connect(addr).await.unwrap();
        let (_read_socket, write_socket) = sender_stream.into_split();
        let send_result = send_metadata(write_socket, &metadata).await;
        
        assert!(send_result.is_ok(), "Send metadata should succeed");
        
        // Wait for receiver
        let received_metadata = receiver_handle.await.unwrap().expect("Should receive metadata");
        
        assert_eq!(received_metadata.filename, metadata_clone.filename);
        assert_eq!(received_metadata.file_size, metadata_clone.file_size);
        assert_eq!(received_metadata.is_folder, metadata_clone.is_folder);
    }

    #[tokio::test]
    async fn test_send_receive_folder_metadata() {
        use tokio::net::{TcpListener, TcpStream};
        
        let metadata = FileMetadata {
            filename: "my_folder".to_string(),
            file_size: 4096,
            is_folder: true,
        };
        
        let metadata_clone = metadata.clone();
        
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let receiver_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_socket, _) = stream.into_split();
            let result = receive_metadata(read_socket).await;
            match result {
                Ok((metadata, _)) => Some(metadata),
                Err(_) => None,
            }
        });
        
        let sender_stream = TcpStream::connect(addr).await.unwrap();
        let (_, write_socket) = sender_stream.into_split();
        let _ = send_metadata(write_socket, &metadata).await;
        
        let received_metadata = receiver_handle.await.unwrap().unwrap();
        assert_eq!(received_metadata.filename, metadata_clone.filename);
        assert_eq!(received_metadata.is_folder, true);
    }

    // ============================================================================
    // Chunk Read/Write Tests
    // ============================================================================

    #[tokio::test]
    async fn test_read_chunk_size() {
        use tokio::net::{TcpListener, TcpStream};
        
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let receiver_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_read, mut write) = stream.into_split();
            
            // Send chunk size
            write.write_u32(1024).await.unwrap();
            write.flush().await.unwrap();
        });
        
        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut read, _) = stream.into_split();
        
        let size = read_chunk_size(&mut read).await.unwrap();
        assert_eq!(size, Some(1024));
        
        receiver_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_chunk_size_eof() {
        use tokio::net::{TcpListener, TcpStream};
        
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let receiver_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream); // Close connection immediately
        });
        
        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut read, _) = stream.into_split();
        
        // Small delay to ensure connection closes
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        let size = read_chunk_size(&mut read).await.unwrap();
        assert_eq!(size, None, "Should return None on EOF");
        
        receiver_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_encrypted_chunk() {
        use tokio::net::{TcpListener, TcpStream};
        
        let test_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let test_data_clone = test_data.clone();
        
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let sender_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_, mut write) = stream.into_split();
            
            write.write_all(&test_data_clone).await.unwrap();
            write.flush().await.unwrap();
        });
        
        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut read, _) = stream.into_split();
        
        let chunk = read_encrypted_chunk(&mut read, test_data.len()).await.unwrap();
        assert_eq!(chunk, test_data);
        
        sender_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_write_multiple_chunks() {
        use tokio::net::{TcpListener, TcpStream};
        
        let chunks = vec![
            vec![1u8; 100],
            vec![2u8; 200],
            vec![3u8; 300],
        ];
        let chunks_clone = chunks.clone();
        
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let sender_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_, mut write) = stream.into_split();
            
            for chunk in &chunks_clone {
                write.write_u32(chunk.len() as u32).await.unwrap();
                write.write_all(chunk).await.unwrap();
                write.flush().await.unwrap();
            }
        });
        
        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut read, _) = stream.into_split();
        
        for expected_chunk in &chunks {
            let size = read_chunk_size(&mut read).await.unwrap().unwrap();
            let chunk = read_encrypted_chunk(&mut read, size).await.unwrap();
            assert_eq!(chunk, *expected_chunk);
        }
        
        sender_task.await.unwrap();
    }
}