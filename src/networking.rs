use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, TcpSocket, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::{error::Error, net::SocketAddr};
use std::time::Duration;
use crate::cryptography::{generate_initial_pake_message, create_session_id, derive_session_key};
use crate::utils::{FileMetadata, Init, PeerAddresses};
use crate::KEY_SIZE;
use log::{debug};


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


pub async fn attempt_p2p_connection(local_addr: SocketAddr, receiver_addr: SocketAddr) -> Result<TcpStream, Box<dyn Error>> {
    debug!("Attempting P2P connection from {} to {}", local_addr, receiver_addr);
    // open a listening socket to accept the tcp hole punch
    let listen_socket: TcpSocket = create_reusable_socket(local_addr)?;
    let listener: TcpListener = listen_socket.listen(1024)?;
    debug!("Created listening socket on {}", local_addr);

    // open a new socket connection to connect to the other peer
    let connect_socket:TcpSocket = create_reusable_socket(local_addr)?;

    tokio::select! {
        // try to accept peer's connection
        Ok((p2p_stream, _addr)) = listener.accept() => {
            debug!("P2P connection accepted from peer");
            return Ok(p2p_stream);
        }

        // try connecting to peer (tcp hole punch) 
        Ok(p2p_stream) = connect_socket.connect(receiver_addr) => {
            debug!("P2P connection established to peer");
            return Ok(p2p_stream);
        }

        // timeout after 50ms, keep the relay stream
        _ = tokio::time::sleep(Duration::from_millis(150)) => {
            debug!("P2P connection attempt timed out");
            return Err("Could not create P2P connection".into())
        }
    };
}


pub async fn establish_connection(relay_addr: &str, mut init: Init) -> Result<TcpStream, Box<dyn Error>> {
    debug!("Establishing connection to relay server at {}", relay_addr);
    // connect to relay server
    let mut relay_stream: TcpStream = TcpStream::connect(relay_addr).await?;
    println!("Connected to relay server at {}", relay_addr);
    debug!("Connected to relay server at {}", relay_addr);

    // Capture our local address before sending to relay
    let local_addr = relay_stream.local_addr()?;
    debug!("Local address: {}", local_addr);
    init.local_addr = Some(local_addr);

    let encoded_init: Vec<u8> = bincode::serialize(&init).unwrap();
    relay_stream.write_all(&encoded_init).await?;

    // Receive the peer's addresses (both external and local)
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

    // Determine which address to use for P2P connection
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

    // if p2p failed, fallback to relay
    println!("P2P failed, using relay connection");
    debug!("P2P connection failed, falling back to relay");
    Ok(relay_stream)
}

fn determine_target_address(
    peer_addresses: &PeerAddresses,
    my_local_addr: &SocketAddr,
) -> Result<SocketAddr, Box<dyn Error>> {
    let my_local_ip = my_local_addr.ip();
    
    // if we have the peer's local address
    if let Some(peer_local_addr) = peer_addresses.local_addr {
        let peer_local_ip = peer_local_addr.ip();
        
        // compare IPs to determine if we're on the same network
        let same_network = match (my_local_ip, peer_local_ip) {
            (std::net::IpAddr::V4(my_ip), std::net::IpAddr::V4(peer_ip)) => {
                // easy check to see if we're on the same network
                let my_octets = my_ip.octets();
                let peer_octets = peer_ip.octets();
                
                // Same /24 network (first 3 octets match)
                my_octets[0] == peer_octets[0] 
                    && my_octets[1] == peer_octets[1] 
                    && my_octets[2] == peer_octets[2]
            }
            _ => false,
        };
        
        // if sender/receiver on same network, use local addresses
        if same_network {
            // println!("Same local network detected, using peer's local address: {}", peer_local_addr);
            return Ok(peer_local_addr);
        }
    }
    
    // different networks or no local address available, use external address
    // println!("Using peer's external address for P2P: {}", peer_addresses.external_addr);
    Ok(peer_addresses.external_addr)
}


pub async fn perform_pake(
    mut write_half: OwnedWriteHalf,
    mut read_half: OwnedReadHalf,
    shared_key: u32,
) -> Result<([u8; KEY_SIZE], OwnedWriteHalf, OwnedReadHalf), Box<dyn std::error::Error>> {
    let identity = create_session_id(shared_key);
    let (spake, message) = generate_initial_pake_message(shared_key, &identity);

    // send our PAKE message
    let encoded_message = bincode::serialize(&message)?;
    let len = encoded_message.len() as u32;
    write_half.write_u32(len).await?;
    write_half.write_all(&encoded_message).await?;

    // receive the peer's PAKE message
    let len = read_half.read_u32().await?;
    let mut buffer = vec![0; len as usize];
    read_half.read_exact(&mut buffer).await?;
    let received_message: Vec<u8> = bincode::deserialize(&buffer)?;

    let key = derive_session_key(spake, &received_message)
        .map_err(|e| format!("PAKE key derivation failed: {:?}", e))?;
    Ok((key, write_half, read_half))
}


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

pub async fn receive_message_metadata(mut read_half: OwnedReadHalf) -> Result<(FileMetadata, OwnedReadHalf), Box<dyn Error>> {
    // Read metadata with length prefix (same pattern as PAKE)
    let len = read_half.read_u32().await?;
    let mut buffer = vec![0; len as usize];
    read_half.read_exact(&mut buffer).await?;
    let metadata: FileMetadata = bincode::deserialize(&buffer)?;

    Ok((metadata, read_half))
}

/// Read the size of the next encrypted chunk from the network
/// Returns None if EOF is reached (graceful connection close)
pub async fn read_chunk_size(read_half: &mut OwnedReadHalf) -> Result<Option<usize>, String> {
    match read_half.read_u32().await {
        Ok(size) => Ok(Some(size as usize)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(format!("Failed to read chunk size: {}", e)),
    }
}

/// Read an encrypted chunk of the specified size from the network
pub async fn read_encrypted_chunk(read_half: &mut OwnedReadHalf, chunk_size: usize) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0; chunk_size];
    read_half.read_exact(&mut buffer).await
        .map_err(|e| format!("Failed to read chunk data: {}", e))?;
    Ok(buffer)
}