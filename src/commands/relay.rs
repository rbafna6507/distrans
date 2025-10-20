use tokio::net::TcpListener;
use tokio::sync::mpsc;
use std::error::Error;
use crate::relay_utils::{ConnectionManager, Message, relay_manager, handle_new_connection};
use log::{debug, info};

/// Run the relay server that coordinates connections between senders and receivers.
/// 
/// # Overview
/// The relay server acts as a rendezvous point for file transfers. It:
/// 1. Accepts incoming connections from both senders and receivers
/// 2. Groups them into "rooms" based on a shared room number
/// 3. Facilitates peer-to-peer (P2P) connection attempts between matched pairs
/// 4. Falls back to relaying data if P2P connection fails
///
/// # Architecture
/// - Main task: Accepts new TCP connections in a loop
/// - Connection handler tasks: One per client, processes initial handshake
/// - Manager task: Central coordinator that manages rooms and connection pairing
///
/// # Process Flow
/// 1. Client connects and sends an Init message with room number and sender/receiver status
/// 2. Connection handler extracts this info and forwards it to the manager
/// 3. Manager creates/joins room and attempts P2P connection when both peers are ready
/// 4. If P2P fails, relay proxies data between sender and receiver
///
/// # Arguments
/// * `port` - The port number to bind the relay server to (typically 8080)
///
/// # Returns
/// Returns `Ok(())` if server starts successfully, or an error if binding fails
pub async fn run(port: u16) -> Result<(), Box<dyn Error>> {
    // Bind the server to 0.0.0.0:<port> - default is 8080
    let bind_addr = format!("0.0.0.0:{}", port);
    debug!("Attempting to bind to {}", bind_addr);
    
    let listener = TcpListener::bind(&bind_addr).await?;
    println!("Server listening on {}", bind_addr);
    info!("Relay server started on {}", bind_addr);

    // Create a message passing channel for communication between connection handlers and the manager
    // Buffer size of 100 allows for bursts of connections without blocking
    let (sender_channel, receiver_channel) = mpsc::channel::<Message>(100);
    let manager = ConnectionManager::new(sender_channel.clone(), receiver_channel);
    
    // Spawn the manager task that will handle room creation, peer matching, and P2P coordination
    debug!("Spawning relay manager task");
    tokio::spawn(relay_manager(manager));

    // Main accept loop: listen for incoming client connections indefinitely
    loop {
        let (stream, addr) = listener.accept().await?;
        println!("Client connected: {}", addr);
        info!("New client connection from: {}", addr);

        // Spawn a dedicated task to handle this connection's initialization
        // This allows the server to continue accepting new connections immediately
        debug!("Spawning relay connection handler for {}", addr);
        tokio::spawn(handle_new_connection(stream, addr, sender_channel.clone()));
    }
}
