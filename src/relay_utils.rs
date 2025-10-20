use tokio::net::{TcpStream};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{self, Receiver, Sender};
use std::net::SocketAddr;
use std::collections::{HashMap, hash_map::Entry};
use std::error::Error;
use crate::utils::{Init, PeerAddresses};
use crate::{CHUNK_SIZE};

/// Main event loop for the relay connection manager.
///
/// This function runs continuously, processing incoming messages from connection handlers.
/// It dispatches messages to appropriate handler methods based on message type:
/// - NewConnection: A client has connected and needs to be assigned to a room
/// - AttemptP2P: Both sender and receiver are ready; try establishing direct P2P connection
///
/// # Arguments
/// * `manager` - The ConnectionManager instance that maintains room state
pub async fn relay_manager(mut manager: ConnectionManager) {
    loop {
        while let Some(message) = manager.receiver_channel.recv().await {
            match message {
                Message::NewConnection(message) => {
                    // Process new client connection and assign to appropriate room
                    let _ = manager.create_or_assign_room(message).await;
                },
                Message::AttemptP2P(message) => {
                    // Both peers are connected; attempt peer-to-peer connection
                    let _ = manager.attempt_p2p(message.room).await;
                }
            }
        }
    }
}

/// Manages relay server state and coordinates connections between senders and receivers.
///
/// The ConnectionManager is responsible for:
/// - Maintaining a mapping of room IDs to Room instances
/// - Handling new client connections and assigning them to rooms
/// - Coordinating P2P connection attempts between matched peers
/// - Relaying data if P2P connection fails
pub struct ConnectionManager {
    /// Maps room IDs to Room instances containing sender/receiver connections
    pub rooms: HashMap<u32, Room>,
    /// Channel for sending messages to self (used for async task coordination)
    pub sender_channel: mpsc::Sender<Message>,
    /// Channel for receiving messages from connection handlers
    pub receiver_channel: mpsc::Receiver<Message>
}

impl ConnectionManager {
    /// Creates a new ConnectionManager with empty room map and the provided channels.
    ///
    /// # Arguments
    /// * `sender_channel` - Used to send messages back to the manager (e.g., trigger P2P attempts)
    /// * `receiver_channel` - Receives messages from connection handler tasks
    pub fn new(sender_channel: Sender<Message>, receiver_channel: Receiver<Message>) -> Self {
        ConnectionManager {rooms: HashMap::new(), sender_channel: sender_channel, receiver_channel: receiver_channel}
    }

    /// Processes a new client connection and assigns it to the appropriate room.
    ///
    /// # Process Flow
    /// - If sender: Create a new room (or reject if room already has a sender)
    /// - If receiver: Join existing room (or reject if no sender is present)
    /// - When both sender and receiver are in a room, trigger a P2P connection attempt
    ///
    /// # Arguments
    /// * `message` - Contains the client's connection and metadata (sender/receiver status, room number)
    ///
    /// # Returns
    /// Returns Ok(()) if successful, or an error if the operation fails
    pub async fn create_or_assign_room(&mut self, message: NewConnection) -> Result<(), Box<dyn Error>>{
        let desired_room = message.meta.room;
        let is_sender = message.meta.is_sender;

        if is_sender {
            // Sender is attempting to create a new room
            match self.rooms.entry(desired_room) {
                Entry::Vacant(e) => {
                    // Room doesn't exist; create it with this sender
                    let sender_addr = message.connection.addr;
                    e.insert(Room { sender: message.connection, receiver: None });
                    println!("Created room {} and moved sender at addr {} to it", desired_room, sender_addr);
                }
                Entry::Occupied(_) => {
                    // Room already has a sender; reject this duplicate
                    println!("Room {} already exists with a sender. Rejecting duplicate sender.", desired_room);
                }
            }
        } else {
            // Receiver is attempting to join an existing room
            let room = self.rooms.get_mut(&desired_room)
                .ok_or("Room does not exist - sender must connect first")?;
            
            // Verify sender is still connected before pairing with receiver
            if !Self::is_connection_alive(&mut room.sender.stream).await {
                println!("Sender in room {} has disconnected. Cleaning up room.", desired_room);
                self.rooms.remove(&desired_room);
                return Err("Sender disconnected before receiver joined".into());
            }
            
            let receiver_addr = message.connection.addr;
            room.receiver = Some(message.connection);
            println!("Added receiver to room {} with addr {}", desired_room, receiver_addr);

            // Both sender and receiver are now in the room - trigger P2P attempt
            self.sender_channel.send(Message::AttemptP2P(AttemptP2P { room: desired_room })).await?;
        }

        Ok(())
    }

    /// Attempts to establish a direct peer-to-peer connection between sender and receiver.
    ///
    /// # Process Flow
    /// 1. Remove the room from the rooms map (we're about to handle it)
    /// 2. Exchange peer address information between sender and receiver
    /// 3. Enter relay mode: proxy data bidirectionally between sender and receiver
    /// 4. Continue relaying until connection closes or error occurs
    ///
    /// If P2P connection succeeds on the client side, clients will disconnect from relay.
    /// If P2P fails, this relay connection will continue to proxy data between them.
    ///
    /// # Arguments
    /// * `room_id` - The ID of the room containing both sender and receiver
    pub async fn attempt_p2p(&mut self, room_id: u32) {
        if let Some(room) = self.rooms.remove(&room_id) {
            println!("Room exists, Attempting peer2peer connection");
            
            let mut sender = room.sender;
            let mut receiver = room.receiver.unwrap();

            // Package up both external (relay-visible) and local (LAN) addresses for each peer
            let receiver_addresses = PeerAddresses {
                external_addr: receiver.addr,
                local_addr: receiver.local_addr,
            };
            
            let sender_addresses = PeerAddresses {
                external_addr: sender.addr,
                local_addr: sender.local_addr,
            };

            println!("Sending to sender - Receiver external: {}, local: {:?}", 
                     receiver_addresses.external_addr, receiver_addresses.local_addr);
            println!("Sending to receiver - Sender external: {}, local: {:?}", 
                     sender_addresses.external_addr, sender_addresses.local_addr);

            // Serialize and send address information to both peers
            let receiver_addr_json = serde_json::to_vec(&receiver_addresses)
                .expect("Failed to serialize receiver addresses");
            let sender_addr_json = serde_json::to_vec(&sender_addresses)
                .expect("Failed to serialize sender addresses");

            // Send receiver's addresses to sender (so sender can attempt direct connection)
            if let Err(e) = sender.stream.write_all(&receiver_addr_json).await {
                eprintln!("Failed to send receiver addresses to sender: {}", e);
                return;
            }

            // Send sender's addresses to receiver (so receiver can attempt direct connection)
            if let Err(e) = receiver.stream.write_all(&sender_addr_json).await {
                eprintln!("Failed to send sender addresses to receiver: {}", e);
                return;
            }

            // Enter relay mode: bidirectionally copy data between sender and receiver
            // This loop continues until either:
            // - Both peers disconnect (P2P succeeded and they're talking directly)
            // - One peer disconnects (transfer complete or error)
            // - Relay error occurs
            loop {
                match copy_bidirectional(&mut sender.stream, &mut receiver.stream).await {
                    Ok((0, 0)) => {
                        // Both directions returned 0 bytes - clean connection close
                        println!(
                            "Connection between {} and {} closed. Sent {} bytes, received {} bytes.",
                            sender.addr, receiver.addr, 0, 0
                        );
                        println!("Relay session ended for {} <-> {}", sender.addr, receiver.addr);
                        return;
                    },
                    Ok((bytes_sent, bytes_received)) => {
                        // Data was relayed; log the throughput
                        println!(
                            "Sent {} bytes, received {} bytes.",
                            bytes_sent, bytes_received
                        );
                    }
                    Err(e) => {
                        // Network error during relay
                        eprintln!(
                            "Error relaying data between {} and {}: {}",
                            sender.addr, receiver.addr, e
                        );
                        return;
                    }
                }
            }
        }
    }

    /// Check if a TCP connection is still alive by attempting a non-blocking read.
    ///
    /// # Returns
    /// - `true` if connection is alive (either has data or would block waiting for data)
    /// - `false` if connection is closed or has an error
    async fn is_connection_alive(stream: &mut TcpStream) -> bool {
        let mut buf = [0u8; 1];
        match stream.try_read(&mut buf) {
            Ok(0) => false,      // Connection closed (EOF)
            Ok(_) => true,        // Data available - connection alive
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true, // No data yet, but connection alive
            Err(_) => false,     // Connection error
        }
    }

}

/// Handles the initial handshake for a new client connection.
///
/// # Process Flow
/// 1. Reads the client's Init message from the TCP stream
/// 2. Extracts room number, sender/receiver status, and local address
/// 3. Packages this information into a NewConnection message
/// 4. Forwards the message to the ConnectionManager for room assignment
///
/// # Arguments
/// * `stream` - The TCP connection to the client
/// * `addr` - The client's external (relay-visible) socket address
/// * `manager_channel` - Channel for sending messages to the ConnectionManager
pub async fn handle_new_connection(mut stream: TcpStream, addr: SocketAddr, manager_channel: Sender<Message>) {
    // Allocate a buffer to read the initial message (Init struct)
    let mut buffer = vec![0; CHUNK_SIZE];
    
    // Deserialize the Init message from the stream
    let message = match stream.read(&mut buffer).await {
        Ok(0) => {
            eprintln!("Client disconnected from server during initial processing");
            return;
        }
        Ok(_n) => {
            let init: Init = bincode::deserialize(&buffer[..]).unwrap();
            println!("Received init: {:?}", init);
            
            let local_addr = init.local_addr;
            
            NewConnection { 
                connection: Connection { 
                    stream, 
                    addr,
                    local_addr,
                }, 
                meta: init 
            }
        }
        Err(e) => {
            eprintln!("Error encountered when reading from initial connection stream: {}", e);
            return;
        }
    };

    // Forward the new connection to the manager for processing
    if let Err(e) = manager_channel.send(Message::NewConnection(message)).await {
        eprintln!("Failed to send message to manager: {}", e);
    }
}

/// Represents an active TCP connection to a client (sender or receiver).
pub struct Connection {
    /// The TCP stream for communicating with this client
    pub stream: TcpStream,
    /// The client's external address (as seen by the relay server)
    pub addr: SocketAddr,
    /// The client's local network address (for LAN P2P optimization)
    pub local_addr: Option<SocketAddr>,
}

/// Represents a "room" where a sender and receiver meet for a file transfer.
///
/// Each room is identified by a room ID (derived from the shared 6-digit key).
/// A room starts with just a sender, then a receiver joins, and finally they
/// attempt to establish a direct P2P connection.
pub struct Room {
    /// The sender's connection (always present)
    pub sender: Connection,
    /// The receiver's connection (None until receiver joins)
    pub receiver: Option<Connection>,
}

/// Message containing a new client connection that needs room assignment.
pub struct NewConnection {
    /// The client's TCP connection and address information
    pub connection: Connection,
    /// Metadata from the client (sender/receiver status, room ID, local address)
    pub meta: Init
}

/// Message indicating both peers are ready and P2P should be attempted.
pub struct AttemptP2P {
    /// The room ID where sender and receiver are waiting
    pub room: u32,
}

/// Messages passed between connection handlers and the ConnectionManager.
pub enum Message {
    /// A new client has connected and needs room assignment
    NewConnection(NewConnection),
    /// Both sender and receiver are in a room; attempt P2P connection
    AttemptP2P(AttemptP2P),
}