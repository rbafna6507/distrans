use tokio::net::{TcpStream};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{self, Receiver, Sender};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::error::Error;
use crate::utils::Init;
use crate::utils::{PeerAddresses};
use crate::{CHUNK_SIZE};


pub struct ConnectionManager {
    pub rooms: HashMap<u32, Room>,
    pub sender_channel: mpsc::Sender<Message>,
    pub receiver_channel: mpsc::Receiver<Message>
}

impl ConnectionManager {
    pub fn new(sender_channel: Sender<Message>, receiver_channel: Receiver<Message>) -> Self {
        ConnectionManager {rooms: HashMap::new(), sender_channel: sender_channel, receiver_channel: receiver_channel}
    }

    pub async fn create_or_assign_room(&mut self, message: NewConnection) -> Result<(), Box<dyn Error>>{
        let desired_room = message.meta.room;
        let is_sender = message.meta.is_sender;

        if is_sender {
            // Use Entry API to avoid double lookup
            use std::collections::hash_map::Entry;
            match self.rooms.entry(desired_room) {
                Entry::Vacant(e) => {
                    let sender_addr = message.connection.addr;
                    e.insert(Room { sender: message.connection, receiver: None });
                    println!("Created room {} and moved sender at addr {} to it", desired_room, sender_addr);
                }
                Entry::Occupied(_) => {
                    println!("Room {} already exists with a sender. Rejecting duplicate sender.", desired_room);
                    // Optionally notify the duplicate sender before dropping the connection
                }
            }
        } else {
            // Receiver joining
            let room = self.rooms.get_mut(&desired_room)
                .ok_or("Room does not exist - sender must connect first")?;
            
            // Check if sender is still connected before adding receiver
            if !Self::is_connection_alive(&mut room.sender.stream).await {
                println!("Sender in room {} has disconnected. Cleaning up room.", desired_room);
                self.rooms.remove(&desired_room);
                return Err("Sender disconnected before receiver joined".into());
            }
            
            let receiver_addr = message.connection.addr;
            room.receiver = Some(message.connection);
            println!("Added receiver to room {} with addr {}", desired_room, receiver_addr);

            // Both sender and receiver are now in the room - attempt P2P
            self.sender_channel.send(Message::AttemptP2P(AttemptP2P { room: desired_room })).await?;
        }

        Ok(())
    }

    // Check if a TCP connection is still alive by attempting a peek
    async fn is_connection_alive(stream: &mut TcpStream) -> bool {
        let mut buf = [0u8; 1];
        match stream.try_read(&mut buf) {
            Ok(0) => false, // Connection closed
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true, // No data, but alive
            Err(_) => false,
            Ok(_) => true,
        }
    }



    pub async fn attempt_p2p(&mut self, room_id: u32) {
        if let Some(room) = self.rooms.remove(&room_id) {
            println!("Room exists, attempting peer2peer connection");
            
            let mut sender = room.sender;
            let mut receiver = room.receiver.unwrap();

            // Create PeerAddresses structs with both external and local addresses
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

            let receiver_addr_json = serde_json::to_vec(&receiver_addresses)
                .expect("Failed to serialize receiver addresses");
            let sender_addr_json = serde_json::to_vec(&sender_addresses)
                .expect("Failed to serialize sender addresses");

            if let Err(e) = sender.stream.write_all(&receiver_addr_json).await {
                eprintln!("Failed to send receiver addresses to sender: {}", e);
                return;
            }

            if let Err(e) = receiver.stream.write_all(&sender_addr_json).await {
                eprintln!("Failed to send sender addresses to receiver: {}", e);
                return;
            }

            // this uses the relay as long as the connection is still alive (eg. sender hasn't disconnected)
            // instead of echoing messages immediately, need to do PAKE
            loop {
                match copy_bidirectional(&mut sender.stream, &mut receiver.stream).await {
                    Ok((0, 0)) => {
                        println!(
                            "Connection between {} and {} closed. Sent {} bytes, received {} bytes.",
                            sender.addr, receiver.addr, 0, 0
                        );
                        println!("Relay session ended for {} <-> {}", sender.addr, receiver.addr);
                        return;
                    },
                    Ok((bytes_sent, bytes_received)) => {
                        println!(
                            "Sent {} bytes, received {} bytes.",
                            bytes_sent, bytes_received
                        );
                    }
                    Err(e) => {
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

}

pub async fn relay_manager(mut manager: ConnectionManager) {

    loop {
        while let Some(message) = manager.receiver_channel.recv().await {
            match message {
                Message::NewConnection(message) => {
                    // process_request
                    let _ = manager.create_or_assign_room(message).await;
                },
                Message::AttemptP2P(message) => {
                    let _ = manager.attempt_p2p(message.room).await;
                }
            }
        }
    }
}

pub async fn relay_new_connection(mut stream: TcpStream, addr: SocketAddr, manager_channel: Sender<Message>) {
    // make buffer to read in the data
    let mut buffer = vec![0; CHUNK_SIZE];
    
    // deserialize 'init' message from the stream
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

    if let Err(e) = manager_channel.send(Message::NewConnection(message)).await {
        eprintln!("Failed to send message to manager: {}", e);
    }
}


pub struct Connection {
    pub stream: TcpStream,
    pub addr: SocketAddr,
    pub local_addr: Option<SocketAddr>,
}

pub struct NewConnection {
    pub connection: Connection,
    pub meta: Init
}

pub struct AttemptP2P {
    pub room: u32,
}


pub enum Message {
    NewConnection(NewConnection),
    AttemptP2P(AttemptP2P),
}


pub struct Room {
    pub sender: Connection,
    pub receiver: Option<Connection>,
}