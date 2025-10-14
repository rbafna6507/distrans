use tokio::net::{TcpListener, TcpStream};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{self, Receiver, Sender};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::error::Error;
use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug, Clone)]
struct Init{
    is_sender: bool,
    room: u32,
    local_addr: Option<SocketAddr>,
    // other relevant file data eventually
    // like pake password hash
    // file metadata - name, size, etc
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PeerAddresses {
    external_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
}
// must be mutable to read/write stream
struct Connection {
    stream: TcpStream,
    addr: SocketAddr,
    local_addr: Option<SocketAddr>,
}

struct NewConnection {
    connection: Connection,
    meta: Init
}

struct AttemptP2P {
    room: u32,
}


enum Message {
    NewConnection(NewConnection),
    AttemptP2P(AttemptP2P),
}

struct Room {
    sender: Connection,
    receiver: Option<Connection>,
    // file_name: String,
    // file_size: u128,
}


struct ConnectionManager {
    rooms: HashMap<u32, Room>,
    sender_channel: mpsc::Sender<Message>,
    receiver_channel: mpsc::Receiver<Message>
}

impl ConnectionManager {
    pub fn new(sender_channel: Sender<Message>, receiver_channel: Receiver<Message>) -> Self {
        ConnectionManager {rooms: HashMap::new(), sender_channel: sender_channel, receiver_channel: receiver_channel}
    }

    pub async fn create_or_assign_room(self: &mut Self, message: NewConnection) -> Result<(), Box<dyn Error>>{
        let desired_room = message.meta.room;
        let is_sender:bool = message.meta.is_sender;

        if is_sender && !self.rooms.contains_key(&desired_room)  {
            let new_room: Room = Room { sender: message.connection, receiver: None };
            self.rooms.insert(desired_room, new_room);
            let sender_addr = self.rooms.get(&desired_room).unwrap().sender.addr;
            println!("Created room {} and moved sender at addr {} to it", desired_room, sender_addr)
        } else if is_sender && self.rooms.contains_key(&desired_room) {
            println!("Room already exists with a sender.")
        }
        else {
            let room = self.rooms.get_mut(&desired_room).ok_or("Room does not exist")?;
            room.receiver = Some(message.connection);
            let receiver_addr = room.receiver.as_ref().unwrap().addr;
            println!("Added receiver to room {} with addr {}", desired_room, receiver_addr);

            if room.receiver.is_some() {
                // if sender and receiver are both in the room
                // send a messsage to relayManager to kick off p2p attemp
                self.sender_channel.send(Message::AttemptP2P(AttemptP2P { room: desired_room })).await?;
            }
        }

        // once both are in room, tell relayManager to kick off p2p attempt (send ip's to each other)

        // once ip's have been sent to each other and room has not closed, kick off communication task
        // clients have the logic for PAKE and file transfer
        Ok(())
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



#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    println!("Server listening on 0.0.0.0:3000");

    // let listener = TcpListener::bind("0.0.0.0:8080").await?;
    // println!("Server listening on 0.0.0.0:8080");

    let (sender_channel, receiver_channel) = mpsc::channel::<Message>(100);
    let manager = ConnectionManager::new(sender_channel.clone(), receiver_channel);
    
    tokio::spawn(relay_manager(manager));

    loop {
        // first connection is always sender
        let (stream, addr) = listener.accept().await?;
        println!("client connected: {}", addr);

        // task to send content from sender to receiver
        tokio::spawn(relay_new_connection(stream, addr, sender_channel.clone()));
    }
}


async fn relay_manager(mut manager: ConnectionManager) {

    loop {
        // basically a match statement right?
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

async fn relay_new_connection(mut stream: TcpStream, addr: SocketAddr, manager_channel: Sender<Message>) {
    // make buffer to read in the data
    let mut buffer = vec![0; 1024];
    
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



















// async fn handle_relay(
//     mut sender_stream: TcpStream,
//     sender_addr: SocketAddr,
//     mut receiver_stream: TcpStream,
//     receiver_addr: SocketAddr,
// ) {
//     let mut buffer = vec![0; 1024];
    
//     loop {
//         match sender_stream.read(&mut buffer).await {
//             Ok(0) => {
//                 println!("Sender {} disconnected", sender_addr);
//                 break;
//             },
//             Ok(n) => {
//                 let message = String::from_utf8_lossy(&buffer[..n]);
//                 println!("Received from {}: {}. Sending to {}", sender_addr, message, receiver_addr);

//                 // send message from sender to receiver
//                 if let Err(e) = receiver_stream.write_all(&buffer[..n]).await {
//                     eprintln!("Failed to write to receiver {}: {}", receiver_addr, e);
//                     break;
//                 }

//                 // echo success back to sender
//                 let echo_message = format!("Message delivered to {}", receiver_addr);
//                 if let Err(e) = sender_stream.write_all(echo_message.as_bytes()).await {
//                     eprintln!("Failed to write to sender {}: {}", sender_addr, e);
//                     break;
//                 }
//             },
//             Err(e) => {
//                 eprintln!("Error reading from sender {}: {}", sender_addr, e);
//                 break;
//             }
//         }
//     }
    
//     println!("Relay session ended for {} <-> {}", sender_addr, receiver_addr);
// }