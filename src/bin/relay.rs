use tokio::net::{TcpListener};
use tokio::sync::mpsc::{self};
use std::error::Error;
use distrans::relay_utils::{ConnectionManager, Message, relay_manager, relay_new_connection};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("Server listening on 0.0.0.0:8080");

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
