use tokio::net::TcpListener;
use tokio::sync::mpsc;
use std::error::Error;
use crate::relay_utils::{ConnectionManager, Message, relay_manager, relay_new_connection};
use log::{debug, info};

pub async fn run(port: u16) -> Result<(), Box<dyn Error>> {
    let bind_addr = format!("0.0.0.0:{}", port);
    debug!("Attempting to bind to {}", bind_addr);
    
    let listener = TcpListener::bind(&bind_addr).await?;
    println!("Server listening on {}", bind_addr);
    info!("Relay server started on {}", bind_addr);

    let (sender_channel, receiver_channel) = mpsc::channel::<Message>(100);
    let manager = ConnectionManager::new(sender_channel.clone(), receiver_channel);
    
    debug!("Spawning relay manager task");
    tokio::spawn(relay_manager(manager));

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("client connected: {}", addr);
        info!("New client connection from: {}", addr);

        debug!("Spawning relay connection handler for {}", addr);
        tokio::spawn(relay_new_connection(stream, addr, sender_channel.clone()));
    }
}
