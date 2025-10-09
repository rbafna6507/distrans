use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Server listening on 127.0.0.1:8080");

    loop {
        // first connection is always sender
        let (stream1, addr1) = listener.accept().await?;
        println!("First client connected: {}", addr1);

        // second connection is always receiver
        let (stream2, addr2) = listener.accept().await?;
        println!("Second client connected: {}", addr2);

        // task to send content from sender to receiver
        tokio::spawn(handle_relay(stream1, addr1, stream2, addr2));
    }
}

async fn handle_relay(
    mut sender_stream: TcpStream,
    sender_addr: SocketAddr,
    mut receiver_stream: TcpStream,
    receiver_addr: SocketAddr,
) {
    let mut buffer = vec![0; 1024];
    
    loop {
        match sender_stream.read(&mut buffer).await {
            Ok(0) => {
                println!("Sender {} disconnected", sender_addr);
                break;
            },
            Ok(n) => {
                let message = String::from_utf8_lossy(&buffer[..n]);
                println!("Received from {}: {}. Sending to {}", sender_addr, message, receiver_addr);

                // send message from sender to receiver
                if let Err(e) = receiver_stream.write_all(&buffer[..n]).await {
                    eprintln!("Failed to write to receiver {}: {}", receiver_addr, e);
                    break;
                }

                // echo success back to sender
                let echo_message = format!("Message delivered to {}", receiver_addr);
                if let Err(e) = sender_stream.write_all(echo_message.as_bytes()).await {
                    eprintln!("Failed to write to sender {}: {}", sender_addr, e);
                    break;
                }
            },
            Err(e) => {
                eprintln!("Error reading from sender {}: {}", sender_addr, e);
                break;
            }
        }
    }
    
    println!("Relay session ended for {} <-> {}", sender_addr, receiver_addr);
}