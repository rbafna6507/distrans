use std::error::Error;
use tokio::net::{TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use distrans::networking::{establish_connection};

#[derive(Serialize, Deserialize, Debug)]
struct Init{
    is_sender: bool,
    room: u32
    // other relevant file data eventually
    // like pake password hash
    // file metadata - name, size, etc
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    // Connect to the server
    // 100.86.70.21:8443 for relay pi
    let addr = "127.0.0.1:3000";
    let mut stream: TcpStream = establish_connection(addr).await?;
    
    let mut buffer = vec![0; 1024];
    
    loop {
        println!("Enter a message to send (or 'exit' to quit):");
        
        tokio::select! {
            // Handle incoming data from the stream
            result = stream.read(&mut buffer) => {
                match result {
                    Ok(0) => {
                        println!("Server closed the connection.");
                        break;
                    },
                    Ok(n) => {
                        let received = String::from_utf8_lossy(&buffer[..n]);
                        println!("Received: '{}'", received);
                    },
                    Err(e) => {
                        eprintln!("Failed to read from server: {}", e);
                        break;
                    }
                }
            }
            
            // Handle user input for sending
            result = tokio::task::spawn_blocking(|| {
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).map(|_| input)
            }) => {
                match result {
                    Ok(Ok(input)) => {
                        let message = input.trim();
                        if message == "exit" {
                            break;
                        }
                        if !message.is_empty() {
                            stream.write_all(message.as_bytes()).await?;
                            println!("Sent: '{}'", message);
                        }
                    }
                    _ => {
                        eprintln!("Failed to read user input");
                        break;
                    }
                }
            }
        }
    }

    println!("Disconnecting.");
    Ok(())
}