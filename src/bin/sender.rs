use std::error::Error;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use distrans::networking::{Init, establish_connection};


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    // Connect to the server
    // 100.86.70.21:8443 for relay pi
    let addr = "127.0.0.1:3000";
    
    // need to generate room, and PAKE encryption stuff here to send on initial connection to relay
    let init:Init = Init {is_sender: true, room: 0};
    let mut stream: TcpStream = establish_connection(addr, init).await?;

    let (mut read_half, mut write_half) = stream.into_split();

    // need logic to 'generate' a random + secure room code
    // will also need to get file info - name and size to send during init
    
    let mut buffer = vec![0; 1024];

    tokio::spawn(read_task(read_half));
    tokio::spawn(write_task(write_half));

    loop {
        
    }

    println!("Disconnecting.");
    Ok(())
}



async fn read_task(mut read_socket: OwnedReadHalf) {

    loop {
        let mut buffer = vec![0; 1024];

        match read_socket.read(&mut buffer).await {
            Ok(0) => {
                println!("Server closed the connection.");
                return;
            },
            Ok(n) => {
                let received = String::from_utf8_lossy(&buffer[..n]);
                println!("Received: '{}'", received);
            },
            Err(e) => {
                eprintln!("Failed to read from server: {}", e);
                return;
            }
        }

    }
}

async fn write_task(mut write_socket: OwnedWriteHalf) {
    loop {
        
        let mut buffer = vec![0;1024];

        let input = tokio::task::spawn_blocking(|| {
            println!("Enter a message to send (or 'exit' to quit):");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).map(|_| input)
            }).await;


        match input {
            Ok(Ok(input)) => {
                let message = input.trim();
                if message == "exit" {
                    return;
                }
                if !message.is_empty() {
                    let _ = write_socket.write_all(message.as_bytes()).await;
                    println!("Sent: '{}'", message);
                }
            }
            _ => {
                eprintln!("Failed to read user input");
            }
        }
    }
    
}