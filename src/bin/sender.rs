use std::error::Error;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream};
use tokio::sync::Semaphore;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use distrans::networking::{Init, establish_connection};
use distrans::bytes::{chunk_file, generate_shared_key};
use std::path::Path;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    // Connect to the server
    // 100.86.70.21:8443 for relay pi
    let addr = "127.0.0.1:3000";

    let input = tokio::task::spawn_blocking(|| {
        println!("Enter filename to send:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).map(|_| input.trim().to_string())
        }).await?;

    let shared_key = generate_shared_key();
    println!("shared key: {}", shared_key);

    let filename = input?;

    if !Path::new(&filename).exists() {
        return Err(format!("File '{}' not found in current directory: {:?}", 
                        filename, std::env::current_dir()?).into());
    }

    let chunks = tokio::spawn(chunk_file(filename, 1024)).await?;

    // need to generate room, and PAKE encryption stuff here to send on initial connection to relay
    let init:Init = Init {is_sender: true, room: 0};
    let mut stream: TcpStream = establish_connection(addr, init).await?;

    let (mut read_half, mut write_half) = stream.into_split();

    // perform PAKE here - do i need PAKEMessage?

    // will also need to get file info - name and file size info - send in a transferInit Message

    // transferMessage - just contains the data we're sending (and optionally the chunk idx if we want to multithread in the future)
    
    tokio::spawn(read_task(read_half));
    tokio::spawn(write_task(write_half, chunks?)).await?;
    
    println!("Disconnecting.");
    Ok(())
}




async fn write_task(mut write_socket: OwnedWriteHalf, chunks: Vec<Vec<u8>>) {

    for chunk in chunks {
        println!("sending {:?} to receiver", chunk);
        let _ = write_socket.write_all(&chunk).await;
    }
    
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