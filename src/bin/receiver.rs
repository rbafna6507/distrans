use std::error::Error;
use std::vec;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use distrans::networking::{Init, establish_connection};
use distrans::bytes::{get_shared_key, reconstruct_file};
use std::path::Path;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to the server
    // 100.86.70.21:8443 for relay pi
    let addr = "127.0.0.1:3000";
    
    // Get 6-digit room number from user
    let room_number = get_shared_key();

    let init:Init = Init {is_sender: false, room: 0};
    let mut stream: TcpStream = establish_connection(addr, init).await?;

    // note: need to do PAKE shit here - make the channel we communicte through secure

    // loop where we continually recieve data + send acks/verification messages
    // note: maybe spawn this as an async tokio task? any benefit to doing that on the reciever?
    let mut file: Vec<Vec<u8>> = Vec::new();
    loop {

        let mut buffer = vec![0; 1024];
        println!("back here");
        // Read the server's echo
        match stream.read(&mut buffer).await {
            Ok(0) => {
                // Connection closed by the server
                println!("Server closed the connection.");
                break;
            },
            Ok(n) => {
                println!("received {} bytes from sender", n);
                buffer.truncate(n);
                file.push(buffer);

            },
            Err(e) => {
                eprintln!("Failed to read from server: {}", e);
                break;
            }
        }
    }

    let output_path: &Path = Path::new("transferred.txt");
    if let Err(e) = reconstruct_file(file, output_path).await {
        eprintln!("Failed to reconstruct file: {}", e);
    } else {
        println!("File successfully reconstructed.");
    }

    println!("Disconnecting.");
    Ok(())
}