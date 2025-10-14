use std::error::Error;
use std::vec;
use bincode::de::read;
use distrans::cryptography::{decrypt_chunk, NONCE_SIZE, EncryptionError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use distrans::networking::{establish_connection, perform_pake, Init};
use distrans::bytes::{get_shared_key, reconstruct_file};
use std::path::Path;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to the server
    // 100.86.70.21:8443 for relay pi
    let addr = "127.0.0.1:3000";
    
    // Get 6-digit room number from user
    let shared_key = get_shared_key();

    let init:Init = Init {is_sender: false, room: 0};
    let mut stream: TcpStream = establish_connection(addr, init).await?;
    let (mut read_half, mut write_half) = stream.into_split();

    // note: need to do PAKE shit here - make the channel we communicte through secure
    let (encryption_key, mut write_half, mut read_half) =
        perform_pake(write_half, read_half, shared_key).await?;


    // loop where we continually recieve data + send acks/verification messages
    // note: maybe spawn this as an async tokio task? any benefit to doing that on the reciever?

    let file = tokio::spawn(read_task(read_half, encryption_key)).await?.unwrap();

    let output_path: &Path = Path::new("pic.jpg");
    if let Err(e) = reconstruct_file(file, output_path).await {
        eprintln!("Failed to reconstruct file: {}", e);
    } else {
        println!("File successfully reconstructed.");
    }

    println!("Disconnecting.");
    Ok(())
}


async fn read_task(mut read_half: OwnedReadHalf, encryption_key:[u8; 32]) -> Result<Vec<Vec<u8>>, EncryptionError> {
    let mut file: Vec<Vec<u8>> = Vec::new();
    let mut chunk_index: u64 = 0;

    loop {

        let mut buffer = vec![0; 1024];

        // Read the server's echo
        match read_half.read(&mut buffer).await {
            Ok(0) => {
                // Connection closed by the server
                println!("Server closed the connection.");
                break;
            },
            Ok(n) => {
                println!("received {} bytes from sender", n);
                buffer.truncate(n);

                // Generate the nonce for this chunk
                let mut nonce_bytes = [0u8; NONCE_SIZE];
                nonce_bytes[..8].copy_from_slice(&chunk_index.to_le_bytes());

                // Decrypt the chunk
                let decrypted_chunk = match decrypt_chunk(&encryption_key, &buffer, &nonce_bytes) {
                    Ok(chunk) => chunk,
                    Err(e) => {
                        eprintln!("Failed to decrypt chunk {}: {}", chunk_index, e);
                        return Err(e);
                    }
                };

                file.push(decrypted_chunk);
                chunk_index += 1;

            },
            Err(e) => {
                eprintln!("Failed to read from server: {}", e);
            }
        }
    }
    Ok(file)
}