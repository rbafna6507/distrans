use std::error::Error;
use std::vec;
use distrans::cryptography::{decrypt_chunk, EncryptionError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use distrans::networking::{establish_connection, perform_pake, Init};
use distrans::bytes::{get_shared_key, reconstruct_file};
use distrans::{RELAY_ADDR, NONCE_SIZE};
use std::path::Path;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get 6-digit room number from user
    let shared_key = get_shared_key();

    let init:Init = Init {is_sender: false, room: 0, local_addr: None};
    let stream: TcpStream = establish_connection(RELAY_ADDR, init).await?;

    let (mut read_half, mut write_half) = stream.into_split();


    let (encryption_key, mut write_half, mut read_half) =
        perform_pake(write_half, read_half, shared_key).await?;


    let file = tokio::spawn(read_task(read_half, encryption_key)).await?.unwrap();

    let output_path: &Path = Path::new("new_hap.txt");
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
        // First, read the chunk size (u32)
        let chunk_size = match read_half.read_u32().await {
            Ok(size) => size as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Connection closed by the sender
                println!("Sender closed the connection.");
                break;
            },
            Err(e) => {
                eprintln!("Failed to read chunk size: {}", e);
                break;
            }
        };

        // Now read exactly chunk_size bytes
        let mut buffer = vec![0; chunk_size];
        match read_half.read_exact(&mut buffer).await {
            Ok(_) => {
                println!("received {} bytes from sender", chunk_size);

                // let decompressed = decompress_chunk(&buffer).await;

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
                eprintln!("Failed to read chunk data: {}", e);
                break;
            }
        }
    }
    Ok(file)
}