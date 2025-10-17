use std::error::Error;
use std::vec;
use distrans::cryptography::{decrypt_chunk, EncryptionError};
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use distrans::networking::{establish_connection, perform_pake, receive_message_metadata};
use distrans::utils::{Init, FileMetadata};
use distrans::bytes::{add_chunk_to_file, create_file_bufwriter, get_shared_key, decompress_folder};
use distrans::{RELAY_ADDR, NONCE_SIZE};
use indicatif::ProgressBar;
use std::path::Path;



#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get 6-digit room number from user
    let shared_key = get_shared_key()?;

    let init:Init = Init {is_sender: false, room: shared_key / 100, local_addr: None};
    let stream: TcpStream = establish_connection(RELAY_ADDR, init).await?;

    let (read_half, write_half) = stream.into_split();

    let (encryption_key, _write_half, read_half) =
        perform_pake(write_half, read_half, shared_key).await?;

    let (metadata, read_half) = receive_message_metadata(read_half).await?;

    if metadata.is_folder {
        // Handle folder: receive compressed data, decrypt, then decompress
        println!("Receiving folder: {}", metadata.filename);
        tokio::spawn(read_folder_task(read_half, encryption_key, metadata))
            .await?
            .map_err(|e| format!("Folder receive error: {}", e))?;
    } else {
        // Handle regular file
        let _file: Vec<Vec<u8>> = tokio::spawn(read_task(read_half, encryption_key, metadata)).await?.unwrap();
    }

    Ok(())
}


async fn read_folder_task(
    mut read_half: OwnedReadHalf,
    encryption_key: [u8; 32],
    metadata: FileMetadata,
) -> Result<(), String> {
    let bar = ProgressBar::new(metadata.file_size / 1024);
    
    let mut zip_data = Vec::new();
    let mut chunk_index: u64 = 0;
    
    loop {
        let chunk_size = match read_half.read_u32().await {
            Ok(size) => size as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            },
            Err(e) => {
                eprintln!("Failed to read chunk size: {}", e);
                break;
            }
        };
        
        let mut buffer = vec![0; chunk_size];
        match read_half.read_exact(&mut buffer).await {
            Ok(_) => {
                // Generate the nonce for this chunk
                let mut nonce_bytes = [0u8; NONCE_SIZE];
                nonce_bytes[..8].copy_from_slice(&chunk_index.to_le_bytes());
                
                // decrypt the chunk
                let decrypted_chunk = match decrypt_chunk(&encryption_key, &buffer, &nonce_bytes) {
                    Ok(chunk) => chunk,
                    Err(e) => {
                        let err_msg = format!("Failed to decrypt chunk {}: {}", chunk_index, e);
                        eprintln!("{}", err_msg);
                        return Err(err_msg);
                    }
                };
                
                // append decrypted chunk to our buffer
                zip_data.extend_from_slice(&decrypted_chunk);
                
                bar.inc(1);
                chunk_index += 1;
            },
            Err(e) => {
                eprintln!("Failed to read chunk data: {}", e);
                break;
            }
        }
    }
    
    bar.finish_with_message("Download complete, extracting...");
    
    // decompress the zip data
    let output_folder = format!("new_{}", metadata.filename);
    let output_path = Path::new(&output_folder);
    
    decompress_folder(&zip_data, output_path)
        .map_err(|e| format!("Failed to decompress folder: {}", e))?;
    
    println!("Folder extraction complete: {}", output_folder);
    Ok(())
}

async fn read_task(mut read_half: OwnedReadHalf, encryption_key:[u8; 32], metadata: FileMetadata) -> Result<Vec<Vec<u8>>, EncryptionError> {
    let output_filename = format!("new_{}", metadata.filename);
    let output_path: &Path = Path::new(&output_filename);

    let bar = ProgressBar::new(metadata.file_size / 1024);


    let mut file: Vec<Vec<u8>> = Vec::new();
    let mut chunk_index: u64 = 0;

    let mut bufwriter = create_file_bufwriter(output_path);

    loop {
        // read chunk_size
        let chunk_size = match read_half.read_u32().await {
            Ok(size) => size as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Connection closed by the sender
                // println!("Sender closed the connection.");
                break;
            },
            Err(e) => {
                eprintln!("Failed to read chunk size: {}", e);
                break;
            }
        };

        // read exactly chunk size bits - decrypt them
        let mut buffer = vec![0; chunk_size];
        match read_half.read_exact(&mut buffer).await {
            Ok(_n) => {
                // println!("received {} bytes from sender", chunk_size);

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

                bufwriter = add_chunk_to_file(bufwriter, &decrypted_chunk).await.unwrap();
                
                file.push(decrypted_chunk);

                bar.inc(1);
                chunk_index += 1;
            },
            Err(e) => {
                eprintln!("Failed to read chunk data: {}", e);
                break;
            }
        }
    }
    bar.finish_with_message("Done!");
    Ok(file)
}