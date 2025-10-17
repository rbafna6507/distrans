use std::error::Error;
use std::io::{Read, Cursor};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpStream};
use tokio::io::{AsyncWriteExt};
use distrans::networking::{establish_connection, perform_pake, send_message_metadata};
use distrans::utils::{Init};
use distrans::bytes::{generate_shared_key, get_filename, compress_folder};
use distrans::cryptography::{encrypt_chunk};
use indicatif::{ProgressBar};
use std::fs::{File, metadata};
use std::path::Path;

use distrans::{CHUNK_SIZE, NONCE_SIZE, RELAY_ADDR};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let path_str = get_filename()?;
    let path = Path::new(&path_str);

    let shared_key = generate_shared_key();
    println!("shared key (copied to clipboard): {}", shared_key);

    let init:Init = Init {is_sender: true, room: shared_key / 100, local_addr: None};
    let stream: TcpStream = establish_connection(RELAY_ADDR, init).await?;
    let (read_half, write_half) = stream.into_split();

    // perform pake handshake with the generated key
    // this will exchange some messages with the receiver
    let (encryption_key, write_half, _read_half) =
        perform_pake(write_half, read_half, shared_key).await?;
    
    let meta = metadata(path)?;
    
    if meta.is_dir() {
        // Handle folder: compress it first
        println!("Compressing folder: {}", path_str);
        let zip_data = compress_folder(path)?;
        
        // Create a cursor to read from the zip data
        let cursor = Cursor::new(zip_data);
        let zip_size = cursor.get_ref().len() as u64;
        
        // Send metadata indicating this is a folder
        let (write_half, _metadata) = send_folder_metadata(write_half, path_str.clone(), zip_size).await?;
        
        // Send the compressed folder data
        tokio::spawn(send_data_from_cursor(write_half, cursor, encryption_key)).await?;
    } else {
        // Handle regular file
        let file = File::open(&path_str)?;
        let (write_half, _metadata) = send_message_metadata(write_half, path_str.clone(), &file).await?;
        
        // chunk and encrypt the file as we go
        tokio::spawn(new_write_task(write_half, file, encryption_key)).await?;
    }

    Ok(())
}


// sends folder meta data
async fn send_folder_metadata(
    mut write_half: OwnedWriteHalf,
    filename: String,
    zip_size: u64,
) -> Result<(OwnedWriteHalf, distrans::utils::FileMetadata), Box<dyn Error>> {
    use distrans::utils::FileMetadata;
    
    let metadata = FileMetadata {
        filename,
        file_size: zip_size,
        is_folder: true,
    };
    
    let encoded_metadata: Vec<u8> = bincode::serialize(&metadata)?;
    write_half.write_all(&encoded_metadata).await?;
    
    Ok((write_half, metadata))
}

// Helper function to send data from a cursor (for compressed folders)
async fn send_data_from_cursor(mut write_socket: OwnedWriteHalf, mut cursor: Cursor<Vec<u8>>, key:[u8; 32]) {
    let total_size = cursor.get_ref().len() as u64;
    let bar = ProgressBar::new(total_size / 1024);
    
    let mut chunk_index: u64 = 0;
    
    const ENCRYPTION_OVERHEAD: usize = 16;
    const PLAINTEXT_CHUNK_SIZE: usize = CHUNK_SIZE - ENCRYPTION_OVERHEAD;
    
    loop {
        let mut buffer = vec![0; PLAINTEXT_CHUNK_SIZE];
        let bytes_read = cursor.read(&mut buffer).unwrap();
        
        if bytes_read == 0 {
            break;
        }
        
        buffer.truncate(bytes_read);
        
        // encrypt buffer
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[..8].copy_from_slice(&chunk_index.to_le_bytes());
        let encrypted = encrypt_chunk(&key, &buffer, &nonce_bytes).unwrap();
        
        // Send chunk size first (as u32), then the encrypted data
        let chunk_size = encrypted.len() as u32;
        let _ = write_socket.write_u32(chunk_size).await;
        let _ = write_socket.write_all(&encrypted).await;
        
        chunk_index += 1;
        bar.inc(1);
    }
    bar.finish_with_message("Transfer Complete!");
}

// new write task is standalone: chunk, encrypt, send for each chunk of data.
async fn new_write_task(mut write_socket: OwnedWriteHalf, mut file: File, key:[u8; 32]) {
    let meta = file.metadata().unwrap();
    let bar = ProgressBar::new(meta.len()/1024);
    // bar.enable_steady_tick(Duration::from_millis(100));

    let mut chunk_index: u64 = 0;

    const ENCRYPTION_OVERHEAD: usize = 16;
    const PLAINTEXT_CHUNK_SIZE: usize = CHUNK_SIZE - ENCRYPTION_OVERHEAD;

    loop {
        let mut buffer = vec![0; PLAINTEXT_CHUNK_SIZE]; 
        let bytes_read = file.read(&mut buffer).unwrap();

        if bytes_read == 0 {
            // End of file reached
            break;
        }

        // If fewer bytes were read than the chunk size, truncate the buffer
        buffer.truncate(bytes_read);

        // compress buffer
        // let compressed = compress_chunk(&buffer).await;

        // encrypt buffer
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[..8].copy_from_slice(&chunk_index.to_le_bytes());
        let encrypted = encrypt_chunk(&key, &buffer, &nonce_bytes).unwrap();

        // Send chunk size first (as u32), then the encrypted data
        let chunk_size = encrypted.len() as u32;
        let _ = write_socket.write_u32(chunk_size).await;
        let _ = write_socket.write_all(&encrypted).await;

        chunk_index += 1;
        bar.inc(1);
    }
    bar.finish_with_message("Transfer Complete!");
    
}