use std::error::Error;
use std::io::Read;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use distrans::networking::{establish_connection, perform_pake, send_message_metadata};
use distrans::utils::{Init};
use distrans::bytes::{chunk_and_encrypt_file, chunk_file, generate_shared_key, get_filename};
use distrans::cryptography::{encrypt_chunk};
use indicatif::{ProgressBar};
use std::fs::{File};

use distrans::{CHUNK_SIZE, NONCE_SIZE, RELAY_ADDR};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let filename = get_filename()?;

    let shared_key = generate_shared_key();
    println!("shared key (copied to clipboard): {}", shared_key);

    let init:Init = Init {is_sender: true, room: shared_key / 100, local_addr: None};
    let mut stream: TcpStream = establish_connection(RELAY_ADDR, init).await?;
    let (mut read_half, mut write_half) = stream.into_split();

    // perform pake handshake with the generated key
    // this will exchange some messages with the receiver
    let (encryption_key, write_half, read_half) =
        perform_pake(write_half, read_half, shared_key).await?;
    
    let mut file = File::open(&filename).unwrap();
    let (write_half, metadata) = send_message_metadata(write_half, filename.clone(), &file).await?;

    // chunk and encrypt the file as we go
    tokio::spawn(new_write_task(write_half, file, encryption_key)).await?;

    Ok(())
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
        // println!("sending {:?} bytes to receiver", encrypted.len());

        chunk_index += 1;
        bar.inc(1);
    }
    bar.finish_with_message("Transfer Complete!");
    
}