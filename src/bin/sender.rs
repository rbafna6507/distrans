use std::error::Error;
use std::io::Read;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream};
use tokio::sync::Semaphore;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use distrans::networking::{Init, establish_connection, perform_pake};
use distrans::bytes::{chunk_file, generate_shared_key, compress_chunk};
use distrans::cryptography::{encrypt_chunk, NONCE_SIZE};
use std::path::Path;
use std::fs::{self, File};

const CHUNK_SIZE: usize = 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    // Connect to the server
    // 100.86.70.21:8443 for relay pi

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

    // let chunks = tokio::spawn(chunk_file(filename, 1024)).await?;

    let init:Init = Init {is_sender: true, room: 0};
    let addr = "127.0.0.1:3000";
    let mut stream: TcpStream = establish_connection(addr, init).await?;

    let (mut read_half, mut write_half) = stream.into_split();

    // perform PAKE here - do i need PAKEMessage?
    // pake function
    let (encryption_key, write_half, read_half) =
        perform_pake(write_half, read_half, shared_key).await?;

    // will also need to get file info - name and file size info - send in a transferInit Message
    // init transfer message - metadata of file: filename, size, etc

    // transferMessage - just contains the data we're sending (and optionally the chunk idx if we want to multithread in the future)
    // file chunk message
    
    // read task should:
    // receive an ack
    // verify the idx and success of the ack
    // allow the write task to continue sending chunks
    tokio::spawn(read_task(read_half));

    // write task should:
    // iterate over file (for chunk in file)
    // compress the chunk
    // encrypt the chunk
    // package? chunk + the ?expected hash? + chunk_id in a FileChunkMessage struct
    // write the FileChunkMessage
    // wait for an ack with the same chunk id
    // tokio::spawn(write_task(write_half, chunks?)).await?;
    let mut file = File::open(filename).unwrap();
    tokio::spawn(new_write_task(write_half, file, encryption_key)).await?;
    
    println!("Disconnecting.");
    Ok(())
}


async fn write_task(mut write_socket: OwnedWriteHalf, chunks: Vec<Vec<u8>>) {

    for chunk in chunks {
        println!("sending {:?} to receiver", chunk);
        let _ = write_socket.write_all(&chunk).await;
    }
    
}

async fn new_write_task(mut write_socket: OwnedWriteHalf, mut file: File, key:[u8; 32]) {
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

        let _ = write_socket.write_all(&encrypted).await;
        println!("sending {:?} bytes to receiver", encrypted.len());

        chunk_index += 1
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