use std::error::Error;
use std::io::Write;
use std::time::Duration;
use crate::cryptography::decrypt_chunk;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use crate::networking::{establish_connection, perform_pake, receive_message_metadata, read_chunk_size, read_encrypted_chunk};
use crate::utils::{Init, FileMetadata};
use crate::bytes::{create_file_bufwriter, get_shared_key, decompress_folder};
use crate::RELAY_ADDR;
use indicatif::ProgressBar;
use std::path::Path;
use log::{debug, info};

pub async fn run(key: Option<u32>) -> Result<(), Box<dyn Error>> {
    debug!("Starting receive command");
    
    // get 6-digit room number from user or CLI arg
    let shared_key = match key {
        Some(k) => {
            debug!("Using shared key from command line: {}", k);
            k
        }
        None => {
            info!("Prompting for shared key");
            get_shared_key()?
        }
    };

    debug!("Using shared key: {}, room: {}", shared_key, shared_key / 100);

    let init = Init {
        is_sender: false,
        room: shared_key / 100,
        local_addr: None
    };

    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner.set_message("Waiting to receive file");
    
    debug!("Connecting to relay server at {}", RELAY_ADDR);
    let stream: TcpStream = establish_connection(RELAY_ADDR, init).await?;

    let (read_half, write_half) = stream.into_split();

    debug!("Performing PAKE handshake");
    let (encryption_key, _write_half, read_half) =
        perform_pake(write_half, read_half, shared_key).await?;

    debug!("Receiving metadata");
    let (metadata, read_half) = receive_message_metadata(read_half).await?;
    debug!("Receiving {}: {} bytes", 
        if metadata.is_folder { "folder" } else { "file" },
        metadata.file_size
    );

    spinner.finish();
    // Start the pipeline: receive → decrypt → write/decompress
    let (tx, rx) = mpsc::channel::<Vec<u8>>(100);
    
    debug!("Spawning receive and decrypt task");
    let receive_handle = tokio::spawn(receive_and_decrypt_task(
        read_half,
        encryption_key,
        tx,
        metadata.file_size
    ));
    
    debug!("Spawning write task");
    let write_handle = if metadata.is_folder {
        debug!("Receiving folder: {}", metadata.filename);
        tokio::spawn(write_folder(rx, metadata))
    } else {
        tokio::spawn(write_file(rx, metadata))
    };
    
    // wait for both tasks to complete
    debug!("Waiting for tasks to complete");
    receive_handle.await?.map_err(|e| format!("Receive task error: {}", e))?;
    write_handle.await?.map_err(|e| format!("Write task error: {}", e))?;

    debug!("Receive completed successfully");
    Ok(())
}

// Task 1: Receive encrypted chunks from network, decrypt them, send to channel
async fn receive_and_decrypt_task(
    mut read_half: OwnedReadHalf,
    encryption_key: [u8; 32],
    tx: mpsc::Sender<Vec<u8>>,
    total_size: u64,
) -> Result<(), String> {
    debug!("Starting receive and decrypt task, total size: {} bytes", total_size);
    let bar = ProgressBar::new(total_size / 1024);
    let mut chunk_index: u64 = 0;
    
    loop {
        // Read chunk size
        let chunk_size = match read_chunk_size(&mut read_half).await? {
            Some(size) => {
                debug!("Received chunk {} size: {} bytes", chunk_index, size);
                size
            }
            None => {
                debug!("Reached EOF, total chunks received: {}", chunk_index);
                break;
            }
        };
        
        // Read encrypted chunk
        let encrypted_chunk = read_encrypted_chunk(&mut read_half, chunk_size).await?;
        debug!("Read encrypted chunk {}: {} bytes", chunk_index, encrypted_chunk.len());
        
        // Decrypt the chunk with index
        let decrypted_chunk = decrypt_chunk(&encryption_key, &encrypted_chunk, chunk_index)
            .map_err(|e| format!("Failed to decrypt chunk {}: {}", chunk_index, e))?;
        debug!("Decrypted chunk {}: {} bytes", chunk_index, decrypted_chunk.len());
        
        // Send to channel
        tx.send(decrypted_chunk).await.map_err(|e| e.to_string())?;
        
        bar.inc(1);
        chunk_index += 1;
    }
    
    bar.finish_with_message("Download complete!");
    Ok(())
}

// receive decrypted chunks and write to file
async fn write_file(
    mut rx: mpsc::Receiver<Vec<u8>>,
    metadata: FileMetadata,
) -> Result<(), String> {
    let output_filename = format!("new_{}", metadata.filename);
    debug!("Writing to file: {}", output_filename);
    let output_path = Path::new(&output_filename);
    
    let mut bufwriter = create_file_bufwriter(output_path);
    let mut total_bytes = 0;
    
    while let Some(chunk) = rx.recv().await {
        total_bytes += chunk.len();
        debug!("Writing chunk to file: {} bytes (total: {})", chunk.len(), total_bytes);
        bufwriter.write_all(&chunk).map_err(|e| e.to_string())?;
    }
    
    bufwriter.flush().map_err(|e| e.to_string())?;
    debug!("Flushed {} bytes to file", total_bytes);
    println!("File saved: {}", output_filename);
    Ok(())
}

// decompress folder
async fn write_folder(
    mut rx: mpsc::Receiver<Vec<u8>>,
    metadata: FileMetadata,
) -> Result<(), String> {
    debug!("Starting folder decompression");
    let mut zip_data = Vec::new();
    
    // collect all decrypted data
    while let Some(chunk) = rx.recv().await {
        debug!("Received chunk for folder: {} bytes", chunk.len());
        zip_data.extend_from_slice(&chunk);
    }

    debug!("Collected {} bytes of zip data", zip_data.len());

    // decompress the zip data
    let output_folder = format!("new_{}", metadata.filename);
    let output_path = Path::new(&output_folder);
    
    debug!("Decompressing folder to: {}", output_folder);
    decompress_folder(&zip_data, output_path)
        .map_err(|e| format!("Failed to decompress folder: {}", e))?;
    
    debug!("Folder extraction complete: {}", output_folder);
    Ok(())
}
