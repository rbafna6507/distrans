use std::error::Error;
use std::io::{Read, Cursor};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use crate::networking::{establish_connection, perform_pake, send_metadata};
use crate::utils::Init;
use crate::bytes::{generate_shared_key, compress_folder, generate_metadata, read_chunk};
use crate::cryptography::encrypt_chunk;
use indicatif::ProgressBar;
use std::fs::{File, metadata};
use std::path::Path;
use tokio::time::Duration;
use log::{debug};

use crate::RELAY_ADDR;

// Type alias for any readable data source
type DataSource = Box<dyn Read + Send>;

pub async fn run(file_path: &str) -> Result<(), Box<dyn Error>> {
    debug!("Starting send command for path: {}", file_path);
    
    let path = Path::new(file_path);
    
    if !path.exists() {
        return Err(format!("Path does not exist: {}", file_path).into());
    }

    let shared_key = generate_shared_key();
    println!("shared key (copied to clipboard): {}", shared_key);
    debug!("Generated shared key: {}, room: {}", shared_key, shared_key / 100);

    let init = Init {
        is_sender: true,
        room: shared_key / 100,
        local_addr: None
    };
    
    debug!("Connecting to relay server at {}", RELAY_ADDR);
    let stream: TcpStream = establish_connection(RELAY_ADDR, init).await?;
    let (read_channel, write_channel) = stream.into_split();

    debug!("Performing PAKE handshake");
    let (encryption_key, write_half, _read_half) =
        perform_pake(write_channel, read_channel, shared_key).await?;
    
    let file_metadata = metadata(path)?;
    
    // prepare data source (file or compressed folder)
    let (data_source, file_metadata): (DataSource, _) = if file_metadata.is_dir() {
        debug!("Compressing folder: {}", file_path);
        debug!("Starting folder compression");
        let spinner = ProgressBar::new_spinner();
        spinner.enable_steady_tick(Duration::from_millis(100));
        spinner.set_message("Compressing Folder");
        let zip_data = compress_folder(path)?;
        let zip_size = zip_data.len() as u64;
        debug!("Folder compressed to {} bytes", zip_size);
        let metadata = generate_metadata(file_path.to_string(), zip_size, true);
        spinner.finish_with_message("Folder Successfully Compressed");
        (Box::new(Cursor::new(zip_data)), metadata)
    } else {
        debug!("Opening file: {}", file_path);
        let file = File::open(file_path)?;
        let file_size = file.metadata()?.len();
        debug!("File size: {} bytes", file_size);
        let metadata = generate_metadata(file_path.to_string(), file_size, false);
        (Box::new(file), metadata)
    };
    
    debug!("Sending metadata");
    let write_channel = send_metadata(write_half, &file_metadata).await?;

    // initialize send/receive channel
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
    
    debug!("Spawning chunk and encrypt task");
    let chunk_handle = tokio::spawn(chunk_and_encrypt_task(
        data_source,
        encryption_key,
        tx,
        file_metadata.file_size
    ));
    
    debug!("Spawning send task");
    let send_handle = tokio::spawn(send_task(write_channel, rx));
    
    // wait for both tasks to complete
    debug!("Waiting for tasks to complete");
    
    // Wait for send task first - if network fails, we know immediately
    let send_result = send_handle.await?;
    if let Err(e) = send_result {
        debug!("Send task failed: {}", e);
        // Send task failed, chunk task will error when trying to send
        let _ = chunk_handle.await; // Don't propagate chunk error, send error is the real issue
        return Err(format!("Network error: {}", e).into());
    }
    
    // Now wait for chunk task
    chunk_handle.await?.map_err(|e| format!("Chunk task error: {}", e))?;

    debug!("Transfer completed successfully");
    Ok(())
}

// Task 1: Read data, chunk it, encrypt it, send to channel
async fn chunk_and_encrypt_task(
    mut data_source: DataSource,
    key: [u8; 32],
    tx: mpsc::Sender<Vec<u8>>,
    total_size: u64,
) -> Result<(), String> {
    debug!("Starting chunk and encrypt task, total size: {} bytes", total_size);
    let bar = ProgressBar::new(total_size / 1024);
    let mut chunk_index: u64 = 0;
    
    loop {
        // Read chunk
        let (buffer, bytes_read) = read_chunk(&mut data_source).map_err(|e| e.to_string())?;
        
        if bytes_read == 0 {
            debug!("Finished reading all chunks, total chunks: {}", chunk_index);
            break;
        }
        
        debug!("Read chunk {}: {} bytes", chunk_index, bytes_read);
        
        // Encrypt chunk with index
        let encrypted = encrypt_chunk(&key, &buffer, chunk_index)
            .map_err(|e| format!("Encryption error: {:?}", e))?;
        
        debug!("Encrypted chunk {}: {} bytes", chunk_index, encrypted.len());
        
        // Send to channel
        if let Err(_) = tx.send(encrypted).await {
            let error_msg = format!("Failed to send chunk {} to network task (channel closed). This usually means the network connection was lost.", chunk_index);
            debug!("{}", error_msg);
            return Err(error_msg);
        }
        
        chunk_index += 1;
        bar.inc(1);
    }
    
    bar.finish_with_message("Processing complete!");
    Ok(())
}

// Task 2: Receive encrypted chunks from channel and send over network
async fn send_task(
    mut write_socket: OwnedWriteHalf,
    mut rx: mpsc::Receiver<Vec<u8>>,
) -> Result<(), String> {
    debug!("Starting send task");
    let mut chunk_count = 0;
    
    while let Some(encrypted_chunk) = rx.recv().await {
        let chunk_size = encrypted_chunk.len() as u32;
        debug!("Sending chunk {}: {} bytes", chunk_count, chunk_size);
        
        // Try to write chunk size
        if let Err(e) = write_socket.write_u32(chunk_size).await {
            let error_msg = format!("Network error writing chunk {} size: {}. The receiver may have disconnected.", chunk_count, e);
            debug!("{}", error_msg);
            return Err(error_msg);
        }
        
        // Try to write chunk data
        if let Err(e) = write_socket.write_all(&encrypted_chunk).await {
            let error_msg = format!("Network error writing chunk {} data: {}. The receiver may have disconnected.", chunk_count, e);
            debug!("{}", error_msg);
            return Err(error_msg);
        }
        
        chunk_count += 1;
    }
    
    debug!("Sent {} chunks total", chunk_count);
    println!("Transfer Complete!");
    Ok(())
}
