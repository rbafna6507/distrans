use std::error::Error;
use std::io::{Read, Cursor};
use std::fs::{File, metadata};
use std::path::Path;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug};

use crate::networking::{establish_connection, perform_pake, send_metadata};
use crate::utils::Init;
use crate::bytes::{generate_shared_key, compress_folder, generate_metadata, read_chunk};
use crate::cryptography::encrypt_chunk;
use crate::RELAY_ADDR;

// Type alias for a readable data source (zip archive or file)
type DataSource = Box<dyn Read + Send>;

/// Function handler to kickoff sender logic:
///     - Read input (filename path)
///     - Generate 6 digit key to share with the receiver
///     - Establish connection with the relay (and attempt direct P2P connection with peer)
///     - If sending a folder, compress it
///     - Spawn an async task to chunk and encrypt the data
///     - Spawn an async task to take chunked + encrypted data, and send it to the peer
pub async fn run(file_path: &str) -> Result<(), Box<dyn Error>> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(format!("Path does not exist: {}", file_path).into());
    }

    // Generates a six digit random key to share with the Receiver
    let shared_key = generate_shared_key();
    println!("Shared key (copied to clipboard): \x1b[4m\x1b[1m{}\x1b[0m", shared_key);

    // Init message to send to the relay
    // Indicates is_sender status, desired room to join, and local ip address
    let init = Init {
        is_sender: true,
        room: shared_key / 100,
        local_addr: None
    };
    
    // Connect to relay server, and attempt to create a direct P2P connection with peer
    debug!("Connecting to relay server at {}", RELAY_ADDR);
    let stream: TcpStream = establish_connection(RELAY_ADDR, init).await?;
    let (_read_socket, _write_socket) = stream.into_split();

    // Complete PAKE handshake to verify receiver is authenticated
    debug!("Performing PAKE handshake");
    let (encryption_key, write_socket, _read_socket) =
        perform_pake(_write_socket, _read_socket, shared_key).await?;
    
    let file_metadata = metadata(path)?;
    
    // If data to transfer is a folder:
        // Compress the folder (create a zip archive and add any subdirectories/files)
        // Generate metadata based on the compressed zip archive (size is in bytes)
    // else:
        // Open the folder and generate metadata (size is in bytes)
    let (data_source, file_metadata): (DataSource, _) = if file_metadata.is_dir() {
        debug!("Compressing folder: {}", file_path);
        let spinner = ProgressBar::new_spinner();
        spinner.enable_steady_tick(Duration::from_millis(100));
        spinner.set_message("Compressing Folder");

        let zip_data = compress_folder(path)?;
        let zip_size = zip_data.len() as u64; // Size in bytes
        
        let metadata = generate_metadata(file_path.to_string(), zip_size, true);
        spinner.finish_with_message("Folder Successfully Compressed");

        (Box::new(Cursor::new(zip_data)), metadata)
    } else {
        let file = File::open(file_path)?;
        let file_size = file.metadata()?.len();

        debug!("File size: {} bytes", file_size);
        let metadata = generate_metadata(file_path.to_string(), file_size, false);
        
        (Box::new(file), metadata)
    };
    
    // Inform the receiver of file metadata - name, size (in bytes), folder/file type
    debug!("Sending metadata");
    let write_socket = send_metadata(write_socket, &file_metadata).await?;

    // Channel for: chunk + encrypt → (channel) → send to peer
    let (write_channel, read_channel) = mpsc::channel::<Vec<u8>>(1024);
    
    // Spawns an async task that chunks and encrypts the data source,
    // then sends encrypted chunks through the write channel to the 'Send' task
    let chunk_handle = tokio::spawn(chunk_and_encrypt_task(
        data_source,
        encryption_key,
        write_channel,
        file_metadata.file_size
    ));
    
    // Spawns an async task that reads encrypted chunks from the read_channel as they appear
    // and sends them to the peer over TCP
    let send_handle = tokio::spawn(send_task(write_socket, read_channel));
    
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


/// Read data source (file or compressed folder), chunk it, encrypt it, send to channel
async fn chunk_and_encrypt_task(
    mut data_source: DataSource,
    key: [u8; 32],
    tx: mpsc::Sender<Vec<u8>>,
    total_size: u64,
) -> Result<(), String> {

    // Initialize a progress bar in this task as it indicates how much of the file we've processed
    // Initialize chunk_index to prepend to chunk as a nonce for encryption/decryption
    debug!("Starting chunk and encrypt task, total size: {} bytes", total_size);
    let bar = ProgressBar::new(total_size / 1024);
    bar.set_style(ProgressStyle::default_bar()
    .template("[{elapsed_precise}] [{bar:40.black}] {pos}/{len} KB ({eta}) {msg}")
    .unwrap());
    let mut chunk_index: u64 = 0;
    
    // For each chunk in the file, read it into a buffer of size ENCRYPTION_ADJUSTED_CHUNK_SIZE
    // Encrypt the chunk, and send it through the channel to the 'Send' Task
    loop {
        // Read chunk (size in bytes)
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
        
        // Send encrypted chunk to channel
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

/// Receive encrypted chunks from channel and send to peer over TCP
async fn send_task(
    mut write_socket: OwnedWriteHalf,
    mut rx: mpsc::Receiver<Vec<u8>>,
) -> Result<(), String>  {
    debug!("Starting send task");
    let mut chunk_count = 0;
    
    // Read chunk from the channel
    // Send size of incoming chunk to peer (in bytes, as u32)
    // Send chunk to peer (encrypted bytes)
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
        
        // Flush to ensure data is sent immediately (critical for relay connections)
        if let Err(e) = write_socket.flush().await {
            let error_msg = format!("Network error flushing chunk {}: {}. The receiver may have disconnected.", chunk_count, e);
            debug!("{}", error_msg);
            return Err(error_msg);
        }
        
        chunk_count += 1;
    }
    
    debug!("Sent {} chunks total", chunk_count);
    println!("Transfer Complete!");
    
    Ok(())
}