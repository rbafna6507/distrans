use std::error::Error;
use std::io::Write;
use std::time::Duration;
use crate::cryptography::decrypt_chunk;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use crate::networking::{establish_connection, perform_pake, read_chunk_size, read_encrypted_chunk, receive_message_metadata};
use crate::utils::{Init, FileMetadata};
use crate::bytes::{create_file_bufwriter, get_shared_key, decompress_folder};
use crate::RELAY_ADDR;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use log::{debug, info};

/// Function handler to kickoff receiver logic:
///     - Read input (shared 6 digit key)
///     - Establish connection with the relay (and attempt direct P2P connection with peer)
///     - Perform PAKE handshake to authenticate the sender
///     - Spawn an asynchronous task to read + decrypt incoming data chunks from TCP Socket
///     - Spawn an asynchronous task to construct/write folder/file - chunk by chunk as we read from TCP
pub async fn run(key: Option<u32>) -> Result<(), Box<dyn Error>> {
    debug!("Starting receive command");
    
    // Get 6-digit room number from user or CLI arg
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

    // Init message to send to the relay
    // Indicates is_sender status, desired room to join, and local ip address
    let init = Init {
        is_sender: false,
        room: shared_key / 100,
        local_addr: None
    };

    // Connect to relay server, and attempt to create a direct P2P connection with peer
    debug!("Connecting to relay server at {}", RELAY_ADDR);
    let stream: TcpStream = establish_connection(RELAY_ADDR, init).await?;
    let (read_socket, write_socket) = stream.into_split();
    
    // Indicate that we haven't received the file yet
    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner.set_message("Waiting to receive file");

    debug!("Performing PAKE handshake");
    let (encryption_key, _write_half, read_half) =
        perform_pake(write_socket, read_socket, shared_key).await?;

    debug!("Receiving metadata");
    let (metadata, read_half) = receive_message_metadata(read_half).await?;
    debug!("Receiving {}: {} bytes", 
        if metadata.is_folder { "folder" } else { "file" },
        metadata.file_size
    );

    spinner.finish_and_clear();
    // Channel for: receive + decrypt → (channel) → write/decompress
    let (send_channel, receive_channel) = mpsc::channel::<Vec<u8>>(100);
    
    // Spawn async task that reads from TCP socket, decrypts chunk, and 
    // sends to 'Write' Task to construct folder/file
    debug!("Spawning receive and decrypt task");
    let receive_handle = tokio::spawn(receive_and_decrypt_task(
        read_half,
        encryption_key,
        send_channel,
        metadata.file_size
    ));
    
    // Spawn async task that reads from channel to construct a file
    // or waits for all chunks to decompress a zip archive (into folder)
    debug!("Spawning write task");
    let write_handle = if metadata.is_folder {
        debug!("Receiving folder: {}", metadata.filename);
        tokio::spawn(write_folder(receive_channel, metadata))
    } else {
        tokio::spawn(write_file(receive_channel, metadata))
    };
    
    // Wait for both tasks to complete
    debug!("Waiting for tasks to complete");
    receive_handle.await?.map_err(|e| format!("Receive task error: {}", e))?;
    write_handle.await?.map_err(|e| format!("Write task error: {}", e))?;

    debug!("Receive completed successfully");
    Ok(())
}

/// Receives encrypted chunks from network, decrypts them, and sends to channel.
///
/// # Process
/// 1. Read chunk size from network (as u32, in bytes)
/// 2. Read encrypted chunk data
/// 3. Decrypt chunk using chunk_index as nonce
/// 4. Send decrypted chunk to write task via channel
/// 5. Repeat until EOF (chunk_size read returns None)
///
/// # Arguments
/// * `read_half` - TCP read half for receiving data
/// * `encryption_key` - The 32-byte decryption key from PAKE
/// * `tx` - Channel for sending decrypted chunks to write task
/// * `total_size` - Total file size in bytes (for progress bar)
async fn receive_and_decrypt_task(
    mut read_half: OwnedReadHalf,
    encryption_key: [u8; 32],
    tx: mpsc::Sender<Vec<u8>>,
    total_size: u64,
) -> Result<(), String> {
    debug!("Starting receive and decrypt task, total size: {} bytes", total_size);

    let bar = ProgressBar::new(total_size / 1024);
    bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.black} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} KB ({eta}) {msg}")
        .unwrap());
    bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.black} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} KB ({eta}) {msg}")
        .unwrap());
    let mut chunk_index: u64 = 0;
    
    // Read chunk_size from stream, then read chunk_size bytes from stream as a chunk
    // Decrypt the chunk using chunk_index as a decryption nonce
    // Send decrypted chunk to 'Write' task to construct file/folder
    loop {
        // Read chunk size (in bytes)
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
        
        // Decrypt the chunk with index as nonce
        let decrypted_chunk = decrypt_chunk(&encryption_key, &encrypted_chunk, chunk_index)
            .map_err(|e| format!("Failed to decrypt chunk {}: {}", chunk_index, e))?;
        debug!("Decrypted chunk {}: {} bytes", chunk_index, decrypted_chunk.len());
        
        // Send to channel to 'Write' task
        tx.send(decrypted_chunk).await.map_err(|e| e.to_string())?;
        
        bar.inc(1);
        chunk_index += 1;
    }
    
    bar.finish_with_message("Download complete!");
    Ok(())
}

/// Receives decrypted chunks from channel and writes them to a file.
///
/// # Process
/// 1. Create a new file with "new_" prefix
/// 2. Receive decrypted chunks from channel
/// 3. Write each chunk to file
/// 4. Flush buffer and close file
///
/// # Arguments
/// * `rx` - Channel for receiving decrypted chunks
/// * `metadata` - File metadata (filename, size)
async fn write_file(
    mut rx: mpsc::Receiver<Vec<u8>>,
    metadata: FileMetadata,
) -> Result<(), String> {
    let output_filename = format!("new_{}", metadata.filename);
    let output_path = Path::new(&output_filename);
    debug!("Writing to file: {}", output_filename);
    
    // Create a buffer writer to write file bytes into
    let mut bufwriter = create_file_bufwriter(output_path);
    let mut total_bytes = 0;
    
    // As we get decrypted chunks from previous task, write the chunks to the file
    while let Some(chunk) = rx.recv().await {
        total_bytes += chunk.len();
        debug!("Writing chunk to file: {} bytes (total: {})", chunk.len(), total_bytes);
        bufwriter.write_all(&chunk).map_err(|e| e.to_string())?;
    }
    
    // Clear buffer and save the file
    bufwriter.flush().map_err(|e| e.to_string())?;
    debug!("Flushed {} bytes to file", total_bytes);
    println!("File saved: {}", output_filename);
    Ok(())
}

/// Receives decrypted chunks, collects all of them, then decompresses the zip archive.
///
/// # Process
/// 1. Collect all decrypted chunks into a single buffer
/// 2. Once all chunks received, decompress the zip data
/// 3. Extract all files and directories to a new folder with "new_" prefix
///
/// # Arguments
/// * `rx` - Channel for receiving decrypted chunks
/// * `metadata` - Folder metadata (folder name, compressed size)
async fn write_folder(
    mut rx: mpsc::Receiver<Vec<u8>>,
    metadata: FileMetadata,
) -> Result<(), String> {
    debug!("Starting folder decompression");
    let mut zip_data = Vec::new();
    
    // Collect all decrypted data from read task
    while let Some(chunk) = rx.recv().await {
        debug!("Received chunk for folder: {} bytes", chunk.len());
        zip_data.extend_from_slice(&chunk);
    }

    debug!("Collected {} bytes of zip data", zip_data.len());

    // Create correctly named output directory
    let output_folder = format!("new_{}", metadata.filename);
    let output_path = Path::new(&output_folder);
    
    // Decompress folder contents into the output directory
    debug!("Decompressing folder to: {}", output_folder);
    decompress_folder(&zip_data, output_path)
        .map_err(|e| format!("Failed to decompress folder: {}", e))?;
    
    debug!("Folder extraction complete: {}", output_folder);
    Ok(())
}
