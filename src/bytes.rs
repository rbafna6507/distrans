use std::io::{self, Read, Write, BufWriter};
use std::error::Error;
use std::fs::{File, OpenOptions};
use crate::{NONCE_SIZE, CHUNK_SIZE, ENCRYPTION_OVERHEAD, ENCRYPTION_ADJUSTED_CHUNK_SIZE, cryptography::{encrypt_chunk}};
use crate::utils::{CliReceiver, CliSender};
use std::path::Path;
use clap::Parser;
use rand::Rng;
use arboard::Clipboard;


// needs compression
// and PAKE
// needs generate_phrase() function to help generate a room

pub fn generate_shared_key() -> u32 {
    let mut clipboard = Clipboard::new().unwrap();
    let mut rng = rand::rng();

    // Generate a random number between 100,000 (inclusive) and 999,999 (inclusive)
    let random_number: u32 = rng.random_range(100_000..=999_999);
    clipboard.set_text(random_number.to_string()).unwrap();
    random_number
}

pub fn get_shared_key() -> Result<u32, Box<dyn Error>> {
    let cli = CliReceiver::parse();
    Ok(cli.shared_key)
}

// pub async fn compress_chunk(chunk: &Vec<u8>) -> Vec<u8> {
//     zstd::encode_all(&chunk[..], 3).expect("Failed to compress chunk")
// }

// pub async fn decompress_chunk(chunk: &Vec<u8>) -> Vec<u8> {
//     zstd::decode_all(&chunk[..]).expect("Failed to decompress chunk")
// }


// folder logic
// similarly:
    // take in the folder path
    // initialize the zip folder (compresses any additions)
    // recursively traverse the folder
    // add file to folder

// 



// add file to folder
    // takes in


pub async fn chunk_file(file_path: String) -> io::Result<Vec<Vec<u8>>> {
    // println!("Attempting to read file: {}", file_path);
    let mut file = File::open(file_path)?;
    let mut chunks = Vec::new();

    loop {
        let mut buffer = vec![0; CHUNK_SIZE-ENCRYPTION_OVERHEAD]; // Create a buffer for the current chunk
        let bytes_read = file.read(&mut buffer)?; // Read bytes into the buffer

        if bytes_read == 0 {
            // End of file reached
            break;
        }

        // If fewer bytes were read than the chunk size, truncate the buffer
        buffer.truncate(bytes_read);
        chunks.push(buffer);
    }

    Ok(chunks)
}

pub fn create_file_bufwriter(output_path: &Path) -> BufWriter<File> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path).unwrap();

    BufWriter::new(file)
}


pub async fn reconstruct_file(chunks: Vec<Vec<u8>>, output_path: &Path) -> io::Result<()> {
    // Open the file for writing. `.create(true)` will create the file
    // if it does not exist.
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)?;

    let mut writer = BufWriter::new(file);

    for chunk in chunks {
        // Write each chunk to the writer
        writer.write_all(&chunk)?;
        // println!("Wrote a chunk of {} bytes.", chunk.len());
    }

    writer.flush()?;

    println!("File successfully reconstructed at {:?}", output_path);
    Ok(())
}

pub async fn add_chunk_to_file(mut writer: BufWriter<File>, chunk: &Vec<u8>) -> Result<BufWriter<File>, Box<dyn Error>> {
    writer.write_all(&chunk)?;
    Ok(writer)
}

pub async fn chunk_and_encrypt_file(file_path: &String, encryption_key: [u8; 32]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    let mut chunk_index: u64 = 0;

    let mut chunks: Vec<Vec<u8>> = Vec::new();

    loop {
        let mut buffer = vec![0; ENCRYPTION_ADJUSTED_CHUNK_SIZE]; 
        let bytes_read = file.read(&mut buffer).unwrap();

        if bytes_read == 0 {
            // End of file reached
            break;
        }

        // If fewer bytes were read than the chunk size, truncate the buffer
        buffer.truncate(bytes_read);

        // encrypt buffer
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[..8].copy_from_slice(&chunk_index.to_le_bytes());
        let encrypted = encrypt_chunk(&encryption_key, &buffer, &nonce_bytes).unwrap();

        chunks.push(encrypted);
        chunk_index += 1
    }

    Ok(chunks)
}


pub fn get_filename() -> Result<String, Box<dyn Error>> {
    let cli = CliSender::parse();
    Ok(cli.filename)

    // println!("Enter filename to send:");
    // let mut input = String::new();
    // input = std::io::stdin().read_line(&mut input).map(|_| input.trim().to_string())?;

    // if !Path::new(&input).exists() {
    //     return Err(format!("File '{}' not found in current directory: {:?}", 
    //                     input, std::env::current_dir()?).into());
    // }

    // Ok(input)
}

