use std::io::{self, Read, Write, BufWriter};
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use crate::{NONCE_SIZE, CHUNK_SIZE, ENCRYPTION_OVERHEAD, cryptography::{encrypt_chunk}};
use std::path::Path;
use rand::Rng;

// needs compression
// and PAKE
// needs generate_phrase() function to help generate a room

pub fn generate_shared_key() -> u32 {
    let mut rng = rand::rng();

    // Generate a random number between 100,000 (inclusive) and 999,999 (inclusive)
    let random_number: u32 = rng.random_range(100_000..=999_999);
    random_number
}

pub fn get_shared_key() -> u32 {
    loop {
        println!("Enter 6-digit room number:");
        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(_) => {
                let trimmed = input.trim();
                if trimmed.len() == 6 && trimmed.chars().all(|c| c.is_ascii_digit()) {
                    match trimmed.parse::<u32>() {
                        Ok(num) => return num,
                        Err(_) => println!("Please enter a valid 6-digit number."),
                    }
                } else {
                    println!("Please enter exactly 6 digits.");
                }
            }
            Err(e) => {
                eprintln!("Failed to read input: {}", e);
                println!("Please try again.");
            }
        }
    };
}

// pub async fn compress_chunk(chunk: &Vec<u8>) -> Vec<u8> {
//     zstd::encode_all(&chunk[..], 3).expect("Failed to compress chunk")
// }

// pub async fn decompress_chunk(chunk: &Vec<u8>) -> Vec<u8> {
//     zstd::decode_all(&chunk[..]).expect("Failed to decompress chunk")
// }


pub async fn chunk_file(file_path: String, chunk_size: usize) -> io::Result<Vec<Vec<u8>>> {
    println!("Attempting to read file: {}", file_path);
    let mut file = File::open(file_path)?;
    let mut chunks = Vec::new();

    loop {
        let mut buffer = vec![0; chunk_size]; // Create a buffer for the current chunk
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


pub async fn reconstruct_file(chunks: Vec<Vec<u8>>, output_path: &Path) -> io::Result<()> {
    // Open the file for writing. `.create(true)` will create the file
    // if it does not exist.
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)?;

    let mut writer = BufWriter::new(file);

    for chunk in chunks {
        // Write each chunk to the writer
        writer.write_all(&chunk)?;
        println!("Wrote a chunk of {} bytes.", chunk.len());
    }

    writer.flush()?;

    println!("File successfully reconstructed at {:?}", output_path);
    Ok(())
}

pub async fn chunk_and_encrypt_file(file_path: &String, encryption_key: [u8; 32]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    if !Path::new(&file_path).exists() {
        return Err(format!("File '{}' not found in current directory: {:?}", 
                        file_path, std::env::current_dir()?).into());
    }

    let mut file = File::open(file_path)?;
    let mut chunk_index: u64 = 0;

    // could compress the file here??

    const PLAINTEXT_CHUNK_SIZE: usize = CHUNK_SIZE - ENCRYPTION_OVERHEAD;

    let mut chunks: Vec<Vec<u8>> = Vec::new();

    loop {
        let mut buffer = vec![0; PLAINTEXT_CHUNK_SIZE]; 
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
    println!("Enter filename to send:");
    let mut input = String::new();
    input = std::io::stdin().read_line(&mut input).map(|_| input.trim().to_string())?;

    Ok(input)
}

