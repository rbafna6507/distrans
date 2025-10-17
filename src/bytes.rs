use std::io::{self, Read, Write, BufWriter, Cursor};
use std::error::Error;
use std::fs::{File, OpenOptions};
use crate::{NONCE_SIZE, CHUNK_SIZE, ENCRYPTION_OVERHEAD, ENCRYPTION_ADJUSTED_CHUNK_SIZE, cryptography::{encrypt_chunk}};
use crate::utils::{CliReceiver, CliSender, FileMetadata};
use std::path::Path;
use clap::Parser;
use rand::Rng;
use zip::write::{FileOptions, ZipWriter};
use zip::read::ZipArchive;
use std::fs;
use arboard::Clipboard;
use walkdir::WalkDir;


// TODO: compression and folders

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


/// compress a file into a zip archive
/// returns the zip archive as a Vec<u8>
pub fn compress_folder(folder_path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let buffer = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(buffer);
    
    let options = FileOptions::<()>::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);
    
    // walk through all directories in folder
    for entry in WalkDir::new(folder_path) {
        let entry = entry?;
        let path = entry.path();
        
        // get relative path from base folder
        let relative_path = path.strip_prefix(folder_path.parent().unwrap_or(folder_path))?;
        let name = relative_path.to_str().ok_or("Invalid path")?;
        
        if path.is_file() {
            println!("Adding file: {}", name);
            zip.start_file(name, options)?;
            let mut f = File::open(path)?;
            io::copy(&mut f, &mut zip)?;
        } else if path.is_dir() && path != folder_path {
            // Add directory entry (with trailing /)
            println!("Adding directory: {}/", name);
            zip.add_directory(format!("{}/", name), options)?;
        }
    }
    
    let cursor = zip.finish()?;
    Ok(cursor.into_inner())
}

// decompress zip folder into target directory
pub fn decompress_folder(zip_data: &[u8], output_path: &Path) -> Result<(), Box<dyn Error>> {
    let reader = Cursor::new(zip_data);
    let mut archive = ZipArchive::new(reader)?;
    
    println!("Extracting {} files/folders...", archive.len());
    
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = output_path.join(file.name());
        
        if file.name().ends_with('/') {
            // It's a directory
            println!("Creating directory: {:?}", outpath);
            fs::create_dir_all(&outpath)?;
        } else {
            // It's a file
            println!("Extracting file: {:?}", outpath);
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut outfile = File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
        }
        
        // Set permissions on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
            }
        }
    }
    
    println!("Extraction complete!");
    Ok(())
}


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

}

