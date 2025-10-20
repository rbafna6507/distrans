use std::io::{self, Read, BufWriter, Cursor};
use std::error::Error;
use std::fs::{File, OpenOptions};
use crate::{CHUNK_SIZE, ENCRYPTION_OVERHEAD, ENCRYPTION_ADJUSTED_CHUNK_SIZE};
use crate::utils::{CliReceiver, FileMetadata};
use std::path::Path;
use clap::Parser;
use log::debug;
use rand::Rng;
use zip::write::{FileOptions, ZipWriter};
use zip::read::ZipArchive;
use std::fs;
use arboard::Clipboard;
use walkdir::WalkDir;

/// Read a chunk of data from a data source (file or zip archive in memory).
///
/// The chunk size is limited to ENCRYPTION_ADJUSTED_CHUNK_SIZE (1024 - 16 = 1008 bytes)
/// to leave room for the 16-byte authentication tag added during encryption.
///
/// # Arguments
/// * `data_source` - Any readable source (File, Cursor<Vec<u8>>, etc.)
///
/// # Returns
/// A tuple of (buffer with data, number of bytes actually read)
/// Returns (buffer, 0) when end of data is reached
pub fn read_chunk<R: Read>(data_source: &mut R) -> Result<(Vec<u8>, usize), io::Error> {
    let mut buffer = vec![0; ENCRYPTION_ADJUSTED_CHUNK_SIZE];
    let bytes_read = data_source.read(&mut buffer)?;
    
    if bytes_read > 0 {
        buffer.truncate(bytes_read);
    }
    
    Ok((buffer, bytes_read))
}

/// Generates a random 6-digit shared key and copies it to the clipboard.
///
/// The key is used for:
/// 1. Determining the room number (key / 100) for relay pairing - divide by 100
///    to obfuscate the rest of the code on the relay used for encryption/decryption
/// 2. PAKE authentication to derive encryption key
///
/// # Returns
/// A random number between 100,000 and 999,999 (inclusive)
pub fn generate_shared_key() -> u32 {
    let mut clipboard = Clipboard::new().unwrap();
    let mut rng = rand::rng();

    // Generate a random number between 100,000 (inclusive) and 999,999 (inclusive)
    let random_number: u32 = rng.random_range(100_000..=999_999);
    clipboard.set_text(random_number.to_string()).unwrap();
    random_number
}

/// Retrieves the shared key from command-line arguments (for receiver).
///
/// # Returns
/// The 6-digit shared key entered by the user
pub fn get_shared_key() -> Result<u32, Box<dyn Error>> {
    let cli = CliReceiver::parse();
    Ok(cli.shared_key)
}

/// Generate FileMetadata struct containing file/folder information.
///
/// # Arguments
/// * `filename` - Name of the file or folder
/// * `size` - Size in bytes (for folders, this is the compressed zip size)
/// * `is_folder` - True if sending a folder, false if sending a file
///
/// # Returns
/// FileMetadata struct to be sent to the receiver
pub fn generate_metadata(filename: String, size: u64, is_folder: bool) -> FileMetadata {
    FileMetadata {
        filename,
        file_size: size,
        is_folder,
    }
}

/// Compresses a folder into a zip archive in memory.
///
/// # Process
/// 1. Walks through all subdirectories and files in the folder
/// 2. Adds each file/directory to a zip archive with compression
/// 3. Preserves directory structure and file permissions (on Unix)
///
/// # Arguments
/// * `folder_path` - Path to the folder to compress
///
/// # Returns
/// A Vec<u8> containing the compressed zip data (ready to send over network)
pub fn compress_folder(folder_path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    // Initialize a buffer to write the zip file into
    let buffer = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(buffer);
    
    let options = FileOptions::<()>::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);
    
    // Walk through all directories and files in folder
    for entry in WalkDir::new(folder_path) {
        let entry = entry?;
        let path = entry.path();
        
        // Skip the root folder itself
        if path == folder_path {
            continue;
        }
        
        // Get relative path from the folder being compressed
        let relative_path = path.strip_prefix(folder_path)?;
        let name = relative_path.to_str().ok_or("Invalid path")?;
        
        // Add file or folder to the zip archive
        if path.is_file() {
            debug!("Adding file: {}", name);
            zip.start_file(name, options)?;
            let mut f = File::open(path)?;
            io::copy(&mut f, &mut zip)?;
        } else if path.is_dir() {
            // Add directory entry (with trailing /)
            debug!("Adding directory: {}/", name);
            zip.add_directory(format!("{}/", name), options)?;
        }
    }
    
    let cursor = zip.finish()?;
    Ok(cursor.into_inner())
}

/// Decompresses a zip archive into a target directory.
///
/// # Process
/// 1. Reads the zip data from memory
/// 2. Extracts all files and directories
/// 3. Preserves directory structure and permissions (on Unix)
///
/// # Arguments
/// * `zip_data` - The compressed zip data (as bytes)
/// * `output_path` - The directory to extract files into
///
/// # Returns
/// Ok(()) if extraction succeeds, or an error if it fails
pub fn decompress_folder(zip_data: &[u8], output_path: &Path) -> Result<(), Box<dyn Error>> {
    let reader = Cursor::new(zip_data);
    let mut archive = ZipArchive::new(reader)?;
    
    debug!("Extracting {} files/folders...", archive.len());
    
    // For each entry in the Zip Archive
    for i in 0..archive.len() {
        // Get filename and create output path
        let mut file = archive.by_index(i)?;
        let outpath = output_path.join(file.name());
        
        // Extract (create) directory and files
        if file.name().ends_with('/') {
            debug!("Creating directory: {:?}", outpath);
            fs::create_dir_all(&outpath)?;
        } else {
            debug!("Extracting file: {:?}", outpath);
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
    
    debug!("Extraction complete!");
    Ok(())
}

/// Reads a file and splits it into chunks of CHUNK_SIZE (with encryption overhead accounted for).
///
/// # Note
/// This function is used for testing/legacy purposes. The main transfer logic uses
/// `read_chunk()` with streaming instead of loading all chunks into memory.
///
/// # Arguments
/// * `file_path` - Path to the file to chunk
///
/// # Returns
/// A vector of chunks (each chunk is a Vec<u8>)

/// Given a filepath, return the file as a vector of chunks of size CHUNK_SIZE
pub async fn chunk_file(file_path: String) -> io::Result<Vec<Vec<u8>>> {
    let mut file = File::open(file_path)?;
    let mut chunks = Vec::new();

    // Continue reading the file in chunks of CHUNK_SIZE
    // Add the newly read chunk to the chunks vector
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

    // Return the chunks vector containing the file
    Ok(chunks)
}

/// Creates a buffered writer for a new file at the specified path.
///
/// The file is created (or truncated if it exists) and opened for writing.
///
/// # Arguments
/// * `output_path` - Path where the file should be created
///
/// # Returns
/// A BufWriter for efficient file writing
pub fn create_file_bufwriter(output_path: &Path) -> BufWriter<File> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path).unwrap();

    BufWriter::new(file)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_chunk_full() {
        let data = vec![0u8; ENCRYPTION_ADJUSTED_CHUNK_SIZE];
        let mut cursor = Cursor::new(data);
        
        let (buffer, bytes_read) = read_chunk(&mut cursor).expect("Should read chunk");
        
        assert_eq!(bytes_read, ENCRYPTION_ADJUSTED_CHUNK_SIZE);
        assert_eq!(buffer.len(), ENCRYPTION_ADJUSTED_CHUNK_SIZE);
    }

    #[test]
    fn test_read_chunk_partial() {
        let data = vec![1u8; 100];
        let mut cursor = Cursor::new(data);
        
        let (buffer, bytes_read) = read_chunk(&mut cursor).expect("Should read chunk");
        
        assert_eq!(bytes_read, 100);
        assert_eq!(buffer.len(), 100);
        assert_eq!(buffer[0], 1);
    }

    #[test]
    fn test_read_chunk_empty() {
        let data = vec![];
        let mut cursor = Cursor::new(data);
        
        let (buffer, bytes_read) = read_chunk(&mut cursor).expect("Should handle EOF");
        
        assert_eq!(bytes_read, 0);
        // When bytes_read is 0 (EOF), buffer is not truncated and remains at full size
        assert_eq!(buffer.len(), ENCRYPTION_ADJUSTED_CHUNK_SIZE);
    }

    #[test]
    fn test_generate_metadata_file() {
        let metadata = generate_metadata("test.txt".to_string(), 1024, false);
        
        assert_eq!(metadata.filename, "test.txt");
        assert_eq!(metadata.file_size, 1024);
        assert_eq!(metadata.is_folder, false);
    }

    #[test]
    fn test_generate_metadata_folder() {
        let metadata = generate_metadata("my_folder".to_string(), 2048, true);
        
        assert_eq!(metadata.filename, "my_folder");
        assert_eq!(metadata.file_size, 2048);
        assert_eq!(metadata.is_folder, true);
    }

    #[test]
    fn test_generate_shared_key_range() {
        let key = generate_shared_key();
        
        // Should be 6 digits (100,000 to 999,999)
        assert!(key >= 100_000);
        assert!(key <= 999_999);
    }

    #[test]
    fn test_compress_folder_empty() {
        use std::fs;

        // Create a temporary directory
        let temp_dir = std::env::temp_dir().join(format!("test_distrans_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        // Compress the empty folder
        let result = compress_folder(&temp_dir);
        
        // Should succeed even with empty folder
        assert!(result.is_ok());
        let compressed = result.unwrap();
        assert!(!compressed.is_empty());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}

