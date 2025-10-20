use std::io::{self, Read, BufWriter, Cursor};
use std::error::Error;
use std::fs::{File, OpenOptions};
use crate::{CHUNK_SIZE, ENCRYPTION_OVERHEAD, ENCRYPTION_ADJUSTED_CHUNK_SIZE};
use crate::utils::{FileMetadata};
use std::path::Path;
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
    let mut rng = rand::rng();

    // Generate a random number between 100,000 (inclusive) and 999,999 (inclusive)
    let random_number: u32 = rng.random_range(100_000..=999_999);
    
    // Try to copy to clipboard (may fail in test environments or headless systems)
    if let Ok(mut clipboard) = Clipboard::new() {
        let _ = clipboard.set_text(random_number.to_string());
    }
    
    random_number
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

    // ============================================================================
    // Chunk Reading Tests
    // ============================================================================

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
    fn test_read_chunk_multiple_chunks() {
        // Create data that spans multiple chunks
        let total_size = ENCRYPTION_ADJUSTED_CHUNK_SIZE * 3 + 500;
        let data = vec![42u8; total_size];
        let mut cursor = Cursor::new(data);
        
        let mut chunks_read = 0;
        let mut total_bytes = 0;
        
        loop {
            let (buffer, bytes_read) = read_chunk(&mut cursor).expect("Should read chunk");
            if bytes_read == 0 {
                break;
            }
            chunks_read += 1;
            total_bytes += bytes_read;
            
            // Verify data integrity
            assert!(buffer.iter().all(|&b| b == 42));
        }
        
        assert_eq!(chunks_read, 4); // 3 full chunks + 1 partial
        assert_eq!(total_bytes, total_size);
    }

    #[test]
    fn test_read_chunk_exact_boundary() {
        // Test reading exactly ENCRYPTION_ADJUSTED_CHUNK_SIZE bytes
        let data = vec![77u8; ENCRYPTION_ADJUSTED_CHUNK_SIZE];
        let mut cursor = Cursor::new(data);
        
        let (buffer, bytes_read) = read_chunk(&mut cursor).expect("Should read chunk");
        assert_eq!(bytes_read, ENCRYPTION_ADJUSTED_CHUNK_SIZE);
        assert_eq!(buffer.len(), ENCRYPTION_ADJUSTED_CHUNK_SIZE);
        
        // Next read should be EOF
        let (_, bytes_read) = read_chunk(&mut cursor).expect("Should handle EOF");
        assert_eq!(bytes_read, 0);
    }

    #[test]
    fn test_read_chunk_single_byte() {
        let data = vec![99u8; 1];
        let mut cursor = Cursor::new(data);
        
        let (buffer, bytes_read) = read_chunk(&mut cursor).expect("Should read single byte");
        assert_eq!(bytes_read, 1);
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer[0], 99);
    }

    // ============================================================================
    // Metadata Generation Tests
    // ============================================================================

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
    fn test_generate_shared_key_multiple() {
        // Generate multiple keys and ensure all are valid
        for _ in 0..100 {
            let key = generate_shared_key();
            assert!(key >= 100_000);
            assert!(key <= 999_999);
        }
    }

    // ============================================================================
    // Folder Compression Tests
    // ============================================================================

    #[test]
    fn test_compress_folder_empty() {
        use std::fs;

        // Create a temporary directory
        let temp_dir = std::env::temp_dir().join(format!("test_rift_empty_{}", std::process::id()));
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

    #[test]
    fn test_compress_folder_with_file() {
        use std::fs;
        use std::io::Write;

        // Create temp directory with a file
        let temp_dir = std::env::temp_dir().join(format!("test_rift_file_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let test_file = temp_dir.join("test.txt");
        let mut file = fs::File::create(&test_file).unwrap();
        file.write_all(b"Hello, World!").unwrap();

        // Compress the folder
        let compressed = compress_folder(&temp_dir).expect("Should compress folder");
        
        // Verify it's a valid zip
        assert!(!compressed.is_empty());
        assert!(compressed.len() > 20); // Zip header is at least 22 bytes

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_compress_folder_with_subdirectory() {
        use std::fs;
        use std::io::Write;

        let temp_dir = std::env::temp_dir().join(format!("test_rift_subdir_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        // Create subdirectory
        let sub_dir = temp_dir.join("subdir");
        fs::create_dir_all(&sub_dir).unwrap();

        // Create file in subdirectory
        let test_file = sub_dir.join("nested.txt");
        let mut file = fs::File::create(&test_file).unwrap();
        file.write_all(b"Nested content").unwrap();

        // Compress
        let compressed = compress_folder(&temp_dir).expect("Should compress folder with subdirs");
        assert!(!compressed.is_empty());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_compress_folder_multiple_files() {
        use std::fs;
        use std::io::Write;

        let temp_dir = std::env::temp_dir().join(format!("test_rift_multi_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        // Create multiple files
        for i in 0..5 {
            let file_path = temp_dir.join(format!("file{}.txt", i));
            let mut file = fs::File::create(&file_path).unwrap();
            file.write_all(format!("Content {}", i).as_bytes()).unwrap();
        }

        let compressed = compress_folder(&temp_dir).expect("Should compress multiple files");
        assert!(!compressed.is_empty());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    // ============================================================================
    // Folder Decompression Tests
    // ============================================================================

    #[test]
    fn test_compress_decompress_roundtrip() {
        use std::fs;
        use std::io::Write;

        // Create source folder
        let source_dir = std::env::temp_dir().join(format!("test_rift_src_{}", std::process::id()));
        fs::create_dir_all(&source_dir).unwrap();

        let test_file = source_dir.join("test.txt");
        let mut file = fs::File::create(&test_file).unwrap();
        file.write_all(b"Test content").unwrap();

        // Compress
        let compressed = compress_folder(&source_dir).expect("Should compress");

        // Decompress to different location
        let dest_dir = std::env::temp_dir().join(format!("test_rift_dst_{}", std::process::id()));
        decompress_folder(&compressed, &dest_dir).expect("Should decompress");

        // Verify file exists
        let decompressed_file = dest_dir.join("test.txt");
        assert!(decompressed_file.exists());

        // Verify content
        let content = fs::read_to_string(decompressed_file).unwrap();
        assert_eq!(content, "Test content");

        // Cleanup
        let _ = fs::remove_dir_all(&source_dir);
        let _ = fs::remove_dir_all(&dest_dir);
    }

    #[test]
    fn test_decompress_preserves_structure() {
        use std::fs;
        use std::io::Write;

        // Create source with subdirectories
        let source_dir = std::env::temp_dir().join(format!("test_rift_struct_{}", std::process::id()));
        fs::create_dir_all(&source_dir).unwrap();

        let sub_dir = source_dir.join("subdir");
        fs::create_dir_all(&sub_dir).unwrap();

        let file1 = source_dir.join("root.txt");
        fs::File::create(&file1).unwrap().write_all(b"Root file").unwrap();

        let file2 = sub_dir.join("nested.txt");
        fs::File::create(&file2).unwrap().write_all(b"Nested file").unwrap();

        // Compress and decompress
        let compressed = compress_folder(&source_dir).expect("Should compress");
        let dest_dir = std::env::temp_dir().join(format!("test_rift_dest_{}", std::process::id()));
        decompress_folder(&compressed, &dest_dir).expect("Should decompress");

        // Verify structure
        assert!(dest_dir.join("root.txt").exists());
        assert!(dest_dir.join("subdir").exists());
        assert!(dest_dir.join("subdir").join("nested.txt").exists());

        // Verify content
        let content = fs::read_to_string(dest_dir.join("subdir").join("nested.txt")).unwrap();
        assert_eq!(content, "Nested file");

        // Cleanup
        let _ = fs::remove_dir_all(&source_dir);
        let _ = fs::remove_dir_all(&dest_dir);
    }

    #[test]
    fn test_decompress_empty_zip() {
        use std::fs;

        // Create and compress empty folder
        let source_dir = std::env::temp_dir().join(format!("test_rift_empty_src_{}", std::process::id()));
        fs::create_dir_all(&source_dir).unwrap();

        let compressed = compress_folder(&source_dir).expect("Should compress empty folder");

        // Decompress
        let dest_dir = std::env::temp_dir().join(format!("test_rift_empty_dst_{}", std::process::id()));
        let result = decompress_folder(&compressed, &dest_dir);
        
        assert!(result.is_ok());

        // Cleanup
        let _ = fs::remove_dir_all(&source_dir);
        let _ = fs::remove_dir_all(&dest_dir);
    }

    #[test]
    fn test_decompress_large_file() {
        use std::fs;
        use std::io::Write;

        let source_dir = std::env::temp_dir().join(format!("test_rift_large_{}", std::process::id()));
        fs::create_dir_all(&source_dir).unwrap();

        // Create a larger file (10KB)
        let large_file = source_dir.join("large.bin");
        let mut file = fs::File::create(&large_file).unwrap();
        let data = vec![0xAAu8; 10240];
        file.write_all(&data).unwrap();

        // Compress and decompress
        let compressed = compress_folder(&source_dir).expect("Should compress");
        let dest_dir = std::env::temp_dir().join(format!("test_rift_large_dst_{}", std::process::id()));
        decompress_folder(&compressed, &dest_dir).expect("Should decompress");

        // Verify
        let decompressed = dest_dir.join("large.bin");
        assert!(decompressed.exists());
        let decompressed_data = fs::read(decompressed).unwrap();
        assert_eq!(decompressed_data.len(), 10240);
        assert!(decompressed_data.iter().all(|&b| b == 0xAA));

        // Cleanup
        let _ = fs::remove_dir_all(&source_dir);
        let _ = fs::remove_dir_all(&dest_dir);
    }

    // ============================================================================
    // File Chunking Tests (async)
    // ============================================================================

    #[tokio::test]
    async fn test_chunk_file_small() {
        use std::fs;
        use std::io::Write;

        // Create a small test file
        let temp_file = std::env::temp_dir().join(format!("test_chunk_small_{}.txt", std::process::id()));
        let mut file = fs::File::create(&temp_file).unwrap();
        file.write_all(b"Hello, World!").unwrap();

        let file_path = temp_file.to_str().unwrap().to_string();
        let chunks = chunk_file(file_path).await.expect("Should chunk file");

        assert_eq!(chunks.len(), 1); // Small file fits in one chunk
        assert_eq!(chunks[0], b"Hello, World!");

        // Cleanup
        let _ = fs::remove_file(&temp_file);
    }

    #[tokio::test]
    async fn test_chunk_file_exact_chunk_size() {
        use std::fs;
        use std::io::Write;

        let temp_file = std::env::temp_dir().join(format!("test_chunk_exact_{}.bin", std::process::id()));
        let mut file = fs::File::create(&temp_file).unwrap();
        let data = vec![42u8; CHUNK_SIZE - ENCRYPTION_OVERHEAD];
        file.write_all(&data).unwrap();

        let file_path = temp_file.to_str().unwrap().to_string();
        let chunks = chunk_file(file_path).await.expect("Should chunk file");

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), CHUNK_SIZE - ENCRYPTION_OVERHEAD);

        // Cleanup
        let _ = fs::remove_file(&temp_file);
    }

    #[tokio::test]
    async fn test_chunk_file_multiple_chunks() {
        use std::fs;
        use std::io::Write;

        let temp_file = std::env::temp_dir().join(format!("test_chunk_multi_{}.bin", std::process::id()));
        let mut file = fs::File::create(&temp_file).unwrap();
        
        // Create file larger than one chunk
        let total_size = (CHUNK_SIZE - ENCRYPTION_OVERHEAD) * 2 + 100;
        let data = vec![77u8; total_size];
        file.write_all(&data).unwrap();

        let file_path = temp_file.to_str().unwrap().to_string();
        let chunks = chunk_file(file_path).await.expect("Should chunk file");

        assert_eq!(chunks.len(), 3); // 2 full chunks + 1 partial
        assert_eq!(chunks[0].len(), CHUNK_SIZE - ENCRYPTION_OVERHEAD);
        assert_eq!(chunks[1].len(), CHUNK_SIZE - ENCRYPTION_OVERHEAD);
        assert_eq!(chunks[2].len(), 100);

        // Cleanup
        let _ = fs::remove_file(&temp_file);
    }

    #[tokio::test]
    async fn test_chunk_file_empty() {
        use std::fs;

        let temp_file = std::env::temp_dir().join(format!("test_chunk_empty_{}.txt", std::process::id()));
        fs::File::create(&temp_file).unwrap();

        let file_path = temp_file.to_str().unwrap().to_string();
        let chunks = chunk_file(file_path).await.expect("Should handle empty file");

        assert_eq!(chunks.len(), 0); // Empty file = no chunks

        // Cleanup
        let _ = fs::remove_file(&temp_file);
    }
}

