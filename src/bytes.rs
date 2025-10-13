use std::io::{self, Read, Write, BufWriter};
use std::fs::{self, File, OpenOptions};
use std::path::Path;

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

