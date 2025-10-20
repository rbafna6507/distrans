// Integration tests for the Rift file transfer system
// These tests validate end-to-end functionality of sender, receiver, and relay

use rift::{
    cryptography::{encrypt_chunk, decrypt_chunk, create_session_id, generate_initial_pake_message, derive_session_key},
    bytes::{generate_metadata, compress_folder, decompress_folder},
    utils::{FileMetadata, Init, PeerAddresses},
};
use std::fs;
use std::io::Write;

// ============================================================================
// End-to-End Encryption Tests
// ============================================================================

#[test]
fn test_complete_encryption_flow() {
    // Simulate complete file encryption workflow
    let shared_key = 123456u32;
    let identity = create_session_id(shared_key);
    
    // Both parties generate PAKE messages
    let (sender_spake, sender_msg) = generate_initial_pake_message(shared_key, &identity);
    let (receiver_spake, receiver_msg) = generate_initial_pake_message(shared_key, &identity);
    
    // Derive encryption keys
    let sender_key = derive_session_key(sender_spake, &receiver_msg)
        .expect("Sender key derivation should succeed");
    let receiver_key = derive_session_key(receiver_spake, &sender_msg)
        .expect("Receiver key derivation should succeed");
    
    // Simulate encrypting multiple chunks of a file
    let file_data = b"This is a test file with multiple chunks of data that will be encrypted and decrypted";
    let chunk_size = 20;
    
    let mut encrypted_chunks = Vec::new();
    for (idx, chunk) in file_data.chunks(chunk_size).enumerate() {
        let encrypted = encrypt_chunk(&sender_key, chunk, idx as u64)
            .expect("Encryption should succeed");
        encrypted_chunks.push(encrypted);
    }
    
    // Simulate decryption on receiver side
    let mut decrypted_data = Vec::new();
    for (idx, encrypted_chunk) in encrypted_chunks.iter().enumerate() {
        let decrypted = decrypt_chunk(&receiver_key, encrypted_chunk, idx as u64)
            .expect("Decryption should succeed");
        decrypted_data.extend_from_slice(&decrypted);
    }
    
    // Verify data integrity
    assert_eq!(&decrypted_data[..], file_data);
}

#[test]
fn test_encryption_wrong_chunk_order() {
    let shared_key = 555555u32;
    let identity = create_session_id(shared_key);
    
    let (sender_spake, sender_msg) = generate_initial_pake_message(shared_key, &identity);
    let (receiver_spake, receiver_msg) = generate_initial_pake_message(shared_key, &identity);
    
    let sender_key = derive_session_key(sender_spake, &receiver_msg).unwrap();
    let receiver_key = derive_session_key(receiver_spake, &sender_msg).unwrap();
    
    // Encrypt chunks with specific indices
    let chunk1 = b"First chunk";
    let chunk2 = b"Second chunk";
    
    let encrypted1 = encrypt_chunk(&sender_key, chunk1, 0).unwrap();
    let encrypted2 = encrypt_chunk(&sender_key, chunk2, 1).unwrap();
    
    // Try to decrypt with swapped indices - should fail
    let result1 = decrypt_chunk(&receiver_key, &encrypted1, 1);
    let result2 = decrypt_chunk(&receiver_key, &encrypted2, 0);
    
    assert!(result1.is_err(), "Decrypting with wrong index should fail");
    assert!(result2.is_err(), "Decrypting with wrong index should fail");
    
    // Decrypt with correct indices - should succeed
    let decrypted1 = decrypt_chunk(&receiver_key, &encrypted1, 0).unwrap();
    let decrypted2 = decrypt_chunk(&receiver_key, &encrypted2, 1).unwrap();
    
    assert_eq!(&decrypted1[..], chunk1);
    assert_eq!(&decrypted2[..], chunk2);
}

// ============================================================================
// Folder Compression/Decompression Integration Tests
// ============================================================================

#[test]
fn test_folder_compress_decompress_integration() {
    let temp_base = std::env::temp_dir().join(format!("test_integration_{}", std::process::id()));
    
    // Create source folder with multiple files and subdirectories
    let source_dir = temp_base.join("source");
    fs::create_dir_all(&source_dir).unwrap();
    
    // Create file in root
    let file1 = source_dir.join("readme.txt");
    fs::File::create(&file1).unwrap()
        .write_all(b"This is the readme file").unwrap();
    
    // Create subdirectory with files
    let subdir = source_dir.join("data");
    fs::create_dir_all(&subdir).unwrap();
    
    let file2 = subdir.join("data.bin");
    fs::File::create(&file2).unwrap()
        .write_all(&[0xAA; 1000]).unwrap();
    
    let file3 = subdir.join("config.json");
    fs::File::create(&file3).unwrap()
        .write_all(b"{\"setting\": \"value\"}").unwrap();
    
    // Create nested subdirectory
    let nested = subdir.join("nested");
    fs::create_dir_all(&nested).unwrap();
    
    let file4 = nested.join("nested.txt");
    fs::File::create(&file4).unwrap()
        .write_all(b"Nested file content").unwrap();
    
    // Compress the folder
    let compressed = compress_folder(&source_dir)
        .expect("Should compress folder");
    
    // Decompress to destination
    let dest_dir = temp_base.join("destination");
    decompress_folder(&compressed, &dest_dir)
        .expect("Should decompress folder");
    
    // Verify all files and structure
    assert!(dest_dir.join("readme.txt").exists());
    assert!(dest_dir.join("data").exists());
    assert!(dest_dir.join("data/data.bin").exists());
    assert!(dest_dir.join("data/config.json").exists());
    assert!(dest_dir.join("data/nested").exists());
    assert!(dest_dir.join("data/nested/nested.txt").exists());
    
    // Verify content
    let content = fs::read_to_string(dest_dir.join("readme.txt")).unwrap();
    assert_eq!(content, "This is the readme file");
    
    let data = fs::read(dest_dir.join("data/data.bin")).unwrap();
    assert_eq!(data.len(), 1000);
    assert!(data.iter().all(|&b| b == 0xAA));
    
    let nested_content = fs::read_to_string(dest_dir.join("data/nested/nested.txt")).unwrap();
    assert_eq!(nested_content, "Nested file content");
    
    // Cleanup
    let _ = fs::remove_dir_all(&temp_base);
}

#[test]
fn test_folder_with_empty_subdirectories() {
    let temp_base = std::env::temp_dir().join(format!("test_empty_dirs_{}", std::process::id()));
    
    let source_dir = temp_base.join("source");
    fs::create_dir_all(&source_dir).unwrap();
    
    // Create empty subdirectories
    let empty1 = source_dir.join("empty1");
    fs::create_dir_all(&empty1).unwrap();
    
    let empty2 = source_dir.join("empty2");
    fs::create_dir_all(&empty2).unwrap();
    
    // Create one file
    let file = source_dir.join("file.txt");
    fs::File::create(&file).unwrap()
        .write_all(b"Single file").unwrap();
    
    // Compress and decompress
    let compressed = compress_folder(&source_dir).unwrap();
    let dest_dir = temp_base.join("destination");
    decompress_folder(&compressed, &dest_dir).unwrap();
    
    // Verify structure
    assert!(dest_dir.join("file.txt").exists());
    // Note: Empty directories may or may not be preserved depending on zip implementation
    
    // Cleanup
    let _ = fs::remove_dir_all(&temp_base);
}

// ============================================================================
// Metadata Tests
// ============================================================================

#[test]
fn test_metadata_generation_for_real_file() {
    let temp_file = std::env::temp_dir().join(format!("test_meta_{}.txt", std::process::id()));
    let content = b"Test file content for metadata generation";
    
    fs::File::create(&temp_file).unwrap()
        .write_all(content).unwrap();
    
    let file_size = fs::metadata(&temp_file).unwrap().len();
    let metadata = generate_metadata(
        temp_file.file_name().unwrap().to_str().unwrap().to_string(),
        file_size,
        false
    );
    
    assert_eq!(metadata.file_size, content.len() as u64);
    assert_eq!(metadata.is_folder, false);
    
    // Cleanup
    let _ = fs::remove_file(&temp_file);
}

#[test]
fn test_metadata_serialization_deserialization() {
    let metadata = FileMetadata {
        filename: "test.txt".to_string(),
        file_size: 12345,
        is_folder: false,
    };
    
    // Serialize
    let serialized = bincode::serialize(&metadata)
        .expect("Should serialize metadata");
    
    // Deserialize
    let deserialized: FileMetadata = bincode::deserialize(&serialized)
        .expect("Should deserialize metadata");
    
    assert_eq!(deserialized.filename, metadata.filename);
    assert_eq!(deserialized.file_size, metadata.file_size);
    assert_eq!(deserialized.is_folder, metadata.is_folder);
}

// ============================================================================
// Init Message Tests
// ============================================================================

#[test]
fn test_init_message_serialization() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    let init = Init {
        is_sender: true,
        room: 1234,
        local_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080)),
    };
    
    // Serialize
    let serialized = bincode::serialize(&init)
        .expect("Should serialize Init");
    
    // Deserialize
    let deserialized: Init = bincode::deserialize(&serialized)
        .expect("Should deserialize Init");
    
    assert_eq!(deserialized.is_sender, init.is_sender);
    assert_eq!(deserialized.room, init.room);
    assert_eq!(deserialized.local_addr, init.local_addr);
}

#[test]
fn test_peer_addresses_serialization() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    let peer_addresses = PeerAddresses {
        external_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(45, 55, 102, 56)), 8080),
        local_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080)),
    };
    
    // Serialize with serde_json (as used in relay)
    let json = serde_json::to_string(&peer_addresses)
        .expect("Should serialize to JSON");
    
    // Deserialize
    let deserialized: PeerAddresses = serde_json::from_str(&json)
        .expect("Should deserialize from JSON");
    
    assert_eq!(deserialized.external_addr, peer_addresses.external_addr);
    assert_eq!(deserialized.local_addr, peer_addresses.local_addr);
}

// ============================================================================
// Large File Simulation Tests
// ============================================================================

#[test]
fn test_large_file_encryption_chunks() {
    let shared_key = 999999u32;
    let identity = create_session_id(shared_key);
    
    let (sender_spake, sender_msg) = generate_initial_pake_message(shared_key, &identity);
    let (receiver_spake, receiver_msg) = generate_initial_pake_message(shared_key, &identity);
    
    let sender_key = derive_session_key(sender_spake, &receiver_msg).unwrap();
    let receiver_key = derive_session_key(receiver_spake, &sender_msg).unwrap();
    
    // Simulate 100 chunks (like a larger file)
    let chunk_count = 100;
    let mut encrypted_chunks = Vec::new();
    
    for i in 0..chunk_count {
        let chunk_data = vec![i as u8; 500]; // Each chunk has distinct data
        let encrypted = encrypt_chunk(&sender_key, &chunk_data, i as u64).unwrap();
        encrypted_chunks.push((i, encrypted, chunk_data));
    }
    
    // Verify all chunks can be decrypted correctly
    for (idx, encrypted, original) in encrypted_chunks.iter() {
        let decrypted = decrypt_chunk(&receiver_key, encrypted, *idx as u64)
            .expect("Should decrypt chunk");
        assert_eq!(&decrypted[..], &original[..], "Chunk {} should match", idx);
    }
}

// ============================================================================
// Error Recovery Tests
// ============================================================================

#[test]
fn test_encryption_with_corrupted_chunk() {
    let shared_key = 111111u32;
    let identity = create_session_id(shared_key);
    
    let (sender_spake, sender_msg) = generate_initial_pake_message(shared_key, &identity);
    let (receiver_spake, receiver_msg) = generate_initial_pake_message(shared_key, &identity);
    
    let sender_key = derive_session_key(sender_spake, &receiver_msg).unwrap();
    let receiver_key = derive_session_key(receiver_spake, &sender_msg).unwrap();
    
    // Encrypt multiple chunks
    let chunks = vec![
        b"Chunk 0 data".to_vec(),
        b"Chunk 1 data".to_vec(),
        b"Chunk 2 data".to_vec(),
    ];
    
    let mut encrypted = Vec::new();
    for (idx, chunk) in chunks.iter().enumerate() {
        encrypted.push(encrypt_chunk(&sender_key, chunk, idx as u64).unwrap());
    }
    
    // Corrupt the middle chunk
    encrypted[1][5] ^= 0xFF;
    
    // First chunk should decrypt fine
    let dec0 = decrypt_chunk(&receiver_key, &encrypted[0], 0);
    assert!(dec0.is_ok());
    
    // Middle chunk should fail (corrupted)
    let dec1 = decrypt_chunk(&receiver_key, &encrypted[1], 1);
    assert!(dec1.is_err(), "Corrupted chunk should fail to decrypt");
    
    // Last chunk should still decrypt fine
    let dec2 = decrypt_chunk(&receiver_key, &encrypted[2], 2);
    assert!(dec2.is_ok());
}

// ============================================================================
// Cross-Module Integration Tests
// ============================================================================

#[test]
fn test_compress_encrypt_decrypt_decompress_flow() {
    // Complete flow: compress folder → encrypt chunks → decrypt chunks → decompress folder
    let temp_base = std::env::temp_dir().join(format!("test_full_flow_{}", std::process::id()));
    
    // 1. Create source folder
    let source_dir = temp_base.join("source");
    fs::create_dir_all(&source_dir).unwrap();
    let file = source_dir.join("data.txt");
    fs::File::create(&file).unwrap()
        .write_all(b"Important data that will be compressed and encrypted").unwrap();
    
    // 2. Compress folder
    let compressed = compress_folder(&source_dir).unwrap();
    
    // 3. Set up encryption
    let shared_key = 424242u32;
    let identity = create_session_id(shared_key);
    let (sender_spake, sender_msg) = generate_initial_pake_message(shared_key, &identity);
    let (receiver_spake, receiver_msg) = generate_initial_pake_message(shared_key, &identity);
    let sender_key = derive_session_key(sender_spake, &receiver_msg).unwrap();
    let receiver_key = derive_session_key(receiver_spake, &sender_msg).unwrap();
    
    // 4. Encrypt compressed data in chunks
    let chunk_size = 500;
    let mut encrypted_chunks = Vec::new();
    for (idx, chunk) in compressed.chunks(chunk_size).enumerate() {
        let encrypted = encrypt_chunk(&sender_key, chunk, idx as u64).unwrap();
        encrypted_chunks.push(encrypted);
    }
    
    // 5. Decrypt chunks
    let mut decrypted_data = Vec::new();
    for (idx, encrypted_chunk) in encrypted_chunks.iter().enumerate() {
        let decrypted = decrypt_chunk(&receiver_key, encrypted_chunk, idx as u64).unwrap();
        decrypted_data.extend_from_slice(&decrypted);
    }
    
    // 6. Verify decrypted data matches original compressed data
    assert_eq!(decrypted_data, compressed);
    
    // 7. Decompress
    let dest_dir = temp_base.join("destination");
    decompress_folder(&decrypted_data, &dest_dir).unwrap();
    
    // 8. Verify final result
    let final_file = dest_dir.join("data.txt");
    assert!(final_file.exists());
    let content = fs::read_to_string(final_file).unwrap();
    assert_eq!(content, "Important data that will be compressed and encrypted");
    
    // Cleanup
    let _ = fs::remove_dir_all(&temp_base);
}

// ============================================================================
// Boundary and Edge Case Tests
// ============================================================================

#[test]
fn test_maximum_room_number() {
    // Test with maximum valid 6-digit key
    let max_key = 999999u32;
    let room = max_key / 100;
    
    let init = Init {
        is_sender: true,
        room,
        local_addr: None,
    };
    
    assert_eq!(init.room, 9999);
}

#[test]
fn test_minimum_room_number() {
    // Test with minimum valid 6-digit key
    let min_key = 100000u32;
    let room = min_key / 100;
    
    let init = Init {
        is_sender: false,
        room,
        local_addr: None,
    };
    
    assert_eq!(init.room, 1000);
}

#[test]
fn test_metadata_with_unicode_filename() {
    let metadata = generate_metadata(
        "файл.txt".to_string(), // Russian characters
        1024,
        false
    );
    
    assert_eq!(metadata.filename, "файл.txt");
    
    // Test serialization with unicode
    let serialized = bincode::serialize(&metadata).unwrap();
    let deserialized: FileMetadata = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.filename, "файл.txt");
}

#[test]
fn test_empty_folder_compression_metadata() {
    let temp_dir = std::env::temp_dir().join(format!("test_empty_meta_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    
    let compressed = compress_folder(&temp_dir).unwrap();
    let metadata = generate_metadata("empty_folder".to_string(), compressed.len() as u64, true);
    
    assert!(metadata.is_folder);
    assert!(metadata.file_size > 0); // Even empty zip has some bytes
    
    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}
