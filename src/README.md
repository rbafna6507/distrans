# Distrans Source Code Structure

This document provides an overview of the `distrans` codebase organization and module responsibilities.

## Directory Structure

```
src/
├── lib.rs                 # Library root with constants and module declarations
├── main.rs               # CLI entry point
├── bytes.rs              # File I/O, chunking, compression utilities
├── cryptography.rs       # Encryption/decryption and key exchange
├── networking.rs         # TCP connections, P2P hole punching, PAKE
├── relay_utils.rs        # Relay server connection management
├── utils.rs              # Data structures (Init, FileMetadata, etc.)
└── commands/
    ├── mod.rs           # Commands module with documentation
    ├── send.rs          # Sender command implementation
    ├── receive.rs       # Receiver command implementation
    └── relay.rs         # Relay server command implementation
```

## Module Descriptions

### Core Modules

#### `lib.rs`
- Central library file that exports all public modules
- Defines global constants (KEY_SIZE, CHUNK_SIZE, etc.)
- Contains comprehensive module-level documentation

#### `main.rs`
- CLI entry point using `clap` for argument parsing
- Dispatches to appropriate command handlers (send/receive/relay)
- Configures logging based on verbosity flags

### Data Processing Modules

#### `bytes.rs`
File manipulation and data chunking operations:
- **Chunking**: `read_chunk()` - Reads data in 1008-byte chunks (leaving room for encryption overhead)
- **Compression**: `compress_folder()` - Creates in-memory zip archives of directories
- **Decompression**: `decompress_folder()` - Extracts zip archives to disk
- **Utilities**: Key generation, metadata creation, file writers

#### `cryptography.rs`
Cryptographic operations for secure transfers:
- **Key Exchange**: SPAKE2-based PAKE for deriving shared encryption keys
- **Encryption**: ChaCha20-Poly1305 AEAD with per-chunk nonces
- **Authentication**: 16-byte Poly1305 tags ensure data integrity
- All encryption uses chunk index as nonce to prevent replay attacks

### Networking Modules

#### `networking.rs`
Connection management and data transfer:
- **Connection Setup**: `establish_connection()` - Connects to relay and attempts P2P
- **P2P Hole Punching**: `attempt_p2p_connection()` - Uses SO_REUSEPORT for NAT traversal
- **PAKE Handshake**: `perform_pake()` - Establishes authenticated encryption keys
- **Metadata Exchange**: Functions to send/receive file information
- **Chunk I/O**: Read chunk sizes and encrypted data from network

#### `relay_utils.rs`
Relay server state management:
- **ConnectionManager**: Central coordinator for all relay operations
- **Room Management**: Groups senders and receivers by shared key
- **P2P Coordination**: Exchanges peer addresses and triggers connection attempts
- **Relay Mode**: Proxies data bidirectionally if P2P fails
- **Connection Handling**: Processes initial client handshakes

### Command Modules (`commands/`)

#### `send.rs`
Implements the sender workflow:
1. Generate random 6-digit shared key
2. Connect to relay and attempt P2P with receiver
3. Perform PAKE handshake
4. Compress folder (if needed)
5. Spawn chunking/encryption task
6. Spawn sending task
7. Stream encrypted chunks to receiver

#### `receive.rs`
Implements the receiver workflow:
1. Get shared key from user
2. Connect to relay and attempt P2P with sender
3. Perform PAKE handshake
4. Receive file metadata
5. Spawn receiving/decryption task
6. Spawn writing task (file or folder)
7. Save received data to disk

#### `relay.rs`
Implements the relay server:
- Binds TCP listener on specified port
- Spawns ConnectionManager for state management
- Spawns per-connection handler tasks
- Coordinates room creation and peer matching

### Utility Modules

#### `utils.rs`
Data structures and helper types:
- **Init**: Message sent to relay (sender/receiver status, room, local address)
- **FileMetadata**: File information (name, size, is_folder)
- **PeerAddresses**: Peer's external and local addresses for P2P
- **CLI parsers**: Argument parsing structs

## Data Flow

### Sender Flow
```
File → Compress (if folder) → Chunk → Encrypt → Send over TCP
```

### Receiver Flow
```
TCP → Receive chunks → Decrypt → Write to disk / Decompress folder
```

### Relay Flow
```
Client1 → Relay (exchange addresses) → Trigger P2P
Client2 → Relay (exchange addresses) → Trigger P2P
If P2P fails → Relay proxies data between clients
```

## Key Design Patterns

### Async Architecture
- Uses Tokio for async I/O and task spawning
- Channels (`mpsc`) for producer-consumer patterns between tasks
- Tasks run concurrently (e.g., chunking + encryption while sending)

### Security Model
- PAKE (SPAKE2) ensures only peers with shared key can communicate
- ChaCha20-Poly1305 provides authenticated encryption
- Each chunk has unique nonce (derived from chunk index)
- No plaintext data ever touches the network

### P2P Optimization
- Attempts direct connection first (lower latency, higher throughput)
- Falls back to relay if P2P fails (ensures reliability)
- LAN detection for optimal local network transfers

## Constants and Configuration

All constants are defined in `lib.rs`:
- `KEY_SIZE = 32`: ChaCha20 key size
- `NONCE_SIZE = 12`: ChaCha20 nonce size
- `CHUNK_SIZE = 1024`: Base chunk size
- `ENCRYPTION_OVERHEAD = 16`: Poly1305 tag size
- `ENCRYPTION_ADJUSTED_CHUNK_SIZE = 1008`: Plaintext chunk size
- `RELAY_ADDR`: Default relay server address

## Testing

Unit tests should be added to each module to verify:
- Encryption/decryption round-trips
- Chunk size handling
- Compression/decompression
- PAKE key derivation
- Connection state management

## Future Enhancements

Potential areas for improvement:
- Resume capability for interrupted transfers
- Multiple file transfer in one session
- Progress callbacks for GUI integration
- Configurable chunk sizes for different network conditions
- IPv6 support improvements
