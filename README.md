# distrans - Distributed File Transfer CLI

A secure, peer-to-peer file transfer tool with relay fallback support.

## Installation

### Building from Source

```bash
cargo build --release
```

The binary will be available at `./target/release/distrans`.

### Install Globally (Optional)

```bash
# Copy to a directory in your PATH
sudo cp target/release/distrans /usr/local/bin/

# Or use cargo install (if in a git repo)
cargo install --path .
```

## Usage

The CLI provides three main commands: `send`, `receive`, and `relay`.

### Send a File or Folder

```bash
# Send a file
distrans send path/to/file.txt

# Send a folder (automatically compressed)
distrans send path/to/folder

# Send with verbose logging
distrans send path/to/file.txt --verbose
```

When you run the send command:
1. A 6-digit shared key is generated and copied to your clipboard
2. The tool connects to the relay server
3. File/folder is encrypted and transferred
4. Share the key with the receiver

### Receive a File or Folder

```bash
# Receive (will prompt for key)
distrans receive

# Receive with key provided
distrans receive 123456

# Receive with verbose logging
distrans receive 123456 --verbose
```

When you run the receive command:
1. Enter the 6-digit shared key (or provide it as argument)
2. The tool connects to the relay server
3. File/folder is received and decrypted
4. Output is saved with `new_` prefix

### Run as Relay Server

```bash
# Run relay on default port (8080)
distrans relay

# Run relay on custom port
distrans relay --port 9000

# Run relay with verbose logging
distrans relay --verbose
```

## Command Reference

### Global Options

- `-v, --verbose` - Enable verbose logging (shows debug information)
- `-h, --help` - Print help information
- `-V, --version` - Print version information

### `distrans send`

**Usage:** `distrans send [OPTIONS] <FILE_PATH>`

**Arguments:**
- `<FILE_PATH>` - Path to the file or folder to send

**Options:**
- `-v, --verbose` - Enable verbose logging

**Example:**
```bash
# Send a file normally
distrans send document.pdf

# Send with detailed logs
distrans send document.pdf --verbose

# Send a folder (will be compressed automatically)
distrans send ./my-project
```

### `distrans receive`

**Usage:** `distrans receive [OPTIONS] [KEY]`

**Arguments:**
- `[KEY]` - Optional 6-digit shared key (will prompt if not provided)

**Options:**
- `-v, --verbose` - Enable verbose logging

**Example:**
```bash
# Receive with prompt
distrans receive

# Receive with key directly
distrans receive 123456

# Receive with verbose output
distrans receive 123456 --verbose
```

### `distrans relay`

**Usage:** `distrans relay [OPTIONS]`

**Options:**
- `-p, --port <PORT>` - Port to bind to (default: 8080)
- `-v, --verbose` - Enable verbose logging

**Example:**
```bash
# Run on default port
distrans relay

# Run on custom port
distrans relay --port 9000

# Run with verbose logging
distrans relay --verbose
```

## Verbose Logging

When you use the `--verbose` flag (or `-v`), you'll see detailed information about:

- Connection establishment (relay and P2P attempts)
- PAKE handshake details
- Chunk processing (encryption/decryption)
- File compression/decompression
- Network operations
- Error details

**Example verbose output:**
```bash
$ distrans send test.txt --verbose
[2024-10-19T10:30:45Z INFO  distrans] Verbose logging enabled
[2024-10-19T10:30:45Z DEBUG distrans::commands::send] Starting send command for path: test.txt
[2024-10-19T10:30:45Z DEBUG distrans::commands::send] Generated shared key: 123456, room: 1234
shared key (copied to clipboard): 123456
[2024-10-19T10:30:45Z INFO  distrans::commands::send] Connecting to relay server at 45.55.102.56:8080
[2024-10-19T10:30:45Z DEBUG distrans::networking] Establishing connection to relay server at 45.55.102.56:8080
Connected to relay server at 45.55.102.56:8080
[2024-10-19T10:30:45Z DEBUG distrans::commands::send] Performing PAKE handshake
...
```

## Features

- **Secure Transfer**: Uses PAKE (Password Authenticated Key Exchange) and ChaCha20-Poly1305 encryption
- **P2P Connection**: Attempts direct peer-to-peer connection with automatic relay fallback
- **Folder Support**: Automatically compresses folders before transfer
- **Progress Bars**: Visual feedback during transfer
- **Clipboard Integration**: Shared key automatically copied to clipboard
- **Flexible CLI**: Multiple ways to use each command

## Technical Details

- **Encryption**: ChaCha20-Poly1305 AEAD cipher
- **Key Exchange**: SPAKE2 PAKE protocol
- **Chunk Size**: 1KB chunks for efficient streaming
- **Default Relay**: 45.55.102.56:8080

## Quick Start Example

### Terminal 1 (Sender):
```bash
$ distrans send document.pdf
shared key (copied to clipboard): 456789
Connected to relay server at 45.55.102.56:8080
P2P connection established, closing relay
Transfer Complete!
```

### Terminal 2 (Receiver):
```bash
$ distrans receive 456789
Connected to relay server at 45.55.102.56:8080
P2P connection established, closing relay
Download complete!
File saved: new_document.pdf
```

## Development

### Running in Development

```bash
# Send
cargo run -- send test.txt

# Receive
cargo run -- receive 123456

# Relay
cargo run -- relay --verbose
```

## Troubleshooting

### P2P Connection Failed

If P2P connection fails, the tool automatically falls back to relay connection. This is normal for networks with strict NAT/firewall rules.

### Connection Timeout

Ensure the relay server is accessible and running. Check your network connection.

### Verbose Mode for Debugging

Always use `--verbose` flag when troubleshooting issues to see detailed logs.
