# Quick Start Guide - Folder Transfer

## Setup

The folder transfer feature is now fully integrated! No additional setup required beyond the existing dependencies (`walkdir` and `zip` are already in Cargo.toml).

## Quick Test

### Step 1: Create a test folder
```bash
./test_folder_transfer.sh
```

This creates a `test_folder/` with sample files and subdirectories.

### Step 2: Send the folder (Terminal 1)
```bash
cargo run --bin sender test_folder
```

You'll see:
```
Compressing folder: test_folder
Adding file: test_folder/file1.txt
Adding directory: test_folder/subfolder1/
Adding file: test_folder/subfolder1/file2.txt
...
shared key (copied to clipboard): 123456
Connected to relay server at ...
P2P connection established, closing relay
Transfer Complete!
```

### Step 3: Receive the folder (Terminal 2)
```bash
cargo run --bin receiver 123456
```

You'll see:
```
Connected to relay server at ...
P2P connection established, closing relay
Receiving folder: test_folder
Download complete, extracting...
Extracting 4 files/folders...
Creating directory: "new_test_folder"
Extracting file: "new_test_folder/file1.txt"
...
Folder extraction complete: new_test_folder
Done!
```

### Step 4: Verify
```bash
diff -r test_folder new_test_folder
# Should show no differences!

tree new_test_folder
# Shows the complete folder structure
```

## Real World Usage

### Send your project folder
```bash
cargo run --bin sender ~/my_project
```

### Send configuration directories
```bash
cargo run --bin sender ~/.config/nvim
```

### Send any folder structure
```bash
cargo run --bin sender /path/to/any/folder
```

## Features Working

✅ Files and folders are compressed (saves bandwidth)
✅ Full encryption during transfer
✅ Directory structure preserved
✅ File permissions preserved (Unix systems)
✅ Progress indicators
✅ P2P connection with relay fallback
✅ PAKE authentication

## Notes

- The receiver creates a folder with "new_" prefix
- Empty directories are preserved
- Symbolic links are followed (copied as regular files)
- Binary files work perfectly
- Text files preserve line endings

## File Transfer Still Works!

Regular file transfers work exactly as before:
```bash
# Send a single file
cargo run --bin sender video.mp4

# Receive it
cargo run --bin receiver 123456
```

The utility automatically detects whether you're sending a file or folder!
