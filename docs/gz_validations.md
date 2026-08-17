# GZ Validations 

## Why Security Checks Are Needed Before Processing GZip Files

Processing untrusted GZip files without validation can lead to:

- **Zip bombs** (extreme decompression ratios causing resource exhaustion)
- **Denial of service** (massive uncompressed sizes consuming memory/disk)
- **Path traversal** (symbolic links escaping the intended extraction directory)
- **TOCTOU attacks** (file modification during validation)
- **Remote file abuse** (malicious servers serving oversized or malformed files)
- **Corrupted/malformed data** (invalid GZip CRC, trailers, or concatenated members causing crashes)

## Capabilities

The `validate_gz` function performs comprehensive security checks:

| Check | Description |
|-------|-------------|
| **Compressed Size** | Enforces maximum archive file size (bytes) |
| **Uncompressed Size** | Limits total decompressed output to prevent bombs |
| **Decompression Ratio** | Rejects files with excessive compression ratios (e.g., >100x) |
| **Streaming Validation** | Decompresses incrementally without loading entire file into memory |
| **GZip Format Validation** | Validates CRC, trailer, and concatenated members |
| **Symlink Protection** | Rejects symbolic links (O_NOFOLLOW support where available) |
| **Regular File Enforcement** | Ensures local paths are regular files (not directories, devices, etc.) |
| **TOCTOU Detection** | Detects file size changes during validation (local files) |
| **Remote File Restriction** | Strictly restricts remote access to HTTPS only |

## How the Checks Can Be Used

The function operates in three modes:

### 1. Direct Call / CLI Mode

```python
# Validate a local GZip file
result = validate_gz("path/to/file.gz", max_uncompressed_size=1000000)

# Validate remote file (HTTPS only)
result = validate_gz("https://example.com/file.gz", max_file_size=10*1024*1024)

# Returns True if valid, False if invalid (validation errors printed to stdout)
```

### 2. Decorator Mode

```python
# Bare decorator (uses default limits)
@validate_gz
def decompress_data(file_path):
    # File already validated before function body runs
    return process_gzip(file_path)

# Decorator with custom limits
@validate_gz(max_file_size=5_000_000, max_uncompressed_ratio=50)
def decompress_secure(file_input):
    return safe_decompress(file_input)

# Explicit argument name targeting
@validate_gz("input_path", max_uncompressed_size=100*1024*1024)
def process_file(input_path):
    return handle_decompressed_data(input_path)
```

### 3. Factory Mode (Preconfigured Validator)

```python
# Create a reusable validator with custom defaults
gz_validator = validate_gz(
    max_file_size=10*1024*1024,
    max_uncompressed_ratio=100,
    max_uncompressed_size=500*1024*1024
)

@gz_validator
def process_large_gzip(archive_path):
    # Uses preconfigured limits
    return handle_large(archive_path)
```

