# ZIP Validations

## Why Security Checks Are Needed Before Processing ZIP Files

Processing untrusted ZIP archives without validation can lead to:

- **Zip bombs** (excessive compression ratios causing resource exhaustion)
- **Path traversal attacks** (`../` paths escaping extraction directory)
- **Denial of service** (massive member counts, total extracted sizes, or individual file sizes)
- **Encrypted archives** (bypassing security scanning)
- **Unsupported compression methods** (causing application crashes)
- **Unicode normalization attacks** (duplicate filenames exploiting filesystem behaviors)
- **Special file exploitation** (symlinks, devices, FIFOs)

## Capabilities

The `validate_zip` function performs comprehensive security checks:

| Check | Description |
|-------|-------------|
| **Compressed Size** | Enforces maximum archive file size (bytes) |
| **Member Count** | Limits number of entries in the archive |
| **Total Extracted Size** | Prevents zip bombs with inflated total decompressed size |
| **Individual File Size** | Caps size per extracted file |
| **Decompression Ratio** | Rejects files with excessive compression ratios (e.g., >100x) |
| **Path Traversal** | Rejects absolute paths, `..`, `.`, backslashes, and drive letters |
| **Filename Length** | Limits encoded path length (UTF-8 bytes) |
| **Directory Depth** | Prevents excessive directory nesting |
| **Duplicate Detection** | Identifies duplicate filenames after Unicode normalization |
| **NUL Byte Rejection** | Blocks filenames containing NUL characters |
| **Symlink/Device Rejection** | Blocks symbolic links and special device files |
| **Encryption Detection** | Rejects encrypted ZIP entries |
| **Compression Validation** | Rejects unsupported compression methods |
| **Remote File Restriction** | Strictly restricts remote access to HTTPS only |

## How the Checks Can Be Used

The function operates in three modes:

### 1. Direct Call / CLI Mode

```python
# Validate a local ZIP file
result = validate_zip("path/to/archive.zip", max_zip_members=1000)

# Validate remote file (HTTPS only)
result = validate_zip("https://example.com/archive.zip", max_file_size=100*1024*1024)

# Returns True if valid, False if invalid (errors printed to stdout)
```

### 2. Decorator Mode

```python
# Bare decorator (uses default limits)
@validate_zip
def extract_data(archive_path):
    # ZIP already validated before function body runs
    return process(archive_path)

# Decorator with custom limits
@validate_zip(
    max_file_size=500*1024*1024,
    max_zip_members=5000,
    max_uncompressed_ratio=50
)
def extract_secure(file_input):
    return safe_extract(file_input)

# Explicit argument name targeting
@validate_zip("zip_path", max_individual_file_size=10*1024*1024)
def process_file(zip_path):
    return handle_archive(zip_path)
```

### 3. Factory Mode (Preconfigured Validator)

```python
# Create a reusable validator with custom defaults
zip_validator = validate_zip(
    max_total_extracted_size=1*1024*1024*1024,
    max_zip_members=100,
    max_directory_depth=10
)

@zip_validator
def process_small_archive(archive_path):
    # Uses preconfigured limits
    return handle_small(archive_path)
```


### Return Values

| Mode | Returns |
|------|---------|
| **Direct Call** | `True` if valid, `False` if invalid (errors printed to stdout) |
| **Decorator** | Wrapped function (raises `ZipValidationError` on failure) |


### Exceptions

- **`ZipValidationError`**: Raised when validation fails (decorator mode only)
- **`zipfile.BadZipFile`**: Propagated from invalid or corrupt ZIP files
- **`FileNotFoundError`**, **`PermissionError`**: Propagated from file operations
- **`urllib.error.URLError`**, **`urllib.error.HTTPError`**: Propagated from remote operations