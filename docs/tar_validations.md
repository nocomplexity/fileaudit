#  TAR Validations

## Why Security Validation is Critical for Tar Files

Processing untrusted TAR archives poses significant security risks:

- **Path Traversal**: Malicious TAR entries with `../` paths can overwrite sensitive system files
- **Resource Exhaustion**: Archive bombs with excessive members or inflated sizes can cause denial of service
- **System Resource Abuse**: Extreme total extraction sizes or individual file sizes can exhaust memory/disk
- **Symlink/Hardlink Attacks**: Links can point to sensitive files outside the extraction target
- **Device/FIFO Exploitation**: Device nodes or named pipes can cause system instability

## Capabilities

The `validate_tar` function performs comprehensive security checks:

| Check | Description |
|-------|-------------|
| **File Size** | Enforces maximum allowed archive file size |
| **Member Count** | Limits number of files/directories inside archive |
| **Total Extraction Size** | Prevents archive bombs through total extracted size limits |
| **Individual File Size** | Caps size per extracted file |
| **Path Traversal** | Prevents `../` and absolute path escapes |
| **Link Rejection** | Blocks symlinks, hardlinks, devices, and FIFOs |
| **Filename Length** | Limits path length to prevent buffer overflows |
| **Directory Depth** | Prevents excessive nesting that could exhaust inodes |
| **Remote File Restriction** | Only accepts `https://` URIs (strictly no `http://`, `ftp://`, `file://`) |

## Usage Modes

### 1. Direct Call / CLI Validation

```python
# Local file validation
valid = validate_tar("path/to/archive.tar", max_tar_members=100)

# Remote HTTPS validation
valid = validate_tar("https://example.com/archive.tar", max_file_size=10*1024*1024)

# Returns bool: True if valid, False if invalid (errors printed to stdout)
```

### 2. Decorator Mode

```python
from pathlib import Path

# Bare decorator (uses default limits)
@validate_tar
def process_archive(path: Path):
    # Archive already validated before function body executes
    return extract_content(path)

# Decorator with custom limits
@validate_tar(max_file_size=5_000_000, max_tar_members=50)
def process_secure_archive(file_path: str):
    # Secure validation with custom thresholds
    return handle_archive(file_path)

# Argument name targeting
@validate_tar("input_path", max_directory_depth=5)
def process_with_named_arg(input_path: str):
    # Validates the argument named 'input_path'
    return process(input_path)
```

### 3. Factory Mode

```python
# Create a preconfigured validator
validator = validate_tar(max_tar_members=10, max_individual_file_size=1024*1024)

@validator
def process_small_archive(tar_path: str):
    # Uses preconfigured limits
    return handle(tar_path)
```

### API Reference

```
validate_tar(
    func_or_path=None,           # Callable (decorator), str/Path (direct), or None (factory)
    max_file_size=None,          # Max archive file size (bytes)
    max_tar_members=None,        # Max number of entries in archive
    max_total_extracted_size=None, # Max total extracted bytes
    max_individual_file_size=None, # Max per-file extracted size
    max_filename_length=None,    # Max path length
    max_directory_depth=None     # Max directory nesting level
)
```
