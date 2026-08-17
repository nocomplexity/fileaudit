# TarGz Validations 

## Why security checks are needed

`TAR.GZ` archives can embed zip bombs, path-traversal payloads (`../`), oversized members, symlinks, device nodes, or excessively deep directory trees. Validating an archive *before* extraction or further processing prevents resource exhaustion, arbitrary file writes, and other attacks that would otherwise occur only at extraction time.

## Capabilities

The validator enforces configurable limits on:

- compressed file size
- GZip decompression ratio (zip-bomb protection)
- number of TAR members
- total extracted size
- individual file size
- filename / path length
- directory nesting depth

The validator also has the capabilities to reject or protect:

- **Path Traversal Protection**  
   The function validates member names against a temporary base path to ensure nothing escapes the intended extraction directory. So it prevents extracting outside target directory.

- **Special Files Rejected**     
   The function also rejects symlinks/hardlinks/devices/FIFOs” in `tar.gz` files.



## How to use the checks

**Decorator mode** – validate the path argument of a function before it runs:

```python
@validate_tar_gz
def process(archive_path):
    ...

@validate_tar_gz(max_tar_members=50, max_file_size=10_000_000)
def process(archive_path):
    ...
```

**Direct / CLI mode** – validate immediately and obtain a boolean result:

```python
ok = validate_tar_gz("data.tar.gz", max_uncompressed_ratio=20)
```
Failures raise `TarValidationError` in decorator mode and return False (with a printed message) in direct mode.
