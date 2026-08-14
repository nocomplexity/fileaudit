# How to use this module

This Python module performs security audits on various types of files.

## Supported file types

| Extension | Description          |
|-----------|----------------------|
| `csv`     | CSV files            |
| `gz`      | GZIP files           |
| `json`    | JSON files           |
| `py`      | Python source files  |
| `tar`     | TAR archives         |
| `tar-gz`  | TAR.GZ archives      |
| `tgz`     | TAR.GZ archives      |
| `xml`     | XML files            |
| `zip`     | ZIP archives         |

## API usage

Each file type has its own validation function (for example `validate_csv`, `validate_tar_gz`, etc.).

Every validator supports two modes of operation:

1. **Decorator mode** — Wrap a function so that the file is validated before the function body runs:

   ```python
   @validate_tar_gz
   def process(path):
       ...
   ```

2. **Direct call** — Validate a file immediately and receive a boolean result:

   ```python
   is_safe = validate_tar_gz("archive.tar.gz")
   ```

Regardless of the filetype, all essential security checks that are always required are performed automatically.

For the full list of available options and configuration parameters, see the API documentation.

## CLI usage

The command-line interface works with every supported filetype and provides a simple way to inspect files from a security perspective.

File type detection is automatic. You can also specify the type explicitly with the `--type` option:

```bash
fileaudit path/to/file
fileaudit path/to/file --type tar-gz
```

For most supported filetypes also remote file locations starting with `https` is supported.

```
Python File Audit - Secure your programs with one simple command.
Usage:
  fileaudit <command> [options]

Commands:
  check <FILE|URL> [--type TYPE]  Run a security audit on a local file or HTTPS URL
  version                        Print version and exit
  help                           Show this help

Options for check:
  --type TYPE                    Force file type instead of auto-detection
Supported types (auto-detected from extension):
  csv          CSV files
  gz           GZIP files
  json         JSON files
  py           Python source files
  tar          TAR archives
  tar-gz       TAR.GZ archives
  tgz          TAR.GZ archives
  xml          XML files
  zip          ZIP archives

Examples:
  fileaudit check app.py
  fileaudit check data.json
  fileaudit check https://example.com/archive.zip
  fileaudit check unknown.dat --type json
```