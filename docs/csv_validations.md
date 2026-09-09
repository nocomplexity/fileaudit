# CSV Validation

## Why Security Checks Are Needed

The Comma Separated Values (CSV) file format is the most common import format for spreadsheets and databases. But loading `csv` files can result in a security nightmare.


CSV files from untrusted sources can trigger security issues or resource exhaustion.
Formula injection (cells starting with `=`, `+`, `-`, or `@`) can execute code when opened in spreadsheets.
Control characters may cause parsing failures or injection attacks.
Unbounded size, row count, column count, or field length can lead to denial-of-service.

Validating before processing mitigates these risks.

## Capabilities

`validate_csv` provides configurable protection against common CSV risks:

- **Size & resource limits** — file size, row count, column count, individual field size, total fields, row size, and filename length (prevents resource exhaustion and oversized records)
- **Content safety** — rejects dangerous spreadsheet formulas (formula injection) and disallowed control characters
- **Encoding control** — configurable character encoding (default UTF-8)
- **Flexible input** — local paths, `pathlib.Path` objects, and URLs
- **Dual usage modes** — direct validation (returns `True`/`False`) or decorator that guards a function argument and raises `CsvValidationError` on failure


## Usage Options

### Parameters

| Parameter                  | Description                                      |
|----------------------------|--------------------------------------------------|
| `func_or_path`             | Path or callable for the CSV file.               |
| `max_file_size`            | Max size of the CSV file.                        |
| `max_rows`                 | Max number of rows.                              |
| `max_columns`              | Max number of columns.                           |
| `max_field_size`           | Max size of any single field.                    |
| `max_total_fields`         | Max total number of fields.                      |
| `max_row_size`             | Max size of any single row.                      |
| `max_filename_length`      | Max length of the filename.                      |
| `reject_formula_injection` | Reject cells that look like formulas.            |
| `reject_control_characters`| Reject control characters in fields.             |
| `encoding`                 | File encoding (default: utf-8).                  |
| `dialect`                  | CSV dialect (default: excel).                    |


### Defaults

```bash
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024       # 10 MB
DEFAULT_MAX_ROWS = 100_000
DEFAULT_MAX_COLUMNS = 1_000
DEFAULT_MAX_FIELD_SIZE = 1 * 1024 * 1024       # 1 MB
DEFAULT_MAX_TOTAL_FIELDS = 10_000_000
DEFAULT_MAX_ROW_SIZE = 5 * 1024 * 1024         # 5 MB
DEFAULT_MAX_FILENAME_LENGTH = 255
DEFAULT_REMOTE_TIMEOUT = 30
DEFAULT_READ_CHUNK_SIZE = 64 * 1024
```


## How to Use

**Direct validation** (returns `True`/`False`):

```python
validate_csv("data.csv")
validate_csv("https://example.com/data.csv")
```

**As a decorator** (raises `CsvValidationError` on failure):

```python
@validate_csv
def process_csv(csv_path):
    ...

@validate_csv(max_file_size=10*1024*1024, max_rows=10_000)
def process_csv(csv_path):
    ...

@validate_csv("input_file")
def process_csv(input_file):
    ...
```
