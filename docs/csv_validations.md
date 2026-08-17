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
