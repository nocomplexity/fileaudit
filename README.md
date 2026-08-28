# Python File Audit


[![PythonCodeAudit Badge](https://img.shields.io/badge/Python%20Code%20Audit-Security%20Verified-FF0000?style=flat-square)](https://github.com/nocomplexity/codeaudit)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14110/badge)](https://www.bestpractices.dev/projects/14110)
[![PyPI - Version](https://img.shields.io/pypi/v/fileaudit.svg)](https://pypi.org/project/fileaudit)
[![Documentation](https://img.shields.io/badge/Python%20File%20Audit%20Manual-Available-blue)](https://nocomplexity.github.io/fileaudit/)
[![License](https://img.shields.io/badge/License-MPL--2.0-FFD700)](https://github.com/nocomplexity/fileaudit/blob/main/docs/license.md)

File Audit – Simplify Python Security by adding one line!
**Build secure Python applications by default. Validate files before you use them.**

A robust file-validation library designed to protect your Python applications and scripts against untrusted or malicious files. 


## Safety Checks

- **File size limit** – Prevents oversized files from being processed
- **GZip decompression ratio** – Guards against decompression bombs
- **Tar member count** – Limits the number of entries inside tar archives
- **Total extracted size** – Caps the overall size of extracted content
- **Individual file size** – Enforces a maximum size per extracted file
- **Path traversal protection** – Blocks `../` and absolute path tricks
- **Reject symlinks** – Disallows symbolic links
- **Reject hardlinks** – Disallows hard links
- **Reject device files** – Blocks device nodes
- **Reject FIFOs** – Blocks named pipes
- **Filename length** – Enforces a maximum filename length
- **Directory depth** – Limits how deeply nested directories can be

These checks can be used via a simple API or by adding a decorator — without changing your existing code.

## Installation

```bash
pip install fileaudit
```



## Installation

```bash
pip install fileaudit
```

## Usage

### API / Decorator (CSV example)

Validate a local CSV file:

```python
validate_csv("data.csv")
```

Validate a CSV file from a URL:

```python
validate_csv("https://example.com/data.csv")
```

Use as a decorator (first function argument is treated as the CSV path):

```python
@validate_csv
def process_csv(csv_path):
    ...
```

Use as a decorator with default validation options:

```python
@validate_csv()
def process_csv(csv_path):
    ...
```

Specify the decorated function argument that contains the CSV path:

```python
@validate_csv("input_file")
def process_csv(input_file):
    ...
```

Configure validation limits:

```python
@validate_csv(
    max_file_size=10 * 1024 * 1024,
    max_rows=10_000,
    max_columns=50,
)
def process_csv(csv_path):
    ...
```

### CLI

You can also inspect a file directly from the command line:

```bash
fileaudit path/to/file
```

## Supported File Types

File types are auto-detected from the extension:

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

---

Python File Audit helps you validate files before they reach your application logic, reducing the risk of common file-based attacks.

## Contributing

All contributions are welcome! Think of corrections on the documentation, code or more and better tests.

Simple Guidelines:

- Questions, Feature Requests, Bug Reports please use on the Github Issue Tracker.

**Pull Requests are welcome!**

When you contribute to FileAudit, your contributions are made under the same license as the file you are working on.

> [!NOTE]
> This is an open community driven project. Contributors will be mentioned in the [documentation](https://nocomplexity.com/documents/codeaudit/intro.html).

We adopt the [Collective Code Construction Contract(C4)](https://rfc.zeromq.org/spec/42/) to streamline collaboration.

## License

`fileaudit` is distributed under the terms of the [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/) license.


