# XML Validation

Secure XML file validation with built-in DDoS and XXE protection.

Python’s standard XML parsers (`xml.etree.ElementTree`, `xml.dom.minidom`, etc.) are **vulnerable by default**.  
FileAudit’s `validate_xml` makes XML processing safe by enforcing strict limits **before** any parsing occurs.

---

## Why Untrusted XML is Dangerous

Processing untrusted XML without protection can lead to:

| Attack | Impact |
|--------|--------|
| **Billion Laughs** | Exponential entity expansion → memory exhaustion |
| **Deep Nesting** | Extreme element nesting → stack overflow |
| **Attribute Bomb** | Too many attributes on one element → DoS |
| **Large Text Nodes** | Huge text/attribute values → memory exhaustion |
| **DTD / DOCTYPE** | XXE, external entity attacks, internal entity bombs |
| **GZip Bomb** | Extremely high decompression ratio |
| **Malformed XML** | Parser crashes or infinite loops |

```python
import xml.etree.ElementTree as ET

# This classic Billion Laughs payload will exhaust memory
billion_laughs = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  ...
]>
<lolz>&lol9;</lolz>"""

ET.fromstring(billion_laughs)  # 💀 Memory exhaustion
```

:::{warning}
The default Python XML parsers are **not** safe.  
AI-generated code that uses them is also unsafe by default.
:::

:::{tip}
**FileAudit makes XML processing secure by default.**
:::

---

## What `validate_xml` Protects Against

| Protection | Description |
|------------|-------------|
| Max file size | Prevents memory exhaustion from huge files |
| Max nesting depth | Prevents stack overflow |
| Max elements | Limits total number of elements |
| Max attributes per element | Stops attribute bombs |
| Max text / attribute length | Limits size of text nodes and attribute values |
| Max name length | Limits element and attribute name length |
| DOCTYPE rejection | Completely blocks DTD / entity attacks (XXE) |
| UTF-8 strict validation | Rejects invalid encoding |
| GZip support | Safely handles compressed XML with size limits |
| HTTPS-only remote files | Blocks `http://`, `ftp://`, protocol-relative URLs, etc. |

---

## Important: What It Accepts

`validate_xml` works **only on files** (local paths or remote HTTPS URLs).

| Input type | Supported? | Example |
|------------|------------|---------|
| Local file path | ✅ | `validate_xml("data.xml")` |
| Remote HTTPS URL | ✅ | `validate_xml("https://example.com/data.xml")` |
| Raw XML string / content | ❌ | `validate_xml("<root>...</root>")` **not supported** |
| File-like object / stream | ❌ | Not supported |

It does **not** accept in-memory XML content.  
You must give it a path or an HTTPS URL.

---

## Installation / Import

```python
from fileaudit import validate_xml
```

The function also raises a custom exception:

```python
from fileaudit import FileValidationError
```

---

## Default Limits

```python
DEFAULT_MAX_DEPTH         = 50
DEFAULT_MAX_FILE_SIZE     = 10 * 1024 * 1024   # 10 MB
DEFAULT_MAX_ATTRIBUTES    = 1000
DEFAULT_MAX_ELEMENTS      = 10_000
DEFAULT_MAX_TEXT_LENGTH   = 100_000            # 100 KB
DEFAULT_MAX_NAME_LENGTH   = 100

HEAD_TIMEOUT      = 10   # seconds (remote HEAD request)
DOWNLOAD_TIMEOUT  = 30   # seconds (remote download)
```

You can override any of these per call or via a pre-configured validator.

---

## Usage

### 1. Direct Call (CLI / script style)

```python
from fileaudit import validate_xml, FileValidationError

# Local file
try:
    validate_xml("path/to/file.xml")
    print("XML is safe")
except FileValidationError as e:
    print(e)

# Remote file (HTTPS only)
validate_xml(
    "https://example.com/data.xml",
    max_file_size=5 * 1024 * 1024,   # 5 MB
    max_depth=30
)

# Returns True on success, raises FileValidationError on failure
```

### 2. Decorator Mode

```python
from fileaudit import validate_xml

# Bare decorator (uses all defaults)
@validate_xml
def process_xml(file_path):
    # Validation already passed when this runs
    ...

# With custom limits
@validate_xml(max_depth=20, max_elements=2000, max_file_size=2*1024*1024)
def process_small_xml(file_path):
    ...

# Target a specific argument name
@validate_xml("config_path", max_name_length=64)
def load_config(config_path, other_arg):
    ...
```

### 3. Factory Mode (reusable pre-configured validator)

```python
from fileaudit import validate_xml

# Create a strict validator once
strict_xml = validate_xml(
    max_depth=15,
    max_file_size=1 * 1024 * 1024,   # 1 MB
    max_elements=1000,
    max_attributes=20,
    max_text_length=10_000
)

@strict_xml
def process_trusted_xml(path):
    ...

# You can also call the factory result directly
strict_xml("another-file.xml")
```

---

## Full Parameter Reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `func_or_path` | `str` / `Path` / `callable` / `None` | – | File path, URL, or function to decorate |
| `max_depth` | `int` | `50` | Maximum element nesting depth |
| `max_file_size` | `int` | `10 MB` | Maximum file size in bytes |
| `max_attributes` | `int` | `1000` | Maximum attributes per element |
| `max_elements` | `int` | `10 000` | Maximum total elements |
| `max_text_length` | `int` | `100 000` | Maximum length of text nodes / attribute values |
| `max_name_length` | `int` | `100` | Maximum length of element / attribute names |

---

## Error Handling

All validation failures raise `FileValidationError`:

```python
from fileaudit import validate_xml, FileValidationError

try:
    validate_xml("malicious.xml")
except FileValidationError as e:
    print(e)
    # Example output:
    # FileAudit Security Validation Failed - DOCTYPE declarations are not allowed.
```

---

## Security Notes

- **DOCTYPE is always rejected** — this completely eliminates classic XXE and entity-expansion attacks.
- Remote files are restricted to **HTTPS only**. HTTP, FTP, and protocol-relative URLs (`//example.com/...`) are blocked.
- Redirects to non-HTTPS locations are also blocked.
- GZip-compressed files are supported, but the *decompressed* size is still limited.
- The validator uses an iterative (non-recursive) tree walk to avoid stack overflows even on deeply nested documents.

---

## Quick Start Example

```python
from fileaudit import validate_xml, FileValidationError

def safe_load_xml(path: str):
    try:
        validate_xml(path, max_depth=40, max_file_size=5*1024*1024)
        # Now it is safe to parse with the standard library
        import xml.etree.ElementTree as ET
        return ET.parse(path)
    except FileValidationError as e:
        raise ValueError(f"Rejected unsafe XML: {e}") from e
```
