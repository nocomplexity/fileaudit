# XML Validations 

## Why Processing XML Files is dangerous

Processing untrusted XML files without validation can lead to:

- **Billion Laughs Attack** (exponential entity expansion causing memory exhaustion)
- **Deep Nesting Attacks** (extreme nesting depth causing stack overflows)
- **Attribute Bomb** (excessive attributes per element causing DoS)
- **Large Text Nodes** (massive text or attribute values consuming memory)
- **DTD/DOCTYPE Attacks** (external entity resolution, XXE, and internal DTD bombs)
- **GZip Bomb** (compressed XML with extreme decompression ratios)
- **Malformed XML** (causing parser crashes or infinite loops)



## The Problem: Python's XML Parsers are Vulnerable by Default

Python's standard XML parsers are vulnerable to numerous attacks:

```python
import xml.etree.ElementTree as ET

# This Billion Laughs attack will consume all memory
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
Good protection before parsing XML files in Python is vital!
The default Python parser is vulnerable. Also AI generated code is not secure by design!
:::

:::{tip}
**Python FileAudit makes XML processing secure by default!**
:::

## Capabilities

DDoS Protection Features:

- **Document Size Limiting**: Enforces maximum file size to prevent memory exhaustion
- **Deep Nesting Protection**: Limits XML element nesting depth to prevent stack overflow
- **Element Count Limiting**: Caps total number of elements in the document
- **Attribute Explosion Protection**: Limits maximum attributes per element
- **Text Node Size Protection**: Enforces maximum length for text nodes and attribute values
- **Name Length Validation**: Limits length of element and attribute names

Security Features:

- **DOCTYPE Rejection**: Blocks all DTD/DOCTYPE declarations (prevents XXE and entity attacks)
- **External Entity Blocking**: DOCTYPE rejection eliminates external entity resolution risk
- **Element and Attribute Count Limits**: Prevents resource exhaustion through excessive elements/attributes
- **Depth Limiting**: Prevents stack overflow from deeply nested XML
- **Name Length Validation**: Prevents buffer overflows from extremely long names
- **Text Length Validation**: Prevents memory exhaustion from oversized text/attribute values
- **UTF-8 Strict Validation**: Rejects files with invalid UTF-8 encoding
- **GZip Compression Handling**: Supports compressed XML with size limits during decompression
- **Remote HTTPS-Only Support**: Strictly restricts remote files to HTTPS URLs only


The `validate_xml` function performs comprehensive security checks:

| Check | Description |
|-------|-------------|
| **Max File Size** | Enforces maximum XML file size (bytes) |
| **Max Nesting Depth** | Prevents deeply nested elements causing stack overflow |
| **Max Elements** | Limits total element count to prevent DoS |
| **Max Attributes** | Caps attributes per element |
| **Max Text Length** | Limits text node and attribute value sizes |
| **Max Name Length** | Limits element and attribute name lengths |
| **DOCTYPE Rejection** | Blocks DTD declarations (XXE, entity expansion) |
| **GZip Support** | Handles compressed XML with size limits |
| **UTF-8 Validation** | Rejects files with invalid UTF-8 encoding |
| **Remote File Restriction** | Strictly restricts remote access to HTTPS only |
| **Parser Hardening** | Uses protection methods against known XML attacks |

## How the Checks Can Be Used

The function operates in three modes:

### 1. Direct Call / CLI Mode

```python
# Validate a local XML file
result = validate_xml("path/to/file.xml", max_depth=50)

# Validate remote file (HTTPS only)
result = validate_xml("https://example.com/data.xml", max_file_size=10*1024*1024)

# Returns True if valid, False if invalid (errors printed to stdout)
```

### 2. Decorator Mode

```python
# Bare decorator (uses default limits)
@validate_xml
def process_data(file_path):
    # XML already validated before function body runs
    return parse_xml(file_path)

# Decorator with custom limits
@validate_xml(
    max_depth=100,
    max_attributes=50,
    max_elements=10000,
    max_text_length=1024*1024
)
def process_secure_xml(xml_file):
    return handle_secure(xml_file)

# Explicit argument name targeting
@validate_xml("config_path", max_name_length=255)
def load_config(config_path):
    return parse_config(config_path)
```

### 3. Factory Mode (Preconfigured Validator)

```python
# Create a reusable validator with custom defaults
xml_validator = validate_xml(
    max_depth=20,
    max_file_size=5*1024*1024,
    max_elements=5000,
    max_attributes=20
)

@xml_validator
def process_small_xml(file_path):
    # Uses preconfigured limits
    return handle_small(file_path)
```

