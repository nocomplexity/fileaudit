# JSON Validation

## Why Security Checks Are Needed

Be cautious when parsing JSON data from untrusted sources or third parties. From a zero trust principle you **SHOULD** always verify all input.

:::{warning} 
[A malicious JSON string may cause the decoder to consume considerable CPU and memory resources. Limiting the size of data to be parsed is recommended.](https://docs.python.org/3/library/json.html)
:::

- JSON files from untrusted sources can cause resource exhaustion or crashes.
- Excessive nesting depth can trigger stack overflows or recursive parsing attacks.
- Very large files can consume excessive memory or CPU.
- Validating size and structure before processing mitigates these risks.


## Capabilities

`validate_json` provides configurable protection against common JSON risks:

- **Nesting depth limit** — rejects excessively deep structures (prevents stack/recursion attacks)
- **File size limit** — rejects oversized files before full loading (prevents resource exhaustion); remote files are size-checked via HEAD and streamed with a hard byte cap
- **Strict UTF-8 encoding** — only valid UTF-8 content is accepted; non-UTF-8 data raises a validation error
- **HTTPS-only remote access** — local paths, `pathlib.Path` objects, and HTTPS URLs are supported; other schemes are rejected
- **Network timeouts** — remote requests use explicit timeouts (10 s for HEAD size check, 30 s for GET download) to avoid hanging on unresponsive servers
- **Dual usage modes** — direct validation (returns `True`/`False`) or decorator that guards a function argument and raises `FileValidationError` on failure

## How to Use

**Direct validation** (returns `True`/`False`):

```python
validate_json("data.json")
```

```python
validate_json("https://example.com/data.json", max_depth=10)
```

**As a decorator** (raises FileValidationError on failure):

```python
@validate_json
def process_json(file_path):
    ...
```

```python
@validate_json(max_depth=50, max_file_size=5000)
def process_json(file_path):
    ...
```

```python
@validate_json("config_path", max_depth=10)
def process_json(config_path, other_arg):
    ...
```


:::{note} 
JSON Schema checks are **not covered**! This is application specific and not considered as a general security validation.
:::