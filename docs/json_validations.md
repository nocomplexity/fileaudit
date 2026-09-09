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


## Configuration Options

The `validate_json` function accepts the following parameters to customize validation behaviour:


### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_depth` | `int` or `None` | `DEFAULT_MAX_DEPTH` | Limits recursive structural depth allowed when parsing the JSON document to prevent stack overflow issues or excessive processing times. |
| `max_file_size` | `int` or `None` | `DEFAULT_MAX_FILE_SIZE` | Defines the maximum byte length allowed for the file on disk or remote HTTP resource before aborting parsing. |


### Default Limits

The function applies sensible defaults to prevent resource exhaustion:

```python
DEFAULT_MAX_DEPTH = 50          # Maximum nesting levels
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
```


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

```python

# Bare decorator (validates the first argument)
@validate_json
def load_data(file_path: str):
    pass

# Custom constraints applied via factory
@validate_json(max_depth=50, max_file_size=5000)
def parse_payload(path: Path):
    pass

```

:::{note} 
JSON Schema checks are **not covered**! This is application specific and not considered as a general security validation.
:::