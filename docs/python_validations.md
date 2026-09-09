# Python File Validations

## Why security checks are needed

Python source files can be weaponised before any analysis or execution occurs. Path traversal, symlinks, oversized inputs, null bytes, non-UTF-8 encodings, and pathological ASTs can exhaust memory, crash the interpreter, or escape intended directory boundaries. Performing these checks *before* reading the file into memory or invoking `ast.parse` mitigates denial-of-service and injection risks that would otherwise affect downstream SAST tools, linters, or execution pipelines.

:::{tip} 
**The best way to validate Python application or code is to use [Python Code Audit](https://github.com/nocomplexity/codeaudit)**
:::

:::{note}
This module is intended for anyone who needs to parse or process Python source files (for example via the `ast` module) and wants a reliable library that performs all necessary security validations *before* any further processing or parsing takes place.
:::

## Capabilities

- Existence, regular-file, and `.py`-extension verification
- Optional symlink rejection and base-directory containment (path-traversal guard)
- Pre-read file-size limit
- Strict UTF-8 decoding with BOM stripping and null-byte rejection
- Line-count and per-line length limits
- Safe `ast.parse` with timeout (Unix `SIGALRM`), catching `SyntaxError`, `ValueError`, `MemoryError`, and `RecursionError`
- Post-parse AST node-count limit

:::{note}
Only local Python files can be checked!
:::


If you only parse Python source and never execute it, the primary residual risks are **denial-of-service** (memory exhaustion, CPU saturation, or recursion-depth crashes) and **information disclosure** via path traversal.  
When the AST is subsequently compiled or walked by further analysis tools, node-count limits and (where applicable) node whitelisting become critical additional safeguards.


`parse_timeout` is not a network-oriented control. Even purely local `.py` files can hang or crash `ast.parse`:

* Deeply nested expressions such as `((((...(((1))))...))))` can exhaust the C stack during parsing.
* Extremely long lines or certain literal constructions can cause the parser to consume CPU for seconds or minutes.
* A malicious file deliberately placed in a watched directory or upload folder remains a viable DoS vector.

Consequently, the `SIGALRM`-based timeout, the explicit catching of `MemoryError` / `RecursionError`, and the post-parse AST node-count limit are parser-hardening measures that stay relevant after remote-URL handling has been removed. They protect the process regardless of whether the file originated on the local filesystem or elsewhere.



## Usage Options

### Parameters

| Parameter           | Description                                      |
|---------------------|--------------------------------------------------|
| `func_or_path`      | Path or callable for the Python file.            |
| `max_file_size`     | Max size of the Python file.                     |
| `max_lines`         | Max number of lines.                             |
| `max_line_length`   | Max length of any line.                          |
| `max_ast_nodes`     | Max number of AST nodes.                         |
| `allowed_base_dir`  | Restrict file to this base directory.            |
| `allow_symlinks`    | Allow symbolic links.                            |
| `parse_timeout`     | Timeout for parsing the file.                    |


### Defaults

```bash
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_LINES = 100_000
DEFAULT_MAX_LINE_LENGTH = 10_000
DEFAULT_MAX_AST_NODES = 500_000
```

:::{note}
A Python file of 10MB is very very large, so these default are targetted on slopy AI produced Python files that you should inspect!
If a `.py` file actually hits >1 MB, it is almost certainly machine-generated or being misused. So use [Python Code Audit](https://github.com/nocomplexity/codeaudit) for inspection!
:::

In software development, guardrails like `DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024` are safety ceilings, not expected norms.

If a code analyzer or linter had a 1 MB limit, it would crash on legitimate edge cases (like a auto-generated 2 MB gRPC file or a file with an embedded lookup table).

:::{note}
Normal Python files are under 500 KB, but we'll allow up to 10 MB for strange edge cases. Anything over 10 MB is definitely a mistake or a malicious attempt to crash our system (Denial of Service).

:::

And note for remote files:
```
DEFAULT_PARSE_TIMEOUT = 10  # seconds
```


## How to use the checks

**Decorator mode** (validates a path argument before the function body runs):

```python
@validate_python
def process(source_path: str):
    ...

@validate_python(max_file_size=5000, allowed_base_dir="/safe/dir")
def analyse(path: Path):
    ...
```

**Direct call / CLI mode** (returns `True`/`False`):

```python
ok = validate_python("path/to/file.py", max_lines=10_000)
```

All limits and guards (`max_file_size`, `max_lines`, `max_line_length`, `max_ast_nodes`, `allowed_base_dir`, `allow_symlinks`, `parse_timeout`) are configurable; defaults provide conservative protection out of the box.
