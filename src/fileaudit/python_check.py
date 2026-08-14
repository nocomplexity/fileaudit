"""
License GPL3
(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/
FileAudit Security Checker - Checks if a Python file is valid Python 
"""

import ast
import inspect
import signal
from pathlib import Path
from functools import wraps

# Global default fallbacks
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_LINES = 100_000
DEFAULT_MAX_LINE_LENGTH = 10_000
DEFAULT_MAX_AST_NODES = 500_000
DEFAULT_PARSE_TIMEOUT = 10  # seconds


class PythonValidationError(Exception):
    """Custom exception for Python/AST validation failures in FileAudit."""

    def __init__(self, message):
        self.prefix = "FileAudit Security Validation Failed -"
        self.original_message = str(message)
        full_message = f"{self.prefix} {self.original_message}"
        super().__init__(full_message)

    def __str__(self):
        return self.args[0]


def validate_python(
    func_or_path=None,
    max_file_size=None,
    max_lines=DEFAULT_MAX_LINES,
    max_line_length=DEFAULT_MAX_LINE_LENGTH,
    max_ast_nodes=DEFAULT_MAX_AST_NODES,
    allowed_base_dir=None,
    allow_symlinks=False,
    parse_timeout=DEFAULT_PARSE_TIMEOUT,
):
    """Validate Python source files via decorator or direct invocation.

    A Python file validator that can operate in two modes:

    1. **Decorator mode** — wraps a function to validate a Python file path
       passed as an argument before the function body runs.
    2. **Direct call / CLI mode** — validates a file immediately and returns
       a boolean result.

    Security checks performed before (and during) AST parsing:

    - File existence and regular-file type
    - Symlink rejection (unless ``allow_symlinks=True``)
    - Directory containment / path-traversal guard (via ``allowed_base_dir``)
    - File size limit (DoS mitigation) — checked *before* reading into memory
    - Only ``.py`` extension is accepted
    - UTF-8 BOM detection and stripping
    - Strict UTF-8 decoding
    - Rejection of null bytes (``\\0``)
    - Line count and per-line length limits (tokenizer DoS protection)
    - Safe ``ast.parse`` with explicit catching of ``SyntaxError``,
      ``ValueError``, ``MemoryError`` and ``RecursionError``
    - Optional parse timeout via ``SIGALRM`` (Unix only)
    - Post-parse AST node count limit (protects downstream SAST walkers)

    Usage::

        @validate_python
        @validate_python()
        @validate_python("custom_arg_name")
        @validate_python(max_file_size=5000)
        validate_python("path/to/file.py")          # CLI / direct call usage

    Args:: 

        func_or_path (callable, str, pathlib.Path, or None):
            * If a **callable**: the function to decorate (bare decorator
              usage: ``@validate_python``).
            * If a **str** or **Path** that looks like a file path:
              the file path to validate (direct call usage).
            * If a **str** that is a valid Python identifier (not a path):
              treated as the target argument name to inspect in decorator
              mode (e.g., ``@validate_python("source_path")``).
            * If **None**: returns a decorator factory
              (``@validate_python()`` or ``@validate_python(max_file_size=…)``).
        max_file_size (int or None): Maximum allowed file size in bytes.
            Falls back to ``DEFAULT_MAX_FILE_SIZE`` if omitted.
        max_lines (int): Maximum number of lines allowed.
        max_line_length (int): Maximum characters per line allowed.
        max_ast_nodes (int): Maximum AST nodes allowed after parsing.
        allowed_base_dir (str or Path or None): If set, the resolved local
            path must lie inside this directory (path-traversal protection).
        allow_symlinks (bool): If False (default), symlinks are rejected.
        parse_timeout (int): Seconds to allow for ``ast.parse`` before
            aborting. Uses ``SIGALRM``; only effective on Unix-like systems.

    Returns:
    
        Union[callable, bool, function]:

            * In decorator mode: the wrapped function.
            * In direct call mode: ``True`` if validation passes,
              ``False`` if it fails (errors are printed to stdout).

    Raises:

        PythonValidationError: If validation fails in decorator mode, or if
            the decorated function has no arguments, the target argument is
            missing, or the argument type is not ``str`` or ``Path``.
    """
    # Resolve optional limit to its default if not provided
    resolved_size = DEFAULT_MAX_FILE_SIZE if max_file_size is None else max_file_size

    # ------------------------------------------------------------------ #
    # MODE DETECTION HEURISTIC
    # ------------------------------------------------------------------ #
    def _looks_like_file_path(s):
        """Heuristic: does this string look like a file path?"""
        if s.startswith(("/", "\\")):
            return True  # absolute path
        if "/" in s or "\\" in s:
            return True  # contains path separators
        if "." in s and not s.startswith("."):
            # Contains a dot that looks like a file extension (e.g., "file.py")
            return True
        return False

    is_decorator_mode = False
    if func_or_path is None:
        # @validate_python() — decorator factory
        is_decorator_mode = True
    elif callable(func_or_path):
        # @validate_python — bare decorator, func_or_path is the function
        is_decorator_mode = True
    elif isinstance(func_or_path, str):
        # Could be direct call or target arg name
        is_decorator_mode = not _looks_like_file_path(func_or_path)
    elif isinstance(func_or_path, Path):
        # Path objects are ALWAYS direct call
        is_decorator_mode = False

    # ------------------------------------------------------------------ #
    # 1. DIRECT CALL / CLI MODE
    # ------------------------------------------------------------------ #
    if not is_decorator_mode and isinstance(func_or_path, (str, Path)):
        try:
            _validate_python_file(
                func_or_path,
                resolved_size,
                max_lines=max_lines,
                max_line_length=max_line_length,
                max_ast_nodes=max_ast_nodes,
                allowed_base_dir=allowed_base_dir,
                allow_symlinks=allow_symlinks,
                parse_timeout=parse_timeout,
            )
            return True
        except Exception as e:
            print(f"Exception: {e}")
            return False

    # ------------------------------------------------------------------ #
    # 2. DECORATOR MODE
    # ------------------------------------------------------------------ #
    def decorator(f):
        sig = inspect.signature(f)
        params = list(sig.parameters.keys())

        if not params:
            raise PythonValidationError(
                f"Decorator applied to '{f.__name__}', but it has no arguments."
            )

        # Determine target argument name
        if isinstance(func_or_path, str) and func_or_path in params:
            target_arg = func_or_path
        else:
            # Default to the very first parameter
            target_arg = params[0]

        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
            except TypeError as e:
                raise PythonValidationError(f"Invalid function call signature: {e}")

            p = bound_args.arguments.get(target_arg)
            if p is None:
                raise PythonValidationError(f"Missing required argument: {target_arg}")

            if isinstance(p, (str, Path)):
                _validate_python_file(
                    p,
                    resolved_size,
                    max_lines=max_lines,
                    max_line_length=max_line_length,
                    max_ast_nodes=max_ast_nodes,
                    allowed_base_dir=allowed_base_dir,
                    allow_symlinks=allow_symlinks,
                    parse_timeout=parse_timeout,
                )
            else:
                raise PythonValidationError(
                    f"Expected Path or str for {target_arg}, got {type(p).__name__}"
                )

            return f(*args, **kwargs)

        return wrapper

    # If used as bare `@validate_python`, func_or_path is the function itself
    if callable(func_or_path):
        return decorator(func_or_path)

    return decorator


def _validate_python_file(
    path,
    max_file_size,
    max_lines=DEFAULT_MAX_LINES,
    max_line_length=DEFAULT_MAX_LINE_LENGTH,
    max_ast_nodes=DEFAULT_MAX_AST_NODES,
    allowed_base_dir=None,
    allow_symlinks=False,
    parse_timeout=DEFAULT_PARSE_TIMEOUT,
):
    """Secure Python source validation with size, existence, encoding and AST protection.

    Internal function!

    Validates a local Python source file by checking its existence, type,
    extension and file size *before* reading it into memory. Then enforces
    UTF-8 decoding, rejects null bytes, and finally runs ``ast.parse`` while
    catching resource-exhaustion errors that can crash the interpreter.

    Args:
        path (pathlib.Path or str): Local path to a ``.py`` file.
        max_file_size (int): Maximum allowed size in bytes.
        max_lines (int): Maximum allowed line count.
        max_line_length (int): Maximum allowed characters per line.
        max_ast_nodes (int): Maximum allowed AST nodes after parsing.
        allowed_base_dir (str or Path or None): Directory the file must reside in.
        allow_symlinks (bool): Whether to permit symbolic links.
        parse_timeout (int): Seconds to allow for parsing (Unix ``SIGALRM`` only).

    Returns:
        None: Completes silently on success.

    Raises:
        PythonValidationError: On any validation failure (missing file, wrong
            type/extension, size exceeded, encoding error, null byte, syntax
            error, or resource exhaustion during parsing).
    """
    # ------------------------------------------------------------------ #
    # 0. Resolve to local path
    # ------------------------------------------------------------------ #
    local_path = Path(path)

    # ------------------------------------------------------------------ #
    # 1. Extension check (.py)
    # ------------------------------------------------------------------ #
    if local_path.suffix.lower() != ".py":
        raise PythonValidationError(
            f"Only .py files are accepted (got extension '{local_path.suffix}'): {local_path}"
        )

    # ------------------------------------------------------------------ #
    # 2. Existence, Type, Symlink and Traversal Checks
    # ------------------------------------------------------------------ #
    if not local_path.exists():
        raise PythonValidationError(f"File not found: {local_path}")
    if not local_path.is_file():
        raise PythonValidationError(f"Path is not a file: {local_path}")

    # 2a. Symlink guard
    if local_path.is_symlink() and not allow_symlinks:
        raise PythonValidationError(
            f"Symlinks are not allowed (set allow_symlinks=True to permit): {local_path}"
        )

    # 2b. Directory containment / path-traversal guard
    if allowed_base_dir is not None:
        try:
            resolved_file = local_path.resolve(strict=True)
            resolved_base = Path(allowed_base_dir).resolve()
            try:
                resolved_file.relative_to(resolved_base)
            except ValueError:
                raise PythonValidationError(
                    f"Path traversal detected: {local_path} resolves to "
                    f"{resolved_file}, which is outside allowed base "
                    f"directory {allowed_base_dir}"
                )
        except OSError as e:
            raise PythonValidationError(
                f"Could not resolve path for traversal check: {e}"
            ) from e

    # ------------------------------------------------------------------ #
    # 3. DoS Mitigation: Check file size BEFORE reading into memory
    # ------------------------------------------------------------------ #
    try:
        file_size = local_path.stat().st_size
        if file_size > max_file_size:
            raise PythonValidationError(
                f"File size ({file_size} bytes) exceeds maximum limit of "
                f"{max_file_size} bytes"
            )
    except OSError as e:
        raise PythonValidationError(f"Could not read file metadata: {e}") from e

    # ------------------------------------------------------------------ #
    # 4. Safe reading, null-byte check, encoding and AST parsing
    # ------------------------------------------------------------------ #
    try:
        # Read as bytes first so we can strip a BOM before strict decode
        raw_bytes = local_path.read_bytes()
        if raw_bytes.startswith(b"\xef\xbb\xbf"):
            raw_bytes = raw_bytes[3:]
        try:
            source = raw_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as e:
            raise PythonValidationError(f"File is not valid UTF-8: {e}") from e

        # Null-byte rejection (ast.parse also raises, but we fail early)
        if "\0" in source:
            raise PythonValidationError("Null byte (\\0) found in source — rejected")

        # Line count and line length check (tokenizer DoS protection)
        line_count = 0
        for line in source.splitlines():
            line_count += 1
            if line_count > max_lines:
                raise PythonValidationError(
                    f"File contains {line_count} lines, exceeding limit of {max_lines}"
                )
            if len(line) > max_line_length:
                raise PythonValidationError(
                    f"Line {line_count} length ({len(line)}) exceeds maximum "
                    f"limit of {max_line_length} characters"
                )

        # AST parse — the critical security-relevant step
        # Official docs warn that sufficiently large/complex input can
        # crash the interpreter via stack-depth limits.
        tree = None
        try:
            # Optional Unix-only timeout to catch pathological inputs that
            # parse slowly without hitting recursion limits.
            if hasattr(signal, "SIGALRM") and parse_timeout > 0:
                _old_alarm = 0
                _old_handler = None

                def _timeout_handler(signum, frame):
                    raise PythonValidationError(
                        f"AST parsing timed out after {parse_timeout} seconds "
                        f"(possible pathological input)"
                    )

                _old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
                _old_alarm = signal.alarm(parse_timeout)
                try:
                    tree = ast.parse(source, filename=str(local_path))
                finally:
                    signal.alarm(_old_alarm)
                    if _old_handler is not None:
                        signal.signal(signal.SIGALRM, _old_handler)
            else:
                tree = ast.parse(source, filename=str(local_path))

        except SyntaxError as e:
            raise PythonValidationError(
                f"Invalid Python syntax at line {e.lineno}: {e.msg}"
            ) from e
        except ValueError as e:
            # e.g. null bytes that somehow slipped through, or other parser errors
            raise PythonValidationError(f"AST parse ValueError: {e}") from e
        except MemoryError:
            raise PythonValidationError(
                "Memory exhaustion during AST parsing (possible DoS input)"
            )
        except RecursionError:
            raise PythonValidationError(
                "Recursion limit / stack depth exceeded during AST parsing "
                "(possible pathological input)"
            )

        # AST node count check — protects downstream SAST walkers from DoS
        node_count = sum(1 for _ in ast.walk(tree))
        if node_count > max_ast_nodes:
            raise PythonValidationError(
                f"AST contains {node_count} nodes, exceeding maximum limit of "
                f"{max_ast_nodes} (possible DoS against AST walkers)"
            )

    except PythonValidationError:
        # Re-raise our own exceptions unchanged
        raise
    except Exception as e:
        # Catch-all for rare OS/permission/TOCTOU issues
        raise PythonValidationError(f"Python validation failed: {e}") from e