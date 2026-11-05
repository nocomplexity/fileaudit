"""
License MPL-2.0
(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/
FileAudit Security Checker - Checks whether a Python file is syntactically valid.
"""

import ast
import inspect
import os
import signal
import stat
import threading
import time
from functools import wraps
from pathlib import Path
from contextlib import suppress



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
        super().__init__(f"{self.prefix} {self.original_message}")

    def __str__(self):
        return self.args[0]


def _validate_limit(name, value, *, allow_zero=False):
    """Validate an integer resource limit."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    minimum = 0 if allow_zero else 1
    if value < minimum:
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{name} must be {qualifier}")


def _looks_like_file_path(value):
    """Heuristic distinguishing a path from a decorator argument identifier."""
    # A valid Python identifier is the documented decorator-argument form.
    # Everything else that resembles a filesystem path is treated as a path.
    if not value.isidentifier():
        return True
    return False

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
    """Validate Python source files via decorator or direct call.

    This function operates in two modes:

    * **Direct call / CLI mode** – When called with a file path
      (``str`` or ``pathlib.Path``), the file is validated immediately.
      Returns ``True`` on success. 
      
      Raises : **`PythonValidationError`** on any validation failure. 
      If an error occurs, an exception is raised. You can catch it or let it propagate depending on your needs.
      
    * **Decorator mode** – When used as ``@validate_python``, 
      ``@validate_python()``, or ``@validate_python("arg_name")``, the
      decorated function’s selected ``str``/``Path`` argument is validated
      before the function body executes. On failure a
      :exc:`PythonValidationError` is raised.

    Existing public calling conventions are preserved.

    Security checks performed (before and during AST parsing):

    * File existence and regular-file type
    * Symlink rejection (unless ``allow_symlinks=True``)
    * Directory containment / path-traversal guard (via ``allowed_base_dir``)
    * File size limit (checked *before* reading into memory)
    * Only ``.py`` extension is accepted
    * UTF-8 BOM detection and stripping
    * Strict UTF-8 decoding
    * Rejection of null bytes (``\\0``)
    * Line count and per-line length limits
    * Safe ``ast.parse`` with explicit handling of ``SyntaxError``,
      ``ValueError``, ``MemoryError`` and ``RecursionError``
    * Optional parse timeout via ``SIGALRM`` (Unix only)
    * Post-parse AST node count limit

    Args:
        func_or_path (callable, str, pathlib.Path, or None): Determines the
            operating mode.

            * ``None`` – Returns a decorator factory
              (``@validate_python()`` or with keyword arguments).
            * A callable – Bare decorator usage (``@validate_python``).
            * A ``str`` that looks like a file path, or a ``pathlib.Path`` –
              Direct validation of that file.
            * A ``str`` that is a valid Python identifier – Treated as the
              name of the argument to validate in decorator mode
              (e.g. ``@validate_python("source_path")``).

        max_file_size (int or None): Maximum allowed file size in bytes.
            Falls back to ``DEFAULT_MAX_FILE_SIZE`` when omitted.
        max_lines (int): Maximum number of lines allowed in the source file.
        max_line_length (int): Maximum number of characters allowed per line.
        max_ast_nodes (int): Maximum number of AST nodes allowed after
            parsing.
        allowed_base_dir (str, pathlib.Path, or None): If set, the resolved
            path of the file must lie inside this directory (path-traversal
            protection).
        allow_symlinks (bool): If ``False`` (default), symbolic links are
            rejected.
        parse_timeout (int): Seconds allowed for ``ast.parse`` before
            aborting. Uses ``SIGALRM`` and is effective only on Unix-like
            systems. A value of ``0`` disables the timeout.

    Returns:
        Union[bool, callable]:

        * In direct-call mode: ``True`` if validation succeeds.
        * In decorator mode: the wrapped function (or a decorator factory
          when ``func_or_path`` is ``None``).

    Raises:
        PythonValidationError: Raised in the following cases:

            * Validation of the target file fails (missing file, wrong
              type/extension, size/line/AST limits exceeded, encoding
              error, null byte, syntax error, timeout, etc.).
            * In decorator mode: the decorated function has no arguments,
              the designated target argument is missing, or the argument
              is not of type ``str`` or ``pathlib.Path``.
            * The function signature cannot be inspected.

        ValueError: Raised when an invalid value is supplied for
            ``allow_symlinks`` or ``allowed_base_dir``.

    Examples:
        Direct validation::

            validate_python("path/to/file.py")
            validate_python(Path("path/to/file.py"), max_file_size=5000)

        Decorator usage::

            @validate_python
            def process(path):
                ...

            @validate_python()
            def process(path):
                ...

            @validate_python("source")
            def process(source, other):
                ...

            @validate_python(max_lines=10_000, allow_symlinks=True)
            def process(path):
                ...
    """
    resolved_size = (
        DEFAULT_MAX_FILE_SIZE if max_file_size is None else max_file_size
    )
    _validate_limit("max_file_size", resolved_size)
    _validate_limit("max_lines", max_lines)
    _validate_limit("max_line_length", max_line_length)
    _validate_limit("max_ast_nodes", max_ast_nodes)
    _validate_limit("parse_timeout", parse_timeout, allow_zero=True)

    if not isinstance(allow_symlinks, bool):
        raise ValueError("allow_symlinks must be a bool")
    if allowed_base_dir is not None and not isinstance(
        allowed_base_dir, (str, Path)
    ):
        raise ValueError("allowed_base_dir must be str, Path, or None")

    is_decorator_mode = (
        func_or_path is None
        or callable(func_or_path)
        or (
            isinstance(func_or_path, str)
            and not _looks_like_file_path(func_or_path)
        )
    )

    # Direct call / CLI mode
    if not is_decorator_mode and isinstance(func_or_path, (str, Path)):
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

    # Decorator mode
    def decorator(function):
        try:
            signature = inspect.signature(function)
        except (TypeError, ValueError) as exc:
            raise PythonValidationError(
                f"Could not inspect decorated function: {exc}"
            ) from exc

        parameters = list(signature.parameters)
        if not parameters:
            raise PythonValidationError(
                f"Decorator applied to '{function.__name__}', but it has no arguments."
            )

        if isinstance(func_or_path, str):
            if func_or_path not in signature.parameters:
                raise PythonValidationError(
                    f"Target argument '{func_or_path}' does not exist in "
                    f"the signature of '{function.__name__}'."
                )
            target_arg = func_or_path
        else:
            target_arg = parameters[0]

        @wraps(function)
        def wrapper(*args, **kwargs):
            try:
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
            except TypeError as exc:
                raise PythonValidationError(
                    f"Invalid function call signature: {exc}"
                ) from exc

            target = bound.arguments.get(target_arg)
            if target is None:
                raise PythonValidationError(
                    f"Missing required argument: {target_arg}"
                )
            if not isinstance(target, (str, Path)):
                raise PythonValidationError(
                    f"Expected Path or str for {target_arg}, "
                    f"got {type(target).__name__}"
                )

            _validate_python_file(
                target,
                resolved_size,
                max_lines=max_lines,
                max_line_length=max_line_length,
                max_ast_nodes=max_ast_nodes,
                allowed_base_dir=allowed_base_dir,
                allow_symlinks=allow_symlinks,
                parse_timeout=parse_timeout,
            )
            return function(*args, **kwargs)

        return wrapper

    if callable(func_or_path):
        return decorator(func_or_path)
    return decorator


def _is_within_directory(candidate, base):
    """Return whether candidate is equal to or below base."""
    try:
        candidate.relative_to(base)
        return True
    except ValueError:
        return False


def _opened_file_path(fd, fallback):
    """Best-effort path of an already-open file descriptor."""
    with suppress(OSError):
        return Path(f"/proc/self/fd/{fd}").resolve(strict=True)
    return fallback.resolve(strict=True)


def _read_bounded_file(path, max_file_size, allow_symlinks):
    """Open once, inspect that descriptor, and read no more than limit + 1."""
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    if not allow_symlinks and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(os.fspath(path), flags)
    except OSError as exc:
        raise PythonValidationError(f"Could not open file: {exc}") from exc

    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise PythonValidationError(f"Path is not a regular file: {path}")
        if file_stat.st_size > max_file_size:
            raise PythonValidationError(
                f"File size ({file_stat.st_size} bytes) exceeds maximum "
                f"limit of {max_file_size} bytes"
            )

        # Read one byte beyond the configured limit to detect growth after
        # fstat(), without ever reading an unbounded amount into memory.
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(max_file_size + 1)
        if len(raw) > max_file_size:
            raise PythonValidationError(
                f"File exceeds maximum limit of {max_file_size} bytes"
            )
        return raw, fd
    except Exception:
        os.close(fd)
        raise


def _parse_with_timeout(source, filename, parse_timeout):
    """Parse source, using SIGALRM only when it can be used without clobbering
    another active alarm. In other environments parsing proceeds without a
    timeout; callers needing a hard timeout should isolate parsing in a process.
    """
    can_alarm = (
        parse_timeout > 0
        and hasattr(signal, "SIGALRM")
        and threading.current_thread() is threading.main_thread()
    )
    if not can_alarm:
        return ast.parse(source, filename=filename)

    try:
        previous_handler = signal.getsignal(signal.SIGALRM)
        # getitimer() observes an existing timer without cancelling or
        # restarting it. Never take ownership of an application timer.
        if hasattr(signal, "getitimer"):
            previous_remaining = signal.getitimer(signal.ITIMER_REAL)[0]
        else:
            # Without a read-only timer API, avoid touching process alarms.
            return ast.parse(source, filename=filename)
    except (AttributeError, OSError, ValueError):
        return ast.parse(source, filename=filename)

    if previous_remaining > 0:
        return ast.parse(source, filename=filename)    

    def timeout_handler(signum, frame):
        raise PythonValidationError(
            f"AST parsing timed out after {parse_timeout} seconds "
            "(possible pathological input)"
        )

    installed = False
    alarm_started = False
    try:
        signal.signal(signal.SIGALRM, timeout_handler)
        installed = True
        signal.alarm(parse_timeout)
        alarm_started = True
        return ast.parse(source, filename=filename)
    finally:
        if alarm_started:
            signal.alarm(0)
        if installed:
            signal.signal(signal.SIGALRM, previous_handler)
        # No pre-existing alarm was active, so none needs to be restored.


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
    """Validate a local .py file; raises PythonValidationError on failure."""
    try:
        local_path = Path(path)
    except (TypeError, ValueError) as exc:
        raise PythonValidationError(f"Invalid file path: {exc}") from exc

    if local_path.suffix.lower() != ".py":
        raise PythonValidationError(
            f"Only .py files are accepted (got extension "
            f"'{local_path.suffix}'): {local_path}"
        )

    # Resolve the permitted base once. The opened descriptor is checked below
    # as well where the platform exposes /proc/self/fd.
    resolved_base = None
    if allowed_base_dir is not None:
        try:
            resolved_base = Path(allowed_base_dir).resolve(strict=True)
            if not resolved_base.is_dir():
                raise PythonValidationError(
                    f"Allowed base path is not a directory: {allowed_base_dir}"
                )
        except OSError as exc:
            raise PythonValidationError(
                f"Could not resolve allowed base directory: {exc}"
            ) from exc

    try:
        if local_path.is_symlink() and not allow_symlinks:
            raise PythonValidationError(
                f"Symlinks are not allowed (set allow_symlinks=True to permit): "
                f"{local_path}"
            )

        # Preliminary containment check, followed by a descriptor-based check
        # after opening to reduce path replacement races.
        if resolved_base is not None:
            try:
                preliminary = local_path.resolve(strict=True)
            except OSError as exc:
                raise PythonValidationError(
                    f"Could not resolve file path: {exc}"
                ) from exc
            if not _is_within_directory(preliminary, resolved_base):
                raise PythonValidationError(
                    f"Path traversal detected: {local_path} resolves to "
                    f"{preliminary}, outside allowed base directory "
                    f"{allowed_base_dir}"
                )

        raw_bytes, fd = _read_bounded_file(
            local_path, max_file_size, allow_symlinks
        )
        try:
            if resolved_base is not None:
                opened_path = _opened_file_path(fd, local_path)
                if not _is_within_directory(opened_path, resolved_base):
                    raise PythonValidationError(
                        f"Opened file is outside allowed base directory: "
                        f"{opened_path}"
                    )
        finally:
            os.close(fd)

    except PythonValidationError:
        raise
    except OSError as exc:
        raise PythonValidationError(
            f"Could not access file {local_path}: {exc}"
        ) from exc

    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raw_bytes = raw_bytes[3:]

    try:
        source = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PythonValidationError(
            f"File is not valid UTF-8: {exc}"
        ) from exc

    if "\0" in source:
        raise PythonValidationError(
            r"Null byte (\0) found in source — rejected"
        )

    # splitlines() preserves the original behaviour for empty files and
    # trailing newlines while enforcing limits on each logical line.
    lines = source.splitlines()
    if len(lines) > max_lines:
        raise PythonValidationError(
            f"File contains {len(lines)} lines, exceeding limit of {max_lines}"
        )
    for line_number, line in enumerate(lines, start=1):
        if len(line) > max_line_length:
            raise PythonValidationError(
                f"Line {line_number} length ({len(line)}) exceeds maximum "
                f"limit of {max_line_length} characters"
            )

    try:
        tree = _parse_with_timeout(
            source, str(local_path), parse_timeout
        )
    except PythonValidationError:
        raise
    except SyntaxError as exc:
        raise PythonValidationError(
            f"Invalid Python syntax at line {exc.lineno}: {exc.msg}"
        ) from exc
    except ValueError as exc:
        raise PythonValidationError(f"AST parse ValueError: {exc}") from exc
    except MemoryError as exc:
        raise PythonValidationError(
            "Memory exhaustion during AST parsing (possible DoS input)"
        ) from exc
    except RecursionError as exc:
        raise PythonValidationError(
            "Recursion limit / stack depth exceeded during AST parsing "
            "(possible pathological input)"
        ) from exc

    # This limit protects subsequent AST consumers, not ast.parse() itself.
    node_count = 0
    for _node in ast.walk(tree):
        node_count += 1
        if node_count > max_ast_nodes:
            raise PythonValidationError(
                f"AST contains more than {max_ast_nodes} nodes, exceeding "
                f"the maximum limit (possible DoS against AST walkers)"
            )

