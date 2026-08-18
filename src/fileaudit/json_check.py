"""
License GPL3
(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/
FileAudit - JSON File Security Checker
"""
import json
import inspect
from pathlib import Path
from functools import wraps

import urllib.request
import urllib.error
from urllib.parse import urlparse


# Global default fallbacks
DEFAULT_MAX_DEPTH = 50
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


class FileValidationError(Exception):
    """Custom exception for JSON validation failures in FileAudit."""
    
    def __init__(self, message):
        self.prefix = "FileAudit Security Validation Failed -"
        self.original_message = str(message)
        full_message = f"{self.prefix} {self.original_message}"
        super().__init__(full_message)
    
    def __str__(self):
        return self.args[0]


class HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Redirect handler that blocks any redirect to a non-HTTPS URL.
    Prevents downgrade attacks (e.g. https -> http redirects).
    """
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        if parsed.scheme.lower() != "https":
            raise FileValidationError(
                f"Redirect blocked: target URL must use HTTPS, "
                f"got '{parsed.scheme}'."
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# Opener that enforces HTTPS on redirects
_https_opener = urllib.request.build_opener(HTTPSOnlyRedirectHandler)

def _validate_url_scheme(path_str):
    """
    Validate that a path is either a local path or an HTTPS URL.

    Returns True for a valid HTTPS URL and False for a local path.
    Raises FileValidationError for non-HTTPS or malformed URLs.
    """
    parsed = urlparse(path_str)

    if parsed.scheme:
        if parsed.scheme.lower() != "https":
            raise FileValidationError(
                f"Unsupported URL scheme '{parsed.scheme}': "
                "only 'https' is allowed."
            )

        if not parsed.netloc:
            raise FileValidationError(
                "Invalid HTTPS URL: hostname is required."
            )

        return True

    if parsed.netloc:
        raise FileValidationError(
            "URL scheme must be explicitly 'https'. "
            "Protocol-relative URLs are not allowed."
        )

    return False


def limited_parse(obj, max_depth, depth=0):
    """Recursively validates nesting depth limits."""
    if depth > max_depth:
        raise FileValidationError("JSON nesting depth exceeded")
    if isinstance(obj, dict):
        for v in obj.values():
            limited_parse(v, max_depth, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            limited_parse(item, max_depth, depth + 1)


def validate_json(func_or_path=None, max_depth=None, max_file_size=None):
    """Validate JSON files via decorator or direct invocation.

    A JSON file validator that can operate in two modes:

    1. **Decorator mode** — wraps a function to validate a JSON file path
       passed as an argument before the function body runs.
    2. **Direct call / CLI mode** — validates a file immediately and returns
       a boolean result.

    Usage:
        @validate_json
        @validate_json()
        @validate_json("custom_arg_name", max_depth=50)
        @validate_json(max_file_size=5000)
        validate_json("path/to/file.json", max_depth=10)  # CLI / direct call usage

    Args:
        func_or_path (callable, str, pathlib.Path, or None):
            * If a **callable**: the function to decorate (bare decorator
              usage: ``@validate_json``).
            * If a **str** or **Path** that looks like a file path or URL:
              the file path to validate (direct call usage).
            * If a **str** that is a valid Python identifier (not a path):
              treated as the target argument name to inspect in decorator
              mode (e.g., ``@validate_json("config_path")``).
            * If **None**: returns a decorator factory
              (``@validate_json()`` or ``@validate_json(max_depth=50)``).
        max_depth (int or None): Maximum allowed JSON nesting depth.
            Falls back to ``DEFAULT_MAX_DEPTH`` if omitted.
        max_file_size (int or None): Maximum allowed file size in bytes.
            Falls back to ``DEFAULT_MAX_FILE_SIZE`` if omitted.

    Returns:
        Union[callable, bool, function]:
            * In decorator mode: the wrapped function.
            * In direct call mode: ``True`` if validation passes,
              ``False`` if it fails (errors are printed to stdout).

    Raises:
        FileValidationError: If validation fails in decorator mode, or if
            the decorated function has no arguments, the target argument is
            missing, or the argument type is not ``str`` or ``Path``.

    Examples:
        Bare decorator (validates the first argument)::

            @validate_json
            def process_data(file_path):
                ...

        Decorator with custom limits::

            @validate_json(max_depth=50, max_file_size=5000)
            def process_data(file_path):
                ...

        Decorator targeting a specific argument by name::

            @validate_json("config_path", max_depth=10)
            def process_data(config_path, other_arg):
                ...

        Direct call / CLI usage::

            result = validate_json("path/to/file.json", max_depth=10)
            # Returns True on success, False on failure.
    """
    # Resolve optional limits to their defaults if they are not provided
    resolved_depth = DEFAULT_MAX_DEPTH if max_depth is None else max_depth
    resolved_size = DEFAULT_MAX_FILE_SIZE if max_file_size is None else max_file_size

    # ------------------------------------------------------------------ #
    # MODE DETECTION HEURISTIC
    # ------------------------------------------------------------------ #
    # We need to distinguish between:
    #   - Direct call:  validate_json("path/to/file.json")
    #   - Target arg:   @validate_json("config_path")
    #
    # A string is treated as a target argument name (decorator mode) if:
    #   1. It is a valid Python identifier (no slashes, no dots, no colons)
    #   2. AND it does not look like a URL (no "://" scheme prefix)
    #   3. AND it does not look like an absolute path (no leading / or \)
    #
    # Otherwise, it is treated as a file path (direct call mode).
    # ------------------------------------------------------------------ #

    def _looks_like_file_path(s):
        """Heuristic: does this string look like a file path or URL?"""
        # ONLY https:// is accepted as a remote URL
        if s.startswith("https://"):
            return True
        if s.startswith(("/", "\\")):
            return True  # absolute path
        if "/" in s or "\\" in s:
            return True  # contains path separators
        if "." in s and not s.startswith("."):
            # Contains a dot that looks like a file extension (e.g., "file.json")
            # But exclude hidden files like ".config"
            return True
        return False

    is_decorator_mode = False

    if func_or_path is None:
        # @validate_json()  — decorator factory
        is_decorator_mode = True

    elif callable(func_or_path):
        # @validate_json     — bare decorator, func_or_path is the function
        is_decorator_mode = True

    elif isinstance(func_or_path, str):
        # Could be direct call or target arg name
        # If it looks like a path/URL → direct call
        # If it looks like a valid identifier → decorator target arg
        is_decorator_mode = not _looks_like_file_path(func_or_path)

    elif isinstance(func_or_path, Path):
        # Path objects are ALWAYS direct call (you can't name a param with Path)
        is_decorator_mode = False

    # ------------------------------------------------------------------ #
    # 1. DIRECT CALL / CLI MODE
    # ------------------------------------------------------------------ #
    if not is_decorator_mode and isinstance(func_or_path, (str, Path)):
        try:
            # Pass raw string/Path directly — do NOT wrap in Path() here,
            # because Path("https://...") mangles URLs to "https:/..." which
            # breaks urlparse and causes "no host given" errors.
            _validate_json_file(func_or_path, resolved_depth, resolved_size)
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
            raise FileValidationError(
                f"Decorator applied to '{f.__name__}', but it has no arguments."
            )
        
        # Determine target argument name
        if isinstance(func_or_path, str) and func_or_path in params:
            # Explicit target arg name provided (and it exists in signature)
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
                raise FileValidationError(f"Invalid function call signature: {e}")
            
            p = bound_args.arguments.get(target_arg)
            
            if p is None:
                raise FileValidationError(f"Missing required argument: {target_arg}")
            
            if isinstance(p, (str, Path)):
                # Pass raw string/Path directly to _validate_json_file.
                # Do NOT wrap in Path() here — it breaks HTTPS URLs.
                _validate_json_file(p, resolved_depth, resolved_size)
            else:
                raise FileValidationError(
                    f"Expected Path or str for {target_arg}, got {type(p).__name__}"
                )
            
            return f(*args, **kwargs)
        return wrapper

    # If used as bare `@validate_json`, func_or_path is the function itself
    if callable(func_or_path):
        return decorator(func_or_path)
        
    return decorator




def _validate_json_file(path, max_depth, max_file_size):
    """Secure JSON validation with size, existence, and depth protection.

    Internal function!

    Validates a JSON file by checking its existence, type, and file size before
    attempting to parse it into memory. Also enforces a maximum nesting depth
    to prevent stack exhaustion attacks. Supports both local file paths and
    remote HTTPS URLs.

    Args:
        path (pathlib.Path or str): The path to the JSON file to validate, or an
            HTTPS URL pointing to a remote JSON file. Local paths must support
            ``exists()``, ``is_file()``, ``stat()``, and ``open()`` operations.
            Only ``https://`` URLs are permitted; plain ``http://`` is rejected.
        max_depth (int): The maximum allowed nesting depth for the JSON
            structure. Must be a non-negative integer. Deeper nesting will
            trigger a validation error.
        max_file_size (int): The maximum allowed file size in bytes. Files
            exceeding this limit will be rejected before being read into memory
            to mitigate denial-of-service (DoS) attacks.

    Returns:
        None: This function does not return a value. Successful validation
            completes silently.

    Raises:
        FileValidationError: If any validation check fails, including:
            - The file does not exist (local) or is unreachable (remote).
            - The path is not a regular file (local only).
            - The file size exceeds ``max_file_size``.
            - File metadata cannot be read.
            - The file contains invalid JSON syntax.
            - JSON nesting exceeds ``max_depth`` (or triggers a RecursionError).
            - The URL scheme is not ``https``.
            - Any network or unexpected error during fetching or parsing.

    Note:
        For remote URLs, this function sends a HEAD request first to check the
        ``Content-Length`` header before downloading. If the header is missing,
        it streams the response with a hard size cap to prevent memory
        exhaustion. For local files, it checks ``stat().st_size`` before reading.
        Only ``https://`` URLs are accepted to ensure encrypted transport.
    """
    # ------------------------------------------------------------------ #
    # 0. Determine if path is local or remote
    # ------------------------------------------------------------------ #
    path_str = str(path)
    
    # Strict HTTPS-only validation: rejects http://, ftp://, file://, //example.com
    is_remote = _validate_url_scheme(path_str)

    # ------------------------------------------------------------------ #
    # 1. LOCAL PATH: Existence and Type Checks
    # ------------------------------------------------------------------ #
    if not is_remote:
        local_path = Path(path)
        if not local_path.exists():
            raise FileValidationError(f"File not found: {local_path}")
        if not local_path.is_file():
            raise FileValidationError(f"Path is not a file: {local_path}")

    # ------------------------------------------------------------------ #
    # 2. DoS Mitigation: Check file size BEFORE reading into memory
    # ------------------------------------------------------------------ #
    if is_remote:
        # Remote: Use HEAD request to check Content-Length before downloading
        try:
            req = urllib.request.Request(path_str, method="HEAD")
            # Set a timeout to prevent hanging on slow/unresponsive servers
            with _https_opener.open(req, timeout=10) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    file_size = int(content_length)
                    if file_size > max_file_size:
                        raise FileValidationError(
                            f"Remote file size ({file_size} bytes) exceeds "
                            f"maximum limit of {max_file_size} bytes"
                        )
                # If Content-Length is missing, we stream with a hard cap later
        except FileValidationError:
            raise
        except urllib.error.HTTPError as e:
            raise FileValidationError(
                f"Remote file unreachable (HTTP {e.code}): {path_str}"
            ) from e
        except urllib.error.URLError as e:
            raise FileValidationError(
                f"Could not reach remote file: {path_str} — {e.reason}"
            ) from e
        except ValueError:
            raise FileValidationError(
                f"Remote server returned invalid Content-Length for: {path_str}"
            )
    else:
        # Local: Check file size via stat()
        try:
            file_size = local_path.stat().st_size
            if file_size > max_file_size:
                raise FileValidationError(
                    f"File size ({file_size} bytes) exceeds maximum limit of "
                    f"{max_file_size} bytes"
                )
        except OSError as e:
            raise FileValidationError(f"Could not read file metadata: {e}") from e

    # ------------------------------------------------------------------ #
    # 3. Safe Parsing and Depth Validation
    # ------------------------------------------------------------------ #
    try:
        if is_remote:
            # Stream remote file with a hard byte cap to prevent memory DoS
            # if Content-Length was missing or lied
            req = urllib.request.Request(path_str)
            with _https_opener.open(req, timeout=30) as response:
                # Stream read with a hard ceiling
                raw_bytes = response.read(max_file_size + 1)
                if len(raw_bytes) > max_file_size:
                    raise FileValidationError(
                        f"Remote file exceeded maximum limit of {max_file_size} "
                        f"bytes during download"
                    )
                data = json.loads(raw_bytes.decode("utf-8"))
        else:
            with local_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

        limited_parse(data, max_depth)

    except json.JSONDecodeError as e:
        raise FileValidationError(f"Invalid JSON format: {e}") from e
    except RecursionError:
        raise FileValidationError(
            "JSON nesting limit triggered Python call stack exhaustion"
        )
    except FileValidationError:
        raise
    except urllib.error.HTTPError as e:
        raise FileValidationError(
            f"Remote file download failed (HTTP {e.code}): {path_str}"
        ) from e
    except urllib.error.URLError as e:
        raise FileValidationError(
            f"Network error downloading file: {path_str} — {e.reason}"
        ) from e
    except UnicodeDecodeError as e:
        raise FileValidationError(
            f"File is not valid UTF-8: {e}"
        ) from e
    except Exception as e:
        # Catches rare OS/permission issues, TOCTOU deletes, or other unexpected errors
        raise FileValidationError(f"JSON validation failed: {e}") from e

