"""
License MPL-2.0
(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/
FileAudit - GZ File Security Checker
"""

import gzip
import inspect
import io
import os
import stat
import urllib.request
import urllib.error
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse


# Global default fallbacks
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_UNCOMPRESSED_RATIO = 100  # 100:1 ratio
DEFAULT_MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB

# Read decompressed data in bounded chunks rather than loading the entire
# decompressed file into memory.
GZ_READ_CHUNK_SIZE = 1024 * 1024  # 1 MB

HEAD_TIMEOUT = 10
DOWNLOAD_TIMEOUT = 30


class GzValidationError(Exception):
    """Custom exception for GZip validation failures in FileAudit."""

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
            raise GzValidationError(
                f"Redirect blocked: target URL must use HTTPS, "
                f"got '{parsed.scheme}'."
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# Opener that enforces HTTPS on redirects
_https_opener = urllib.request.build_opener(HTTPSOnlyRedirectHandler)


def _validate_url_scheme(path_str: str) -> bool:
    """
    Validate that a URL uses HTTPS only.
    
    Returns True if the path is a remote URL, False if it's a local path.
    Raises GzValidationError for any non-HTTPS URL.
    """
    parsed = urlparse(path_str)
    
    if parsed.scheme:
        if parsed.scheme.lower() != "https":
            raise GzValidationError(
                f"Unsupported URL scheme '{parsed.scheme}': only 'https' is allowed."
            )
        return True
    elif parsed.netloc:
        # Protocol-relative URLs like //example.com/file.gz
        raise GzValidationError(
            "URL scheme must be explicitly 'https'. Protocol-relative URLs are not allowed."
        )
    
    return False


def _validate_limit(name, value):
    """
    Validate a numeric security limit.

    Args:
        name: Name of the limit.
        value: Limit value.

    Raises:
        ValueError: If the value is not a positive integer.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")

    if value <= 0:
        raise ValueError(f"{name} must be greater than 0")


def _open_gz_file(path):
    """
    Open a GZip file safely and return the file object and initial stat data.

    The file is opened before its size is checked. This avoids the common
    stat(path) -> open(path) TOCTOU pattern.

    O_NOFOLLOW is used where supported so the final path component cannot be
    replaced by a symbolic link between the security check and opening.

    Args:
        path: Path to the GZip file.

    Returns:
        Tuple containing the opened binary file and its initial stat result.

    Raises:
        GzValidationError: If the file cannot be opened safely.
    """
    flags = os.O_RDONLY

    # Windows requires O_BINARY for binary reads.
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    # Prevent following the final symbolic link where supported.
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(str(path), flags)

    except FileNotFoundError as e:
        raise GzValidationError(
            f"File not found: {path}"
        ) from e

    except PermissionError as e:
        raise GzValidationError(
            f"Permission denied: {path}"
        ) from e

    except OSError as e:
        raise GzValidationError(
            f"Failed to open file '{path}': {e}"
        ) from e

    try:
        file_stat = os.fstat(fd)

        # Never process directories, devices, FIFOs, sockets, etc.
        if not stat.S_ISREG(file_stat.st_mode):
            raise GzValidationError(
                f"Path is not a regular file: {path}"
            )

        file_obj = os.fdopen(fd, "rb", closefd=True)

        return file_obj, file_stat

    except GzValidationError:
        os.close(fd)
        raise

    except OSError as e:
        os.close(fd)
        raise GzValidationError(
            f"Failed to inspect file '{path}': {e}"
        ) from e


def _validate_gz_stream(fileobj, compressed_size, path_display, max_uncompressed_size):
    """
    Stream-decompress a GZip file object and enforce the uncompressed size limit.

    Args:
        fileobj: A file-like object supporting read().
        compressed_size: The known compressed size in bytes.
        path_display: String used in error messages.
        max_uncompressed_size: Maximum allowed uncompressed size.

    Returns:
        int: Total uncompressed size in bytes.

    Raises:
        GzValidationError: If the file is empty, malformed, or exceeds limits.
    """
    if compressed_size == 0:
        raise GzValidationError(
            f"Rejected {path_display}: GZip file is empty"
        )

    total_uncompressed_size = 0

    try:
        with gzip.GzipFile(fileobj=fileobj, mode="rb") as gz:
            while True:
                chunk = gz.read(GZ_READ_CHUNK_SIZE)
                if not chunk:
                    break

                total_uncompressed_size += len(chunk)

                if total_uncompressed_size > max_uncompressed_size:
                    raise GzValidationError(
                        f"Rejected {path_display}: Uncompressed size "
                        f"({total_uncompressed_size} bytes) exceeds "
                        f"maximum of {max_uncompressed_size} bytes"
                    )

    except GzValidationError:
        raise

    except gzip.BadGzipFile as e:
        raise GzValidationError(
            f"Invalid GZip format: {e}"
        ) from e

    except (EOFError, OSError) as e:
        raise GzValidationError(
            f"GZip decompression failed: {e}"
        ) from e

    return total_uncompressed_size


def _validate_gz_file(
    path,
    max_file_size,
    max_uncompressed_ratio,
    max_uncompressed_size
):
    """
    Internal validation function for GZip files.

    Performs all security checks on a GZip file.

    Security checks:

    - File exists and is a regular file (local)
    - Symbolic links are rejected where O_NOFOLLOW is supported (local)
    - Compressed file size limits
    - Streaming uncompressed size limits
    - GZip decompression ratio limits
    - GZip format/CRC/trailer validation
    - Detection of compressed file size changes during validation (local)
    - Remote files restricted to HTTPS only

    Args:
        path: Path to the GZip file or an HTTPS URL.
        max_file_size: Maximum compressed file size.
        max_uncompressed_ratio: Maximum decompression ratio.
        max_uncompressed_size: Maximum uncompressed size.

    Raises:
        GzValidationError: If any security check fails.
    """
    path_str = str(path)
    is_remote = _validate_url_scheme(path_str)

    # ------------------------------------------------------------------ #
    # REMOTE: HTTPS-only download and validation
    # ------------------------------------------------------------------ #
    if is_remote:
        # HEAD request to check size before downloading
        try:
            req = urllib.request.Request(path_str, method="HEAD")
            with _https_opener.open(req, timeout=HEAD_TIMEOUT) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    compressed_size = int(content_length)
                    if compressed_size > max_file_size:
                        raise GzValidationError(
                            f"Rejected {path_str}: Remote file size "
                            f"({compressed_size} bytes) exceeds maximum of "
                            f"{max_file_size} bytes"
                        )
        except GzValidationError:
            raise
        except urllib.error.HTTPError as e:
            raise GzValidationError(
                f"Remote file unreachable (HTTP {e.code}): {path_str}"
            ) from e
        except urllib.error.URLError as e:
            raise GzValidationError(
                f"Could not reach remote file: {path_str} — {e.reason}"
            ) from e
        except ValueError:
            raise GzValidationError(
                f"Remote server returned invalid Content-Length for: {path_str}"
            )

        # Download with a hard byte cap
        try:
            req = urllib.request.Request(path_str)
            with _https_opener.open(req, timeout=DOWNLOAD_TIMEOUT) as response:
                raw_bytes = response.read(max_file_size + 1)
                if len(raw_bytes) > max_file_size:
                    raise GzValidationError(
                        f"Rejected {path_str}: Remote file exceeded maximum "
                        f"size ({max_file_size} bytes) during download"
                    )
        except GzValidationError:
            raise
        except urllib.error.HTTPError as e:
            raise GzValidationError(
                f"Remote file download failed (HTTP {e.code}): {path_str}"
            ) from e
        except urllib.error.URLError as e:
            raise GzValidationError(
                f"Network error downloading file: {path_str} — {e.reason}"
            ) from e

        compressed_size = len(raw_bytes)

        total_uncompressed_size = _validate_gz_stream(
            io.BytesIO(raw_bytes),
            compressed_size,
            path_str,
            max_uncompressed_size
        )

        # Ratio check
        ratio = total_uncompressed_size / compressed_size
        if ratio > max_uncompressed_ratio:
            raise GzValidationError(
                f"Rejected {path_str}: Decompression ratio "
                f"({ratio:.2f}x) exceeds maximum of "
                f"{max_uncompressed_ratio}x "
                f"(GZip bomb protection)"
            )

        return

    # ------------------------------------------------------------------ #
    # LOCAL: Existing TOCTOU-safe validation
    # ------------------------------------------------------------------ #
    path = Path(path)

    # On platforms without O_NOFOLLOW, explicitly reject symbolic links before
    # opening. On platforms with O_NOFOLLOW, the open operation itself
    # provides the stronger race-resistant protection.
    if not hasattr(os, "O_NOFOLLOW"):
        try:
            if path.is_symlink():
                raise GzValidationError(
                    f"Rejected {path}: Symbolic links are not allowed"
                )
        except OSError as e:
            raise GzValidationError(
                f"Failed to inspect path '{path}': {e}"
            ) from e

    # Open the actual file that will be validated.
    raw_file, initial_stat = _open_gz_file(path)

    try:
        # ---------------------------------------------------------------
        # 1. Compressed file size limit
        # ---------------------------------------------------------------

        compressed_size = initial_stat.st_size

        if compressed_size > max_file_size:
            raise GzValidationError(
                f"Rejected {path}: File size ({compressed_size} bytes) "
                f"exceeds maximum of {max_file_size} bytes"
            )

        # ---------------------------------------------------------------
        # 2. Streaming GZip decompression
        # ---------------------------------------------------------------

        total_uncompressed_size = _validate_gz_stream(
            raw_file,
            compressed_size,
            path,
            max_uncompressed_size
        )

        # ---------------------------------------------------------------
        # 3. Detect file modification during validation
        # ---------------------------------------------------------------

        try:
            final_stat = os.fstat(raw_file.fileno())

        except OSError as e:
            raise GzValidationError(
                f"Failed to re-check file '{path}': {e}"
            ) from e

        if final_stat.st_size != compressed_size:
            raise GzValidationError(
                f"Rejected {path}: File changed while being validated "
                f"(size changed from {compressed_size} to "
                f"{final_stat.st_size} bytes)"
            )

        # ---------------------------------------------------------------
        # 4. GZip decompression ratio limit
        # ---------------------------------------------------------------

        ratio = total_uncompressed_size / compressed_size

        if ratio > max_uncompressed_ratio:
            raise GzValidationError(
                f"Rejected {path}: Decompression ratio "
                f"({ratio:.2f}x) exceeds maximum of "
                f"{max_uncompressed_ratio}x "
                f"(GZip bomb protection)"
            )

    finally:
        raw_file.close()


def validate_gz(
    func_or_path=None,
    max_file_size=None,
    max_uncompressed_ratio=None,
    max_uncompressed_size=None):
    """Validate GZip files via decorator or direct invocation.

    A GZip file validator that can operate in two modes:

    1. **Decorator mode** — wraps a function to validate a GZip file path passed as an argument before the function body runs.

    2. **Direct call / CLI mode** — validates a file immediately and returns a boolean result.

    Security checks performed:

    - Compressed file size limits
    - GZip decompression ratio limits
    - Maximum uncompressed size
    - Streaming decompression
    - GZip CRC/trailer validation
    - GZip concatenated-member validation
    - Regular-file validation (local)
    - Symlink protection where supported (local)
    - Detection of file-size changes during validation (local)
    - Remote files restricted to ``https://`` only

    Usage:

        Bare decorator::

            @validate_gz
            def process(path):
                ...

        Decorator with defaults::

            @validate_gz()
            def process(path):
                ...

        Decorator with custom argument name and options::

            @validate_gz("custom_arg_name", max_file_size=5000)
            def process(custom_arg_name):
                ...

        Direct validation of a local file::

            validate_gz("path/to/file.gz", max_uncompressed_size=1000000)

        Direct validation of a remote file (HTTPS only)::

            validate_gz("https://example.com/file.gz")

    Args:
        func_or_path (callable, str, pathlib.Path, or None):
            Controls the operating mode:

            * If a **callable**: the function to decorate
            (bare decorator usage: ``@validate_gz``).

            * If a **str** or **Path** representing a file path or HTTPS URL:
            direct validation mode.

            * If a **str** that is a valid Python identifier and does not
            look like a file path: treated as the target argument name in decorator mode.

            * If **None**: returns a decorator factory.

        max_file_size (int):

            Maximum allowed compressed file size in bytes.

        max_uncompressed_ratio (int):

            Maximum GZip decompression ratio.

        max_uncompressed_size (int):

            Maximum total uncompressed size in bytes.

    Returns:

        Union[callable, bool, function]:

        * In decorator mode: the wrapped function.
        * In direct call mode: ``True`` if validation passes, ``False`` if validation fails.

    Raises:

        GzValidationError:

            If validation fails in decorator mode.
        
        ValueError:

            If a security limit is invalid.
    """
    # ---------------------------------------------------------------
    # Resolve optional limits to defaults
    # ---------------------------------------------------------------

    resolved_file_size = (
        DEFAULT_MAX_FILE_SIZE
        if max_file_size is None
        else max_file_size
    )

    resolved_ratio = (
        DEFAULT_MAX_UNCOMPRESSED_RATIO
        if max_uncompressed_ratio is None
        else max_uncompressed_ratio
    )

    resolved_uncompressed_size = (
        DEFAULT_MAX_UNCOMPRESSED_SIZE
        if max_uncompressed_size is None
        else max_uncompressed_size
    )

    # Validate configuration immediately.
    _validate_limit(
        "max_file_size",
        resolved_file_size
    )

    _validate_limit(
        "max_uncompressed_ratio",
        resolved_ratio
    )

    _validate_limit(
        "max_uncompressed_size",
        resolved_uncompressed_size
    )
   
    
    # ---------------------------------------------------------------
    # Determine whether a string looks like a file path
    # ---------------------------------------------------------------

    def _looks_like_file_path(value):
        """
        Heuristic: does this string look like a file path?
        """
        # ONLY https:// is accepted as a remote URL
        if value.startswith("https://"):
            return True

        if value.startswith(("/", "\\")):
            return True

        if "/" in value or "\\" in value:
            return True

        if "." in value and not value.startswith("."):
            return True

        return False

    # ---------------------------------------------------------------
    # Determine operating mode
    # ---------------------------------------------------------------

    is_decorator_mode = False

    if func_or_path is None:
        is_decorator_mode = True

    elif callable(func_or_path):
        is_decorator_mode = True

    elif isinstance(func_or_path, str):
        # FIX: A string is only an argument name if it is a valid
        # Python identifier AND does not look like a file path.
        is_decorator_mode = (
            func_or_path.isidentifier()
            and not _looks_like_file_path(func_or_path)
        )

    elif isinstance(func_or_path, Path):
        is_decorator_mode = False

    else:
        raise TypeError(
            "Expected callable, str, pathlib.Path, or None, "
            f"got {type(func_or_path).__name__}"
        )

    # ---------------------------------------------------------------
    # Direct call / CLI mode
    # ---------------------------------------------------------------

    if not is_decorator_mode and isinstance(
        func_or_path,
        (str, Path)
    ):
        try:
            _validate_gz_file(
                func_or_path,
                resolved_file_size,
                resolved_ratio,
                resolved_uncompressed_size
            )

            return True

        except GzValidationError:
            # Direct invocation intentionally has a boolean API.            
            # Do not catch Exception here: programming/configuration errors
            # must not be silently hidden.
            return False

    # ---------------------------------------------------------------
    # Decorator mode
    # ---------------------------------------------------------------

    def decorator(f):
        try:
            sig = inspect.signature(f)

        except (TypeError, ValueError) as e:
            raise GzValidationError(
                f"Unable to inspect function '{f.__name__}': {e}"
            ) from e

        params = list(sig.parameters.values())

        if not params:
            raise GzValidationError(
                f"Decorator applied to '{f.__name__}', "
                "but it has no arguments."
            )

        # -----------------------------------------------------------
        # Determine target argument
        # -----------------------------------------------------------

        if (
            isinstance(func_or_path, str)
            and func_or_path in sig.parameters
        ):
            target_arg = func_or_path

        else:
            positional_params = [
                p for p in params
                if p.kind in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD
                )
            ]

            if not positional_params:
                raise GzValidationError(
                    f"Decorator applied to '{f.__name__}', but it has "
                    "no positional argument available for the GZip path. "
                    "Specify the argument name explicitly."
                )

            target_arg = positional_params[0].name

        target_parameter = sig.parameters[target_arg]

        if target_parameter.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD
        ):
            raise GzValidationError(
                f"Argument '{target_arg}' cannot contain the GZip path"
            )

        # -----------------------------------------------------------
        # Wrapped function
        # -----------------------------------------------------------

        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()

            except TypeError as e:
                raise GzValidationError(
                    f"Invalid function call signature: {e}"
                ) from e

            p = bound_args.arguments.get(target_arg)

            if p is None:
                raise GzValidationError(
                    f"Missing required argument: {target_arg}"
                )

            if not isinstance(p, (str, Path, os.PathLike)):
                raise GzValidationError(
                    f"Expected Path or str for {target_arg}, "
                    f"got {type(p).__name__}"
                )

            _validate_gz_file(
                p,
                resolved_file_size,
                resolved_ratio,
                resolved_uncompressed_size
            )

            return f(*args, **kwargs)

        return wrapper

    # ---------------------------------------------------------------
    # Bare decorator usage: @validate_gz
    # ---------------------------------------------------------------

    if callable(func_or_path):
        return decorator(func_or_path)

    # ---------------------------------------------------------------
    # Factory usage: @validate_gz(...)
    # ---------------------------------------------------------------

    return decorator