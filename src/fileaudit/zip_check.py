"""
License GPL3
(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/
FileAudit - ZIP File Security Checker
"""

import inspect
import os
import re
import stat
import tempfile
import urllib.request
import urllib.error
import zipfile
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse
import unicodedata

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024          # 100 MiB
DEFAULT_MAX_UNCOMPRESSED_RATIO = 100               # 100:1
DEFAULT_MAX_ZIP_MEMBERS = 10_000
DEFAULT_MAX_TOTAL_EXTRACTED_SIZE = 1 * 1024 * 1024**3  # 1 GiB
DEFAULT_MAX_INDIVIDUAL_FILE_SIZE = 100 * 1024 * 1024   # 100 MiB
DEFAULT_MAX_FILENAME_LENGTH = 255
DEFAULT_MAX_DIRECTORY_DEPTH = 20

HEAD_TIMEOUT = 10
DOWNLOAD_TIMEOUT = 30

_WIN_DRIVE_RE = re.compile(r'^[A-Za-z]:[\\/]')

def _validate_positive_int(name, value):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ZipValidationError(
            f"{name} must be an integer"
        )

    if value <= 0:
        raise ZipValidationError(
            f"{name} must be greater than zero"
        )


def _validate_limits(
    max_file_size,
    max_uncompressed_ratio,
    max_zip_members,
    max_total_extracted_size,
    max_individual_file_size,
    max_filename_length,
    max_directory_depth,
):
    _validate_positive_int("max_file_size", max_file_size)
    _validate_positive_int("max_zip_members", max_zip_members)
    _validate_positive_int(
        "max_total_extracted_size",
        max_total_extracted_size,
    )
    _validate_positive_int(
        "max_individual_file_size",
        max_individual_file_size,
    )
    _validate_positive_int(
        "max_filename_length",
        max_filename_length,
    )
    _validate_positive_int(
        "max_directory_depth",
        max_directory_depth,
    )

    if (
        not isinstance(max_uncompressed_ratio, (int, float))
        or isinstance(max_uncompressed_ratio, bool)
    ):
        raise ZipValidationError(
            "max_uncompressed_ratio must be a number"
        )

    if max_uncompressed_ratio <= 0:
        raise ZipValidationError(
            "max_uncompressed_ratio must be greater than zero"
        )

# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------
class ZipValidationError(Exception):
    """Raised when a ZIP archive fails security validation."""

class HTTPSOnlyRedirectHandler(
    urllib.request.HTTPRedirectHandler
):
    """Allow redirects only to valid HTTPS URLs."""

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        parsed = urlparse(newurl)

        if parsed.scheme.lower() != "https":
            raise ZipValidationError(
                "Redirect blocked: target URL must use HTTPS."
            )

        if not parsed.netloc:
            raise ZipValidationError(
                "Redirect blocked: target URL has no hostname."
            )

        if (
            parsed.username is not None
            or parsed.password is not None
        ):
            raise ZipValidationError(
                "Redirect blocked: credentials in URLs are not allowed."
            )

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            newurl,
        )


# Opener that enforces HTTPS on redirects
_https_opener = urllib.request.build_opener(HTTPSOnlyRedirectHandler)

def _validate_url_scheme(path_str):
    """
    Return True for valid HTTPS URLs.

    Return False for local filesystem paths.

    Raise ZipValidationError for unsupported or malformed URLs.
    """

    if _WIN_DRIVE_RE.match(path_str):
        return False

    parsed = urlparse(path_str)

    # No scheme means local path.
    if not parsed.scheme:
        if parsed.netloc:
            raise ZipValidationError(
                "URL scheme must be explicitly 'https'. "
                "Protocol-relative URLs are not allowed."
            )

        return False

    if parsed.scheme.lower() != "https":
        raise ZipValidationError(
            f"Unsupported URL scheme '{parsed.scheme}': "
            "only 'https' is allowed."
        )

    if not parsed.netloc:
        raise ZipValidationError(
            f"Invalid HTTPS URL: {path_str!r}"
        )

    if parsed.username is not None or parsed.password is not None:
        raise ZipValidationError(
            "HTTPS URLs containing username/password credentials "
            "are not allowed."
        )

    return True



def _looks_like_file_path(s):
    """Heuristic: does this string look like a file path or URL?"""
    if s.startswith("https://"):
        return True
    if s.startswith(("/", "\\")):
        return True
    if "/" in s or "\\" in s:
        return True
    # Contains a dot that looks like a file extension (but not a hidden file)
    if "." in s and not s.startswith("."):
        return True
    return False


# ---------------------------------------------------------------------------
# ZIP validation implementation
# ---------------------------------------------------------------------------
def _validate_zip_file(
    path,
    max_file_size,
    max_uncompressed_ratio,
    max_zip_members,
    max_total_extracted_size,
    max_individual_file_size,
    max_filename_length,
    max_directory_depth,
):
    """
    Validate a ZIP archive without extracting it.
    Supports both local file paths and remote HTTPS URLs.
    Raises:
        ZipValidationError: If the archive fails any security check.
    """
    _validate_limits(
        max_file_size=max_file_size,
        max_uncompressed_ratio=max_uncompressed_ratio,
        max_zip_members=max_zip_members,
        max_total_extracted_size=max_total_extracted_size,
        max_individual_file_size=max_individual_file_size,
        max_filename_length=max_filename_length,
        max_directory_depth=max_directory_depth,
    )

    path_str = str(path)
    if is_remote:
        request = urllib.request.Request(
        path_str,
        headers={
            "User-Agent": "FileAudit-ZIPValidator/1.0",
        },
        method="GET",
    )

    try:
        with _https_opener.open(
            request,
            timeout=DOWNLOAD_TIMEOUT,
        ) as response:

            # Validate the final URL as well.
            final_url = response.geturl()
            _validate_url_scheme(final_url)

            tmp = tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".zip",
            )

            temp_path = tmp.name

            try:
                total = 0

                while True:
                    chunk = response.read(65536)

                    if not chunk:
                        break

                    total += len(chunk)

                    if total > max_file_size:
                        raise ZipValidationError(
                            "Remote file exceeded maximum size "
                            f"({max_file_size} bytes) during download"
                        )

                    tmp.write(chunk)

            finally:
                tmp.close()

            path = temp_path

    except ZipValidationError:
        raise

    except urllib.error.HTTPError as e:
        raise ZipValidationError(
            f"Remote file unreachable (HTTP {e.code}): "
            f"{path_str}"
        ) from e

    except urllib.error.URLError as e:
        raise ZipValidationError(
            f"Could not reach remote file: {path_str} — "
            f"{e.reason}"
        ) from e

    except OSError as e:
        raise ZipValidationError(
            f"Unable to download remote ZIP: {path_str} — {e}"
        ) from e
        
    is_remote = _validate_url_scheme(path_str)
    temp_path = None

    try:
        if is_remote:
            request = urllib.request.Request(
                path_str,
                headers={
                    "User-Agent": "FileAudit-ZIPValidator/1.0",
                },
                method="GET",
            )

            try:
                with _https_opener.open(
                    request,
                    timeout=DOWNLOAD_TIMEOUT,
                ) as response:

                    # Validate the final URL as well.
                    final_url = response.geturl()
                    _validate_url_scheme(final_url)

                    tmp = tempfile.NamedTemporaryFile(
                        delete=False,
                        suffix=".zip",
                    )

                    temp_path = tmp.name

                    try:
                        total = 0

                        while True:
                            chunk = response.read(65536)

                            if not chunk:
                                break

                            total += len(chunk)

                            if total > max_file_size:
                                raise ZipValidationError(
                                    "Remote file exceeded maximum size "
                                    f"({max_file_size} bytes) during download"
                                )

                            tmp.write(chunk)

                    finally:
                        tmp.close()

                    path = temp_path

            except ZipValidationError:
                raise

            except urllib.error.HTTPError as e:
                raise ZipValidationError(
                    f"Remote file unreachable (HTTP {e.code}): "
                    f"{path_str}"
                ) from e

            except urllib.error.URLError as e:
                raise ZipValidationError(
                    f"Could not reach remote file: {path_str} — "
                    f"{e.reason}"
                ) from e

            except OSError as e:
                raise ZipValidationError(
                    f"Unable to download remote ZIP: {path_str} — {e}"
                ) from e

        
        # === Existing local-file validation logic =================================
        path = Path(path)

        if not path.exists():
            raise ZipValidationError(f"ZIP file does not exist: {path}")
        if not path.is_file():
            raise ZipValidationError(f"ZIP path is not a regular file: {path}")

        # -----------------------------------------------------------------------
        # Compressed archive size
        # -----------------------------------------------------------------------
        try:
            file_size = path.stat().st_size
        except OSError as e:
            raise ZipValidationError(
                f"Unable to stat ZIP file '{path}': {e}"
            ) from e

        if file_size > max_file_size:
            raise ZipValidationError(
                f"ZIP file is too large: {file_size} bytes "
                f"(maximum {max_file_size})"
            )

        # -----------------------------------------------------------------------
        # Open archive
        # -----------------------------------------------------------------------
        try:
            with zipfile.ZipFile(path, "r") as zf:  # NOSEC -- This is a security checker
                infos = zf.infolist()

                if len(infos) > max_zip_members:
                    raise ZipValidationError(
                        f"ZIP contains too many members: {len(infos)} "
                        f"(maximum {max_zip_members})"
                    )

                total_uncompressed_size = 0
                seen_names = set()

                for info in infos:
                    filename = info.filename

                    # -----------------------------------------------------------
                    # Basic filename validation
                    # -----------------------------------------------------------
                    if not filename:
                        raise ZipValidationError(
                            "ZIP contains an entry with an empty filename"
                        )
                    if "\x00" in filename:
                        raise ZipValidationError(
                            f"ZIP entry contains a NUL byte: {filename!r}"
                        )
                    # ZIP uses '/' internally, but '\' can become a path
                    # separator when the archive is later processed on Windows.
                    if "\\" in filename:
                        raise ZipValidationError(
                            f"ZIP entry contains a backslash in its path: "
                            f"{filename!r}"
                        )

                    # Measure encoded filename length rather than Python's
                    # character count. This is closer to filesystem limits.
                    filename_length = len(filename.encode("utf-8"))
                    if filename_length > max_filename_length:
                        raise ZipValidationError(
                            f"ZIP entry filename is too long: "
                            f"{filename_length} bytes "
                            f"(maximum {max_filename_length}): {filename!r}"
                        )

                    # -----------------------------------------------------------
                    # Duplicate names
                    # -----------------------------------------------------------
                    normalized_name = unicodedata.normalize(
                        "NFC",
                        filename,
                    )

                    if normalized_name in seen_names:
                        raise ZipValidationError(
                            f"ZIP contains duplicate filename after Unicode "
                            f"normalization: {filename!r}"
                        )
                    seen_names.add(normalized_name)
                    # -----------------------------------------------------------
                    # Path traversal protection
                    # -----------------------------------------------------------
                    if filename.startswith("/"):
                        raise ZipValidationError(
                            f"ZIP contains an absolute path: {filename!r}"
                        )
                    if (
                        len(filename) >= 2
                        and filename[1] == ":"
                        and filename[0].isalpha()
                    ):
                        raise ZipValidationError(
                            f"ZIP contains a Windows drive path: {filename!r}"
                        )
                    if filename.startswith("//"):
                        raise ZipValidationError(
                            f"ZIP contains a UNC-style path: {filename!r}"
                        )

                    parts = filename.split("/")

                    for part in parts:
                        if part == "..":
                            raise ZipValidationError(
                                f"ZIP contains a path traversal component: "
                                f"{filename!r}"
                            )

                        if part == ".":
                            raise ZipValidationError(
                                f"ZIP contains an ambiguous '.' path component: "
                                f"{filename!r}"
                            )

                    # -----------------------------------------------------------
                    # Directory depth
                    # -----------------------------------------------------------
                    is_directory = filename.endswith("/")
                    unix_mode = (info.external_attr >> 16) & 0xFFFF
                    if unix_mode and stat.S_ISDIR(unix_mode):
                        is_directory = True
                    elif info.external_attr & 0x10:
                        is_directory = True

                    depth_parts = [p for p in parts if p not in ("", ".")]
                    depth = len(depth_parts)
                    if not is_directory and depth > 0:
                        depth -= 1

                    if depth > max_directory_depth:
                        raise ZipValidationError(
                            f"ZIP entry exceeds maximum directory depth: "
                            f"{filename!r} "
                            f"(depth {depth}, maximum {max_directory_depth})"
                        )

                    # -----------------------------------------------------------
                    # ZIP member type / symlink protection
                    # -----------------------------------------------------------
                    if unix_mode:
                        file_type = stat.S_IFMT(unix_mode)
                        if file_type == stat.S_IFLNK:
                            raise ZipValidationError(
                                f"ZIP contains a symbolic link: {filename!r}"
                            )
                        if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                            raise ZipValidationError(
                                f"ZIP contains an unsupported special file: "
                                f"{filename!r}"
                            )

                    # -----------------------------------------------------------
                    # Encryption
                    # -----------------------------------------------------------
                    if info.flag_bits & 0x1:
                        raise ZipValidationError(
                            f"ZIP contains an encrypted entry: {filename!r}"
                        )

                    # -----------------------------------------------------------
                    # Compression method
                    # -----------------------------------------------------------
                    supported_methods = {
                        zipfile.ZIP_STORED,
                        zipfile.ZIP_DEFLATED,
                        zipfile.ZIP_BZIP2,
                        zipfile.ZIP_LZMA,
                    }
                    if info.compress_type not in supported_methods:
                        raise ZipValidationError(
                            f"ZIP entry uses an unsupported compression method: "
                            f"{filename!r}"
                        )

                    # -----------------------------------------------------------
                    # Size validation
                    # -----------------------------------------------------------
                    uncompressed_size = info.file_size
                    compressed_size = info.compress_size

                    if is_directory:
                        if uncompressed_size > 0:
                            raise ZipValidationError(
                                f"Directory entry contains data: {filename!r}"
                            )
                        continue

                    if uncompressed_size > max_individual_file_size:
                        raise ZipValidationError(
                            f"ZIP entry is too large: {filename!r} "
                            f"({uncompressed_size} bytes, "
                            f"maximum {max_individual_file_size})"
                        )

                    # Protect against ZIP bombs
                    if uncompressed_size > 0:
                        if compressed_size == 0:
                            raise ZipValidationError(
                                f"ZIP entry has uncompressed data but zero "
                                f"compressed size: {filename!r}"
                            )
                        ratio = uncompressed_size / compressed_size
                        if ratio > max_uncompressed_ratio:
                            raise ZipValidationError(
                                f"ZIP entry has an excessive compression ratio: "
                                f"{filename!r} "
                                f"({ratio:.2f}:1, maximum "
                                f"{max_uncompressed_ratio}:1)"
                            )

                    total_uncompressed_size += uncompressed_size
                    if total_uncompressed_size > max_total_extracted_size:
                        raise ZipValidationError(
                            f"ZIP total uncompressed size is too large: "
                            f"{total_uncompressed_size} bytes "
                            f"(maximum {max_total_extracted_size})"
                        )

        except ZipValidationError:
            raise
        except zipfile.BadZipFile as e:
            raise ZipValidationError(
                f"Invalid or corrupt ZIP file: {e}"
            ) from e
        except (OSError, EOFError, RuntimeError, ValueError) as e:
            raise ZipValidationError(
                f"Unable to validate ZIP file '{path}': {e}"
            ) from e
    finally:
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass #NOSEC


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def validate_zip(
    func_or_path=None,
    max_file_size=None,
    max_uncompressed_ratio=None,
    max_zip_members=None,
    max_total_extracted_size=None,
    max_individual_file_size=None,
    max_filename_length=None,
    max_directory_depth=None,
):
    """Validate ZIP files via decorator or direct invocation.

    Supports:

    1. Bare decorator::

        @validate_zip
        def process(path):
            ...
    
    2. Decorator factory::

        @validate_zip()
        def process(path):
            ...
    
    3. Named function argument::

        @validate_zip("zip_path")
        def process(zip_path):
            ...
    
    4. Named argument with limits::

        @validate_zip(
            "zip_path",
            max_file_size=500 * 1024 * 1024,
            max_zip_members=5000,
        )
        
        def process(zip_path):
            ...
    
    5. Direct / CLI invocation (local)::

        validate_zip("archive.zip")
    
    6. Direct / CLI invocation (remote HTTPS)::

        validate_zip("https://example.com/archive.zip")

    Returns:

        In decorator mode:

        - The decorated function.

        In direct mode:

        - True if validation succeeds, False otherwise.

    Raises:

        - ZipValidationError:
              
        If validation fails in decorator mode.
    """
    # Resolve optional limits to defaults.
    resolved_file_size = (
        DEFAULT_MAX_FILE_SIZE if max_file_size is None else max_file_size
    )
    resolved_ratio = (
        DEFAULT_MAX_UNCOMPRESSED_RATIO
        if max_uncompressed_ratio is None
        else max_uncompressed_ratio
    )
    resolved_members = (
        DEFAULT_MAX_ZIP_MEMBERS if max_zip_members is None else max_zip_members
    )
    resolved_total_size = (
        DEFAULT_MAX_TOTAL_EXTRACTED_SIZE
        if max_total_extracted_size is None
        else max_total_extracted_size
    )
    resolved_individual_size = (
        DEFAULT_MAX_INDIVIDUAL_FILE_SIZE
        if max_individual_file_size is None
        else max_individual_file_size
    )
    resolved_filename_len = (
        DEFAULT_MAX_FILENAME_LENGTH
        if max_filename_length is None
        else max_filename_length
    )
    resolved_depth = (
        DEFAULT_MAX_DIRECTORY_DEPTH
        if max_directory_depth is None
        else max_directory_depth
    )

    # ---------------------------------------------------------------
    # Determine whether this is decorator or direct-call mode.
    # ---------------------------------------------------------------
    is_decorator_mode = False
    if func_or_path is None:
        is_decorator_mode = True
    elif callable(func_or_path):
        # @validate_zip
        is_decorator_mode = True
    elif isinstance(func_or_path, Path):
        # validate_zip(Path("archive.zip"))
        is_decorator_mode = False
    elif isinstance(func_or_path, str):
        # A string that looks like a path/URL is direct-call mode.
        # A plain identifier is treated as a target argument name.
        is_decorator_mode = not _looks_like_file_path(func_or_path)

    # ---------------------------------------------------------------
    # Direct call / CLI mode.
    # ---------------------------------------------------------------
    if not is_decorator_mode and isinstance(func_or_path, (str, Path)):
        try:
            _validate_zip_file(
                func_or_path,
                resolved_file_size,
                resolved_ratio,
                resolved_members,
                resolved_total_size,
                resolved_individual_size,
                resolved_filename_len,
                resolved_depth,
            )
            return True
        except ZipValidationError as e:
            print(f"Exception: {e}")
            return False

    # ---------------------------------------------------------------
    # Decorator mode.
    # ---------------------------------------------------------------
    def decorator(f):
        sig = inspect.signature(f)
        params = list(sig.parameters.keys())

        if not params:
            raise ZipValidationError(
                f"Decorator applied to '{f.__name__}', "
                f"but it has no arguments."
            )

        # If the user supplied a valid argument name, use it.
        # Otherwise validate the first argument.
        if isinstance(func_or_path, str):
            if func_or_path in params:
                target_arg = func_or_path
            elif func_or_path.isidentifier():
                raise ZipValidationError(
                    f"'{func_or_path}' is not an argument of "
                    f"'{f.__name__}'. Available arguments: "
                    f"{', '.join(params)}"
                )
            else:
                target_arg = params[0]
        else:
            target_arg = params[0]

        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
            except TypeError as e:
                raise ZipValidationError(
                    f"Invalid function call signature: {e}"
                ) from e

            p = bound_args.arguments.get(target_arg)

            if p is None:
                raise ZipValidationError(
                    f"Missing required argument: {target_arg}"
                )

            if not isinstance(p, (str, Path)):
                raise ZipValidationError(
                    f"Expected Path or str for {target_arg}, "
                    f"got {type(p).__name__}"
                )

            _validate_zip_file(
                p,
                resolved_file_size,
                resolved_ratio,
                resolved_members,
                resolved_total_size,
                resolved_individual_size,
                resolved_filename_len,
                resolved_depth,
            )
            return f(*args, **kwargs)

        return wrapper

    if callable(func_or_path):
        return decorator(func_or_path)

    return decorator