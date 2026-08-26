"""
License MPL-2.0
(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/
FileAudit - TAR Security Checker
"""
import gzip
import tarfile
import io
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import urlparse
from functools import wraps
import inspect


# Global default fallbacks
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_UNCOMPRESSED_RATIO = 100  # 100:1 ratio
DEFAULT_MAX_TAR_MEMBERS = 1000
DEFAULT_MAX_TOTAL_EXTRACTED_SIZE = 100 * 1024 * 1024  # 100 MB
DEFAULT_MAX_INDIVIDUAL_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_FILENAME_LENGTH = 255
DEFAULT_MAX_DIRECTORY_DEPTH = 50


class TarValidationError(Exception):
    """Custom exception for TAR validation failures in FileAudit."""
    
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
            raise TarValidationError(
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
    Raises TarValidationError for any non-HTTPS URL.
    """
    parsed = urlparse(path_str)
    
    if parsed.scheme:
        if parsed.scheme.lower() != "https":
            raise TarValidationError(
                f"Unsupported URL scheme '{parsed.scheme}': only 'https' is allowed."
            )
        return True
    elif parsed.netloc:
        # Protocol-relative URLs like //example.com/file.tar.gz
        raise TarValidationError(
            "URL scheme must be explicitly 'https'. Protocol-relative URLs are not allowed."
        )
    
    return False


def _check_tar_member(member, base_path, max_individual_size, max_filename_length, max_depth):
    """
    Validate a single TAR member for security issues.
    
    Args:
        member: TarInfo object
        base_path: Path object for the extraction base directory
        max_individual_size: Maximum allowed size for individual files
        max_filename_length: Maximum allowed filename/path length
        max_depth: Maximum allowed directory depth
    
    Raises:
        TarValidationError: If any security check fails
    """
    
    # 1. Reject symlinks, hardlinks, devices, and FIFOs
    if member.issym() or member.islnk():
        raise TarValidationError(
            f"Rejected {member.name}: Symlinks and hardlinks are not allowed"
        )
    
    if member.isdev() or member.isfifo():
        raise TarValidationError(
            f"Rejected {member.name}: Device files and FIFOs are not allowed"
        )
    
    # 2. Filename/path length limits
    if len(member.name) > max_filename_length:
        raise TarValidationError(
            f"Rejected {member.name}: Path length ({len(member.name)}) exceeds "
            f"maximum of {max_filename_length} characters"
        )
    
    # 3. Path traversal protection
    # Resolve the full path and check if it's within the extraction directory
    member_path = (base_path / member.name).resolve()
    try:
        # Check if the resolved path is still within the base directory
        member_path.relative_to(base_path.resolve())
    except ValueError:
        raise TarValidationError(
            f"Rejected {member.name}: Path traversal attempt detected"
        )
    
    # 4. Directory depth limits
    # Count path components
    path_parts = Path(member.name).parts
    depth = len(path_parts) if member.name else 0
    if depth > max_depth:
        raise TarValidationError(
            f"Rejected {member.name}: Directory depth ({depth}) exceeds "
            f"maximum of {max_depth}"
        )
    
    # 5. Individual file size limits (for regular files only)
    if member.isfile() and member.size > max_individual_size:
        raise TarValidationError(
            f"Rejected {member.name}: File size ({member.size} bytes) exceeds "
            f"maximum individual file size of {max_individual_size} bytes"
        )


def validate_tar_gz(func_or_path=None, 
                    max_file_size=None,
                    max_uncompressed_ratio=None,
                    max_tar_members=None,
                    max_total_extracted_size=None,
                    max_individual_file_size=None,
                    max_filename_length=None,
                    max_directory_depth=None):
    """
    Validate TAR.GZ files via decorator or direct invocation.
    
    A TAR.GZ file validator that can operate in two modes:
    
    1. **Decorator mode** — wraps a function to validate a TAR.GZ file path
       passed as an argument before the function body runs.
    2. **Direct call / CLI mode** — validates a file immediately and returns
       a boolean result.
    
    Security checks performed:
    - File size limits
    - GZip decompression ratio limits
    - Tar member count limits
    - Tar total extracted size limits
    - Tar individual file size limits
    - Tar path traversal protection
    - Reject symlinks/hardlinks/devices/FIFOs
    - Filename/path length limits
    - Directory depth limits
    
    Usage:
        @validate_tar_gz
        @validate_tar_gz()
        @validate_tar_gz("custom_arg_name", max_file_size=5000)
        validate_tar_gz("path/to/file.tar.gz", max_tar_members=100)  # CLI usage
    
    Args:
        func_or_path (callable, str, pathlib.Path, or None):
            * If a **callable**: the function to decorate (bare decorator
              usage: ``@validate_tar_gz``).
            * If a **str** or **Path**: the file path to validate (direct call).
            * If a **str** that is a valid Python identifier: treated as the
              target argument name in decorator mode.
            * If **None**: returns a decorator factory.
        max_file_size (int): Maximum allowed compressed file size in bytes.
        max_uncompressed_ratio (int): Maximum GZip decompression ratio.
        max_tar_members (int): Maximum number of files/directories in TAR.
        max_total_extracted_size (int): Maximum total extracted size in bytes.
        max_individual_file_size (int): Maximum size per extracted file.
        max_filename_length (int): Maximum filename/path length.
        max_directory_depth (int): Maximum directory nesting depth.
    
    Returns:
        Union[callable, bool, function]:
            * In decorator mode: the wrapped function.
            * In direct call mode: ``True`` if validation passes,
              ``False`` if it fails (errors are printed to stdout).
    
    Raises:
        TarValidationError: If validation fails in decorator mode.
    """
    
    # Resolve optional limits to defaults
    resolved_file_size = DEFAULT_MAX_FILE_SIZE if max_file_size is None else max_file_size
    resolved_ratio = DEFAULT_MAX_UNCOMPRESSED_RATIO if max_uncompressed_ratio is None else max_uncompressed_ratio
    resolved_members = DEFAULT_MAX_TAR_MEMBERS if max_tar_members is None else max_tar_members
    resolved_total_size = DEFAULT_MAX_TOTAL_EXTRACTED_SIZE if max_total_extracted_size is None else max_total_extracted_size
    resolved_individual_size = DEFAULT_MAX_INDIVIDUAL_FILE_SIZE if max_individual_file_size is None else max_individual_file_size
    resolved_filename_len = DEFAULT_MAX_FILENAME_LENGTH if max_filename_length is None else max_filename_length
    resolved_depth = DEFAULT_MAX_DIRECTORY_DEPTH if max_directory_depth is None else max_directory_depth
    
    def _looks_like_file_path(s):
        """Heuristic: does this string look like a file path or URL?"""
        # ONLY https:// is accepted as a remote URL
        if s.startswith("https://"):
            return True
        if s.startswith(("/", "\\")):
            return True
        if "/" in s or "\\" in s:
            return True
        if "." in s and not s.startswith("."):
            return True
        return False
    
    is_decorator_mode = False
    
    if func_or_path is None:
        is_decorator_mode = True
    elif callable(func_or_path):
        is_decorator_mode = True
    elif isinstance(func_or_path, str):
        is_decorator_mode = not _looks_like_file_path(func_or_path)
    elif isinstance(func_or_path, Path):
        is_decorator_mode = False
    
    # Direct call / CLI mode
    if not is_decorator_mode and isinstance(func_or_path, (str, Path)):
        try:
            _validate_tar_gz_file(
                func_or_path,
                resolved_file_size,
                resolved_ratio,
                resolved_members,
                resolved_total_size,
                resolved_individual_size,
                resolved_filename_len,
                resolved_depth
            )
            return True
        except Exception as e:
            print(f"Exception: {e}")
            return False
    
    # Decorator mode
    def decorator(f):
        sig = inspect.signature(f)
        params = list(sig.parameters.keys())
        
        if not params:
            raise TarValidationError(
                f"Decorator applied to '{f.__name__}', but it has no arguments."
            )
        
        target_arg = func_or_path if isinstance(func_or_path, str) and func_or_path in params else params[0]
        
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
            except TypeError as e:
                raise TarValidationError(f"Invalid function call signature: {e}")
            
            p = bound_args.arguments.get(target_arg)
            
            if p is None:
                raise TarValidationError(f"Missing required argument: {target_arg}")
            
            if isinstance(p, (str, Path)):
                _validate_tar_gz_file(
                    p,
                    resolved_file_size,
                    resolved_ratio,
                    resolved_members,
                    resolved_total_size,
                    resolved_individual_size,
                    resolved_filename_len,
                    resolved_depth
                )
            else:
                raise TarValidationError(
                    f"Expected Path or str for {target_arg}, got {type(p).__name__}"
                )
            
            return f(*args, **kwargs)
        return wrapper
    
    if callable(func_or_path):
        return decorator(func_or_path)
    
    return decorator


def _validate_tar_gz_file(path, max_file_size, max_uncompressed_ratio, 
                          max_tar_members, max_total_extracted_size,
                          max_individual_file_size, max_filename_length,
                          max_directory_depth):
    """
    Internal validation function for TAR.GZ files.
    
    Performs all security checks on a TAR.GZ file.
    """
    path_str = str(path)
    
    # Strict HTTPS-only validation: rejects http://, ftp://, file://, //example.com
    is_remote = _validate_url_scheme(path_str)
    
    # Get file content as bytes (either local or remote)
    try:
        if is_remote:
            req = urllib.request.Request(path_str)
            with _https_opener.open(req, timeout=30) as response:
                compressed_data = response.read()
                if len(compressed_data) > max_file_size:
                    raise TarValidationError(
                        f"Remote file size ({len(compressed_data)} bytes) exceeds "
                        f"maximum of {max_file_size} bytes"
                    )
        else:
            local_path = Path(path)
            if not local_path.exists():
                raise TarValidationError(f"File not found: {local_path}")
            if not local_path.is_file():
                raise TarValidationError(f"Path is not a file: {local_path}")
            
            if local_path.stat().st_size > max_file_size:
                raise TarValidationError(
                    f"File size ({local_path.stat().st_size} bytes) exceeds "
                    f"maximum of {max_file_size} bytes"
                )
            
            with local_path.open('rb') as f:
                compressed_data = f.read()
    
    except TarValidationError:
        raise
    except urllib.error.HTTPError as e:
        raise TarValidationError(f"Remote file unreachable (HTTP {e.code})") from e
    except urllib.error.URLError as e:
        raise TarValidationError(f"Could not reach remote file: {e.reason}") from e
    except Exception as e:
        raise TarValidationError(f"Failed to read file: {e}") from e
    
    # Decompress and check ratio
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
            decompressed_data = gz.read()
            original_size = len(compressed_data)
            decompressed_size = len(decompressed_data)
            
            # Check decompression ratio
            if original_size > 0:
                ratio = decompressed_size / original_size
                if ratio > max_uncompressed_ratio:
                    raise TarValidationError(
                        f"Decompression ratio ({ratio:.2f}x) exceeds maximum "
                        f"of {max_uncompressed_ratio}x (zip bomb protection)"
                    )
    
    except gzip.BadGzipFile as e:
        raise TarValidationError(f"Invalid GZip format: {e}") from e
    except Exception as e:
        raise TarValidationError(f"GZip decompression failed: {e}") from e
    
    # Now parse the TAR archive from the decompressed data
    try:
        with tarfile.open(fileobj=io.BytesIO(decompressed_data), mode='r') as tar:
            members = tar.getmembers()
            
            # Check member count
            if len(members) > max_tar_members:
                raise TarValidationError(
                    f"Archive contains {len(members)} members, exceeding "
                    f"maximum of {max_tar_members}"
                )
            
            # Create a temporary base path for path traversal checks
            temp_base = Path("/tmp/tar_validation_extract")
            
            # Check total extracted size
            total_size = sum(member.size for member in members if member.isfile())
            if total_size > max_total_extracted_size:
                raise TarValidationError(
                    f"Total extracted size ({total_size} bytes) exceeds "
                    f"maximum of {max_total_extracted_size} bytes"
                )
            
            # Validate each member
            for member in members:
                _check_tar_member(
                    member,
                    temp_base,
                    max_individual_file_size,
                    max_filename_length,
                    max_directory_depth
                )
    
    except tarfile.TarError as e:
        raise TarValidationError(f"Invalid TAR archive: {e}") from e
    except Exception as e:
        raise TarValidationError(f"TAR validation failed: {e}") from e