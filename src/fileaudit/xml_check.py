"""
License GPL3
(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/
FileAudit - XML Security Checker with DDoS Protection
"""

import inspect
from pathlib import Path
from functools import wraps
import xml.etree.ElementTree as ET
from xml.parsers.expat import ExpatError
import urllib.request
import urllib.error
from urllib.parse import urlparse
import re
import gzip
import io



# Global default fallbacks
DEFAULT_MAX_DEPTH = 50
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_ATTRIBUTES = 1000
DEFAULT_MAX_ELEMENTS = 10_000
DEFAULT_MAX_TEXT_LENGTH = 100000  # 100KB per text node
DEFAULT_MAX_NAME_LENGTH = 100

_DOCTYPE_RE = re.compile(r"<!DOCTYPE", re.IGNORECASE)

HEAD_TIMEOUT = 10
DOWNLOAD_TIMEOUT = 30


class FileValidationError(Exception):
    """Custom exception for XML validation failures in FileAudit."""

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

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            newurl,
        )


# Opener that enforces HTTPS on redirects
_https_opener = urllib.request.build_opener(
    HTTPSOnlyRedirectHandler()
)


class XMLSecurityValidator:
    """XML security validator with comprehensive DDoS protection."""

    def __init__(
        self,
        max_depth=None,
        max_file_size=None,
        max_attributes=None,
        max_elements=None,
        max_text_length=None,
        max_name_length=None,
    ):
        # Use explicit None checks rather than `or`.        #
        # This means an explicitly supplied value such as 0 is
        # preserved instead of silently being replaced by the default.
        self.max_depth = (
            DEFAULT_MAX_DEPTH
            if max_depth is None
            else max_depth
        )

        self.max_file_size = (
            DEFAULT_MAX_FILE_SIZE
            if max_file_size is None
            else max_file_size
        )

        self.max_attributes = (
            DEFAULT_MAX_ATTRIBUTES
            if max_attributes is None
            else max_attributes
        )

        self.max_elements = (
            DEFAULT_MAX_ELEMENTS
            if max_elements is None
            else max_elements
        )

        self.max_text_length = (
            DEFAULT_MAX_TEXT_LENGTH
            if max_text_length is None
            else max_text_length
        )

        self.max_name_length = (
            DEFAULT_MAX_NAME_LENGTH
            if max_name_length is None
            else max_name_length
        )

        self.reset_counters()

    def reset_counters(self):
        """Reset internal counters."""
        self.element_count = 0

    def secure_parse(self, xml_content):
        """Parse XML and validate it against security limits."""
        self.reset_counters()

        try:
            parser = ET.XMLParser()

            root = ET.fromstring(
                xml_content,
                parser=parser,
            )

            self._validate_tree(root)

            return root

        except (ExpatError, ET.ParseError) as e:
            raise FileValidationError(
                f"XML parsing error: {e}"
            ) from e

        except RecursionError as e:
            raise FileValidationError(
                f"XML nesting too deep: {e}"
            ) from e

    def _validate_tree(self, root):
        """Validate an XML tree without recursion."""

        stack = [(root, 0)]

        while stack:
            element, depth = stack.pop()

            if depth > self.max_depth:
                raise FileValidationError(
                    f"XML nesting depth exceeds {self.max_depth}"
                )

            self.element_count += 1

            if self.element_count > self.max_elements:
                raise FileValidationError(
                    f"XML contains more than {self.max_elements} elements"
                )

            tag = str(element.tag)

            if len(tag) > self.max_name_length:
                raise FileValidationError(
                    f"Element name too long: {tag[:50]}"
                )

            if len(element.attrib) > self.max_attributes:
                raise FileValidationError(
                    f"Too many attributes on element '{tag}'"
                )

            for name, value in element.attrib.items():
                if len(str(name)) > self.max_name_length:
                    raise FileValidationError(
                        "Attribute name too long"
                    )

                if len(str(value)) > self.max_text_length:
                    raise FileValidationError(
                        "Attribute value too long"
                    )

            if element.text is not None:
                if len(str(element.text)) > self.max_text_length:
                    raise FileValidationError(
                        "Text node exceeds limit"
                    )

            if element.tail is not None:
                if len(str(element.tail)) > self.max_text_length:
                    raise FileValidationError(
                        "Tail text exceeds limit"
                    )

            for child in reversed(element):
                stack.append(
                    (child, depth + 1)
                )


def _reject_doctype(xml_content: str) -> None:
    """Reject XML containing a DOCTYPE declaration."""

    if _DOCTYPE_RE.search(xml_content):
        raise FileValidationError(
            "DOCTYPE declarations are not allowed."
        )


def _validate_url_scheme(path_str: str) -> bool:
    """
    Validate that a URL uses HTTPS only.

    Returns True if the path is a remote URL,
    False if it's a local path.

    Raises FileValidationError for any non-HTTPS URL.
    """

    parsed = urlparse(path_str)

    if parsed.scheme:
        if parsed.scheme.lower() != "https":
            raise FileValidationError(
                f"Unsupported URL scheme '{parsed.scheme}': "
                "only 'https' is allowed."
            )

        return True

    elif parsed.netloc:
        # Protocol-relative URLs like //example.com/file.xml
        raise FileValidationError(
            "URL scheme must be explicitly 'https'. "
            "Protocol-relative URLs are not allowed."
        )

    return False


def _read_gzip_stream(stream, max_file_size):
    """
    Read and decompress a gzip stream while limiting
    the decompressed size.
    """

    chunks = []
    total = 0

    while True:
        chunk = stream.read(8192)

        if not chunk:
            break

        total += len(chunk)

        if total > max_file_size:
            raise FileValidationError(
                "Decompressed file exceeds maximum allowed size."
            )

        chunks.append(chunk)

    return b"".join(chunks).decode(
        "utf-8",
        errors="strict",
    )



def _validate_xml_file(
    path,
    max_depth,
    max_file_size,
    max_attributes,
    max_elements,
    max_text_length,
    max_name_length,
):
    """Secure XML validation with DDoS protection."""

    path_str = str(path)

    # Validate URL scheme first — rejects http://, ftp://, file://, //example.com, etc.
    is_remote = _validate_url_scheme(path_str)

    if not is_remote:
        local_path = Path(path_str)

        if not local_path.exists():
            raise FileValidationError(
                f"File not found: {local_path}"
            )

        if not local_path.is_file():
            raise FileValidationError(
                f"Path is not a file: {local_path}"
            )

        try:
            file_size = local_path.stat().st_size

            if file_size > max_file_size:
                raise FileValidationError(
                    f"File size ({file_size} bytes) exceeds maximum "
                    f"limit of {max_file_size} bytes."
                )

        except OSError as e:
            raise FileValidationError(
                f"Could not read file metadata: {e}"
            ) from e

    else:
        # HEAD is only an optimization.
        # Some servers reject it, so ignore failures.
        try:
            req = urllib.request.Request(
                path_str,
                method="HEAD",
            )

            with _https_opener.open(
                req,
                timeout=HEAD_TIMEOUT,
            ) as response:
                content_length = response.headers.get(
                    "Content-Length"
                )

                if content_length is not None:
                    file_size = int(content_length)

                    if file_size > max_file_size:
                        raise FileValidationError(
                            f"Remote file size ({file_size} bytes) exceeds "
                            f"maximum limit of {max_file_size} bytes."
                        )

        except FileValidationError:
            raise

        except urllib.error.HTTPError as exc:
            # Only fall back to GET when the server explicitly does not
            # support HEAD (405 or 501). For all other HTTP errors,
            # fail fast to avoid unnecessary follow-up requests and
            # reduce the SSRF / request-amplification attack surface.
            if exc.code not in (405, 501):
                raise FileValidationError(
                    f"Remote file unreachable (HTTP {exc.code})"
                ) from exc

        except urllib.error.URLError as exc:
            # DNS failures, connection refused, timeouts, etc. mean
            # that the target is unreachable. Do not proceed to GET.
            raise FileValidationError(
                f"Could not reach remote file: {exc.reason}"
            ) from exc
    
    # Read file contents
    try:
        if is_remote:
            req = urllib.request.Request(path_str)

            with _https_opener.open(
                req,
                timeout=DOWNLOAD_TIMEOUT,
            ) as response:
                raw_bytes = response.read(
                    max_file_size + 1
                )

                if len(raw_bytes) > max_file_size:
                    raise FileValidationError(
                        f"Remote file exceeds maximum size "
                        f"({max_file_size} bytes)."
                    )

                content_encoding = response.headers.get(
                    "Content-Encoding",
                    "",
                ).lower()

                if "gzip" in content_encoding:
                    try:
                        with gzip.GzipFile(
                            fileobj=io.BytesIO(raw_bytes)
                        ) as gz:
                            content = _read_gzip_stream(
                                gz,
                                max_file_size,
                            )

                    except (
                        OSError,
                        EOFError,
                        gzip.BadGzipFile,
                    ) as e:
                        raise FileValidationError(
                            f"Gzip decompression failed: {e}"
                        ) from e

                else:
                    content = raw_bytes.decode(
                        "utf-8",
                        errors="strict",
                    )

        else:
            with local_path.open("rb") as f:
                header = f.read(2)

            if header == b"\x1f\x8b":
                try:
                    with gzip.open(
                        local_path,
                        "rb",
                    ) as gz:  # NOSEC -- This is a security checker
                        content = _read_gzip_stream(
                            gz,
                            max_file_size,
                        )

                except (
                    OSError,
                    EOFError,
                    gzip.BadGzipFile,
                ) as e:
                    raise FileValidationError(
                        f"Gzip decompression failed: {e}"
                    ) from e

            else:
                content = local_path.read_text(
                    encoding="utf-8",
                    errors="strict",
                )

    except UnicodeDecodeError as e:
        raise FileValidationError(
            f"File is not valid UTF-8: {e}"
        ) from e

    except OSError as e:
        raise FileValidationError(
            f"Failed to read file: {e}"
        ) from e

    # Reject DTD/DOCTYPE
    _reject_doctype(content)

    # Validate XML structure
    validator = XMLSecurityValidator(
        max_depth=max_depth,
        max_file_size=max_file_size,
        max_attributes=max_attributes,
        max_elements=max_elements,
        max_text_length=max_text_length,
        max_name_length=max_name_length,
    )

    try:
        validator.secure_parse(content)

    except FileValidationError:
        raise

    except (
        ET.ParseError,
        ExpatError,
        RecursionError,
    ) as e:
        raise FileValidationError(
            f"XML validation failed: {e}"
        ) from e


def validate_xml(
    func_or_path=None,
    max_depth=None,
    max_file_size=None,
    max_attributes=None,
    max_elements=None,
    max_text_length=None,
    max_name_length=None,
):
    """
    Validate XML files via decorator or direct invocation.

    An XML file validator that can operate in two modes:

    1. Decorator mode — wraps a function to validate an XML file path
       passed as an argument before the function body runs.

    2. Direct call / CLI mode — validates a file immediately and
       returns a boolean result.

    Usage:
        @validate_xml
        @validate_xml()
        @validate_xml("custom_arg_name", max_depth=50)
        @validate_xml(max_file_size=5000)
        validate_xml("path/to/file.xml", max_depth=10)

    Args:
        func_or_path (callable, str, pathlib.Path, or None):
            * If a callable: the function to decorate
              (bare decorator usage: ``@validate_xml``).
            * If a str or Path that looks like a file path or URL:
              the file path to validate (direct call usage).
            * If a str that is a valid Python identifier (not a path):
              treated as the target argument name to inspect in decorator
              mode (e.g., ``@validate_xml("config_path")``).
            * If None: returns a decorator factory
              (``@validate_xml()`` or ``@validate_xml(max_depth=50)``).
        max_depth (int or None): Maximum allowed XML nesting depth.
            Falls back to ``DEFAULT_MAX_DEPTH`` if omitted.
        max_file_size (int or None): Maximum allowed file size in bytes.
            Falls back to ``DEFAULT_MAX_FILE_SIZE`` if omitted.
        max_attributes (int or None): Maximum number of attributes permitted
            per XML element. Falls back to ``DEFAULT_MAX_ATTRIBUTES`` if omitted.
        max_elements (int or None): Maximum number of XML elements allowed
            in the document. Falls back to ``DEFAULT_MAX_ELEMENTS`` if omitted.
        max_text_length (int or None): Maximum permitted length of text or
            attribute values. Falls back to ``DEFAULT_MAX_TEXT_LENGTH`` if omitted.
        max_name_length (int or None): Maximum permitted length of element and
            attribute names. Falls back to ``DEFAULT_MAX_NAME_LENGTH`` if omitted.

    Returns:
        Union[callable, bool, function]:
            * In decorator mode: the wrapped function.
            * In direct call mode: ``True`` if validation passes,
              ``False`` if it fails (errors are printed to stdout).

    Raises:
        FileValidationError: If validation fails in decorator mode, or if
        the decorated function has no arguments, the target argument is
        missing, or the argument type is not ``str`` or ``Path``.
    """

    resolved_depth = (
        DEFAULT_MAX_DEPTH
        if max_depth is None
        else max_depth
    )

    resolved_size = (
        DEFAULT_MAX_FILE_SIZE
        if max_file_size is None
        else max_file_size
    )

    resolved_attributes = (
        DEFAULT_MAX_ATTRIBUTES
        if max_attributes is None
        else max_attributes
    )

    resolved_elements = (
        DEFAULT_MAX_ELEMENTS
        if max_elements is None
        else max_elements
    )

    resolved_text = (
        DEFAULT_MAX_TEXT_LENGTH
        if max_text_length is None
        else max_text_length
    )

    resolved_name = (
        DEFAULT_MAX_NAME_LENGTH
        if max_name_length is None
        else max_name_length
    )

    def _looks_like_file_path(s: str) -> bool:
        p = Path(s)

        return (
            p.is_absolute()
            or bool(p.suffix)
            or "/" in s
            or "\\" in s
            or s.startswith("https://")
        )

    # Direct invocation
    if isinstance(
        func_or_path,
        (str, Path),
    ) and _looks_like_file_path(
        str(func_or_path)
    ):
        try:
            _validate_xml_file(
                func_or_path,
                max_depth=resolved_depth,
                max_file_size=resolved_size,
                max_attributes=resolved_attributes,
                max_elements=resolved_elements,
                max_text_length=resolved_text,
                max_name_length=resolved_name,
            )

            return True

        except FileValidationError:
            return False

    # Decorator
    def decorator(func):
        sig = inspect.signature(func)
        params = list(sig.parameters)

        if not params:
            raise FileValidationError(
                f"Decorator applied to '{func.__name__}', "
                "but the function has no parameters."
            )

        target_arg = (
            func_or_path
            if isinstance(func_or_path, str)
            and func_or_path in params
            else params[0]
        )

        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                bound = sig.bind(
                    *args,
                    **kwargs,
                )

                bound.apply_defaults()

            except TypeError as e:
                raise FileValidationError(
                    f"Invalid function call signature: {e}"
                ) from e

            value = bound.arguments.get(target_arg)

            if value is None:
                raise FileValidationError(
                    f"Missing required argument '{target_arg}'."
                )

            if not isinstance(
                value,
                (str, Path),
            ):
                raise FileValidationError(
                    f"Expected a file path (str or pathlib.Path) "
                    f"for '{target_arg}', got "
                    f"{type(value).__name__}."
                )

            _validate_xml_file(
                value,
                max_depth=resolved_depth,
                max_file_size=resolved_size,
                max_attributes=resolved_attributes,
                max_elements=resolved_elements,
                max_text_length=resolved_text,
                max_name_length=resolved_name,
            )

            return func(
                *args,
                **kwargs,
            )

        return wrapper

    if callable(func_or_path):
        return decorator(func_or_path)

    return decorator