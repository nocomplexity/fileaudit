"""
License GPL3
(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/
FileAudit - CSV File  Security Checker
"""
import csv
import inspect
import io
import re
import threading
import urllib.error
import urllib.request
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024       # 10 MB
DEFAULT_MAX_ROWS = 100_000
DEFAULT_MAX_COLUMNS = 1_000
DEFAULT_MAX_FIELD_SIZE = 1 * 1024 * 1024       # 1 MB
DEFAULT_MAX_TOTAL_FIELDS = 10_000_000
DEFAULT_MAX_ROW_SIZE = 5 * 1024 * 1024         # 5 MB
DEFAULT_MAX_FILENAME_LENGTH = 255
DEFAULT_REMOTE_TIMEOUT = 30
DEFAULT_READ_CHUNK_SIZE = 64 * 1024


# Spreadsheet formula injection prefixes.
DEFAULT_DANGEROUS_FORMULA_PREFIXES = (
    "=",
    "+",
    "-",
    "@",
)


# csv.field_size_limit() is process-global.
_CSV_FIELD_SIZE_LOCK = threading.Lock()


# Windows drive path, e.g. C:\data\file.csv or C:/data/file.csv.
_WINDOWS_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class CsvValidationError(Exception):
    """Custom exception for CSV validation failures in FileAudit."""

    def __init__(self, message):
        self.prefix = "FileAudit Security Validation Failed -"
        self.original_message = str(message)
        super().__init__(f"{self.prefix} {self.original_message}")


# ---------------------------------------------------------------------------
# Input classification
# ---------------------------------------------------------------------------

def _classify_input(value):
    """
    Classify a CSV source as either a local filesystem path or HTTPS URL.

    Returns:
        ("local", Path)
        ("https", str)

    Raises:
        CsvValidationError: if the input is invalid or uses an unsupported
                            URL scheme.
    """
    if isinstance(value, Path):
        return "local", value

    if not isinstance(value, str):
        raise CsvValidationError(
            f"Expected a local path or HTTPS URL, "
            f"got {type(value).__name__}"
        )

    value = value.strip()

    if not value:
        raise CsvValidationError("CSV path/URL cannot be empty")

    # Windows paths must be checked before urlparse().
    #
    # urlparse("C:\\data\\file.csv") interprets "C" as a URL scheme.
    if _WINDOWS_DRIVE_PATH.match(value):
        return "local", Path(value)

    parsed = urlparse(value)

    if parsed.scheme:
        scheme = parsed.scheme.lower()

        if scheme != "https":
            raise CsvValidationError(
                f"Unsupported URL scheme '{parsed.scheme}': "
                "only HTTPS URLs are allowed."
            )

        if not parsed.netloc:
            raise CsvValidationError(
                f"Invalid HTTPS URL: {value!r}"
            )

        # Userinfo in URLs is unnecessary and should not be accepted.
        if parsed.username is not None or parsed.password is not None:
            raise CsvValidationError(
                "HTTPS URLs containing username/password credentials "
                "are not allowed."
            )

        return "https", value

    # No URL scheme => local filesystem path.
    return "local", Path(value)


# ---------------------------------------------------------------------------
# Remote HTTPS handling
# ---------------------------------------------------------------------------

class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Allow redirects only when the destination remains HTTPS.

    This prevents an HTTPS URL from silently redirecting to HTTP.
    """

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
            raise CsvValidationError(
                "Remote URL redirected to a non-HTTPS location; "
                "redirect rejected."
            )

        if not parsed.netloc:
            raise CsvValidationError(
                f"Invalid HTTPS redirect target: {newurl!r}"
            )

        if parsed.username is not None or parsed.password is not None:
            raise CsvValidationError(
                "HTTPS redirects containing username/password "
                "credentials are not allowed."
            )

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            newurl,
        )


_HTTPS_OPENER = urllib.request.build_opener(
    _HttpsOnlyRedirectHandler()
)


# ---------------------------------------------------------------------------
# Individual CSV checks
# ---------------------------------------------------------------------------

def _check_csv_field(
    value,
    row_number,
    column_number,
    max_field_size,
    reject_formula_injection,
    reject_control_characters,
    encoding,
):
    """Validate one CSV field for common security issues."""

    if not isinstance(value, str):
        raise CsvValidationError(
            f"Invalid field type at row {row_number}, "
            f"column {column_number}"
        )

    if reject_control_characters:
        for char in value:
            codepoint = ord(char)

            # Permit tab, newline and carriage return.
            if codepoint < 32 and codepoint not in (9, 10, 13):
                raise CsvValidationError(
                    f"Rejected field at row {row_number}, "
                    f"column {column_number}: "
                    f"contains control character U+{codepoint:04X}"
                )

    # NUL deserves an explicit security error regardless of the
    # control-character setting.
    if "\x00" in value:
        raise CsvValidationError(
            f"Rejected field at row {row_number}, "
            f"column {column_number}: contains NUL byte"
        )

    try:
        field_size = len(value.encode(encoding))
    except UnicodeEncodeError as exc:
        raise CsvValidationError(
            f"Field at row {row_number}, column {column_number} "
            f"cannot be encoded using {encoding!r}"
        ) from exc

    if field_size > max_field_size:
        raise CsvValidationError(
            f"Rejected field at row {row_number}, "
            f"column {column_number}: field size exceeds "
            f"maximum of {max_field_size} bytes"
        )

    if reject_formula_injection:
        stripped = value.lstrip()

        if stripped.startswith(DEFAULT_DANGEROUS_FORMULA_PREFIXES):
            raise CsvValidationError(
                f"Rejected field at row {row_number}, "
                f"column {column_number}: possible spreadsheet "
                f"formula injection"
            )


def _check_csv_row(
    row,
    row_number,
    max_columns,
    max_field_size,
    max_row_size,
    reject_formula_injection,
    reject_control_characters,
    encoding,
):
    """Validate a single parsed CSV row."""

    if len(row) > max_columns:
        raise CsvValidationError(
            f"Rejected row {row_number}: contains {len(row)} columns, "
            f"exceeding maximum of {max_columns}"
        )

    row_size = 0

    for column_number, value in enumerate(row, start=1):
        _check_csv_field(
            value=value,
            row_number=row_number,
            column_number=column_number,
            max_field_size=max_field_size,
            reject_formula_injection=reject_formula_injection,
            reject_control_characters=reject_control_characters,
            encoding=encoding,
        )

        row_size += len(value.encode(encoding))

    if row_size > max_row_size:
        raise CsvValidationError(
            f"Rejected row {row_number}: row size ({row_size} bytes) "
            f"exceeds maximum of {max_row_size} bytes"
        )


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------

def _validate_positive_integer(name, value):
    if not isinstance(value, int) or isinstance(value, bool):
        raise CsvValidationError(
            f"{name} must be a positive integer"
        )

    if value <= 0:
        raise CsvValidationError(
            f"{name} must be greater than zero"
        )


def _validate_configuration(
    max_file_size,
    max_rows,
    max_columns,
    max_field_size,
    max_total_fields,
    max_row_size,
    max_filename_length,
):
    values = {
        "max_file_size": max_file_size,
        "max_rows": max_rows,
        "max_columns": max_columns,
        "max_field_size": max_field_size,
        "max_total_fields": max_total_fields,
        "max_row_size": max_row_size,
        "max_filename_length": max_filename_length,
    }

    for name, value in values.items():
        _validate_positive_integer(name, value)


# ---------------------------------------------------------------------------
# Internal file validation
# ---------------------------------------------------------------------------

def _read_https_csv(url, max_file_size):
    """Download an HTTPS CSV while enforcing a hard byte limit."""

    parsed = urlparse(url)

    if parsed.scheme.lower() != "https":
        raise CsvValidationError(
            "Only HTTPS URLs are allowed for remote files."
        )

    if not parsed.netloc:
        raise CsvValidationError(
            f"Invalid HTTPS URL: {url!r}"
        )

    if parsed.username is not None or parsed.password is not None:
        raise CsvValidationError(
            "HTTPS URLs containing username/password credentials "
            "are not allowed."
        )

    if not (parsed.path or "").lower().endswith(".csv"):
        raise CsvValidationError(
            f"Remote URL does not point to a .csv file: {url}"
        )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "FileAudit-CSVValidator/1.0",
        },
        method="GET",
    )

    with _HTTPS_OPENER.open(
        request,
        timeout=DEFAULT_REMOTE_TIMEOUT,
    ) as response:

        content_length = response.headers.get("Content-Length")

        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError as exc:
                raise CsvValidationError(
                    f"Remote server returned invalid "
                    f"Content-Length: {content_length!r}"
                ) from exc

            if declared_size < 0:
                raise CsvValidationError(
                    "Negative Content-Length is invalid"
                )

            if declared_size > max_file_size:
                raise CsvValidationError(
                    f"Remote file size ({declared_size} bytes) "
                    f"exceeds maximum of {max_file_size} bytes"
                )

        chunks = []
        total_size = 0

        while True:
            chunk = response.read(DEFAULT_READ_CHUNK_SIZE)

            if not chunk:
                break

            total_size += len(chunk)

            if total_size > max_file_size:
                raise CsvValidationError(
                    f"Remote file exceeds maximum size of "
                    f"{max_file_size} bytes"
                )

            chunks.append(chunk)

        return b"".join(chunks)


def _read_local_csv(path, max_file_size, max_filename_length):
    """Read a local CSV while enforcing the configured size limits."""

    local_path = Path(path)

    if len(local_path.name) > max_filename_length:
        raise CsvValidationError(
            f"Filename length ({len(local_path.name)}) exceeds "
            f"maximum of {max_filename_length} characters"
        )

    if local_path.suffix.lower() != ".csv":
        raise CsvValidationError(
            f"Expected a .csv file, got "
            f"'{local_path.suffix or '[no extension]'}'"
        )

    try:
        # Open first rather than stat() followed by open(), reducing
        # the TOCTOU window.
        with local_path.open("rb") as file:
            csv_data = file.read(max_file_size + 1)
    except FileNotFoundError as exc:
        raise CsvValidationError(
            f"File not found: {local_path}"
        ) from exc
    except IsADirectoryError as exc:
        raise CsvValidationError(
            f"Path is not a file: {local_path}"
        ) from exc
    except OSError as exc:
        raise CsvValidationError(
            f"Failed to access local file: {exc}"
        ) from exc

    if len(csv_data) > max_file_size:
        raise CsvValidationError(
            f"File size exceeds maximum of {max_file_size} bytes"
        )

    return csv_data


def _validate_csv_file(
    path,
    max_file_size,
    max_rows,
    max_columns,
    max_field_size,
    max_total_fields,
    max_row_size,
    max_filename_length,
    reject_formula_injection,
    reject_control_characters,
    encoding,
    dialect,
):
    """
    Validate a local CSV file or an HTTPS CSV URL.

    No CSV content is executed or imported.
    """

    _validate_configuration(
        max_file_size=max_file_size,
        max_rows=max_rows,
        max_columns=max_columns,
        max_field_size=max_field_size,
        max_total_fields=max_total_fields,
        max_row_size=max_row_size,
        max_filename_length=max_filename_length,
    )

    source_type, source = _classify_input(path)

    # ---------------------------------------------------------------
    # Read bytes
    # ---------------------------------------------------------------

    if source_type == "https":
        try:
            csv_data = _read_https_csv(
                source,
                max_file_size=max_file_size,
            )
        except urllib.error.HTTPError as exc:
            raise CsvValidationError(
                f"Remote file unreachable (HTTP {exc.code})"
            ) from exc
        except urllib.error.URLError as exc:
            raise CsvValidationError(
                f"Could not reach remote file: {exc.reason}"
            ) from exc

    else:
        csv_data = _read_local_csv(
            source,
            max_file_size=max_file_size,
            max_filename_length=max_filename_length,
        )

    # ---------------------------------------------------------------
    # Decode
    # ---------------------------------------------------------------

    try:
        text = csv_data.decode(encoding)
    except UnicodeDecodeError as exc:
        raise CsvValidationError(
            f"CSV is not valid {encoding} text: {exc}"
        ) from exc

    if encoding.lower().replace("_", "-") == "utf-8":
        if text.startswith("\ufeff"):
            raise CsvValidationError(
                "CSV contains a UTF-8 BOM; use encoding='utf-8-sig' "
                "if BOMs are intentionally supported"
            )

    if "\x00" in text:
        raise CsvValidationError(
            r"Null byte (\0) found in CSV content - rejected"
        )

    # ---------------------------------------------------------------
    # CSV parsing and validation
    # ---------------------------------------------------------------

    previous_limit = csv.field_size_limit()

    try:
        with _CSV_FIELD_SIZE_LOCK:
            csv.field_size_limit(max_field_size)

            reader = csv.reader(
                io.StringIO(text, newline=""),
                dialect=dialect,
            )

            row_count = 0
            total_fields = 0

            try:
                for row_number, row in enumerate(reader, start=1):
                    row_count += 1

                    if row_count > max_rows:
                        raise CsvValidationError(
                            f"CSV contains more than {max_rows} rows"
                        )

                    total_fields += len(row)

                    if total_fields > max_total_fields:
                        raise CsvValidationError(
                            f"CSV contains more than "
                            f"{max_total_fields} fields"
                        )

                    _check_csv_row(
                        row=row,
                        row_number=row_number,
                        max_columns=max_columns,
                        max_field_size=max_field_size,
                        max_row_size=max_row_size,
                        reject_formula_injection=reject_formula_injection,
                        reject_control_characters=reject_control_characters,
                        encoding=encoding,
                    )

            except csv.Error as exc:
                raise CsvValidationError(
                    f"Invalid CSV format: {exc}"
                ) from exc

    except CsvValidationError:
        raise

    except (OverflowError, ValueError) as exc:
        raise CsvValidationError(
            f"Invalid CSV parser configuration: {exc}"
        ) from exc

    finally:
        with _CSV_FIELD_SIZE_LOCK:
            csv.field_size_limit(previous_limit)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def validate_csv(
    func_or_path=None,
    max_file_size=None,
    max_rows=None,
    max_columns=None,
    max_field_size=None,
    max_total_fields=None,
    max_row_size=None,
    max_filename_length=None,
    reject_formula_injection=True,
    reject_control_characters=True,
    encoding="utf-8",
    dialect="excel",
):
    """Validate a CSV file directly or validate CSV arguments with a decorator.

    This function supports both direct CSV validation and decorator usage.

    In direct-invocation mode, the CSV file is validated immediately and the
    function returns ``True`` when validation succeeds or ``False`` when
    validation fails. Local file paths, ``Path`` objects, and URLs are
    supported.

    In decorator mode, the decorated function is called only after its CSV
    argument has successfully passed validation. A validation failure raises
    ``CsvValidationError``.

    ``func_or_path`` is interpreted based on its value. A callable is treated
    as the function to decorate. A ``Path`` or a string that looks like a file
    path or URL is treated as a CSV source for direct validation. A string
    that does not look like a path or URL can be used to explicitly identify
    the decorated function argument containing the CSV path.

    Examples:

        Validate a local CSV file::

            validate_csv("data.csv")

        Validate a CSV file from a URL::

            validate_csv("https://example.com/data.csv")

        Use as a decorator, using the first function argument as the CSV path::

            @validate_csv
            def process_csv(csv_path):
                ...

        Use as a decorator with default validation options::

            @validate_csv()
            def process_csv(csv_path):
                ...

        Specify the decorated function argument containing the CSV path::

            @validate_csv("input_file")
            def process_csv(input_file):
                ...

        Configure validation limits::

            @validate_csv(
                max_file_size=10 * 1024 * 1024,
                max_rows=10_000,
                max_columns=50,
            )
            def process_csv(csv_path):
                ...

        The explicit argument name must match a parameter of the decorated
        function. Otherwise, the decorator uses the function's first
        parameter as the CSV path::

            @validate_csv("csv_path")
            def process_csv(csv_path):
                ...

    Args:
        func_or_path: Controls whether the function operates in direct or
            decorator mode. A callable is treated as the function to decorate.
            A ``Path`` or a string that looks like a file path or URL is
            treated as a CSV source for direct validation. A string that does
            not look like a file path or URL is treated as the name of the
            decorated function argument containing the CSV path. If that name
            does not match a function parameter, the first function parameter
            is used instead. ``None`` creates a decorator that uses the first
            function parameter as the CSV path.
        max_file_size: Maximum allowed CSV file size in bytes. If ``None``,
            uses the default maximum file size.
        max_rows: Maximum number of rows allowed in the CSV file. If ``None``,
            uses the default maximum number of rows.
        max_columns: Maximum number of columns allowed in the CSV file. If
            ``None``, uses the default maximum number of columns.
        max_field_size: Maximum allowed size of an individual CSV field. If
            ``None``, uses the default maximum field size.
        max_total_fields: Maximum total number of fields allowed in the CSV
            file. If ``None``, uses the default maximum.
        max_row_size: Maximum allowed size of an individual CSV row. If
            ``None``, uses the default maximum row size.
        max_filename_length: Maximum allowed length of the CSV filename. If
            ``None``, uses the default maximum filename length.
        reject_formula_injection: Whether to reject fields that could be
            interpreted as spreadsheet formulas. Defaults to ``True``.
        reject_control_characters: Whether to reject disallowed control
            characters in CSV fields. Defaults to ``True``.
        encoding: Character encoding used to read the CSV file. Defaults to
            ``"utf-8"``.
        dialect: CSV dialect used when parsing the file. Defaults to
            ``"excel"``.

    Returns:
        In direct-invocation mode, ``True`` if the CSV passes validation or
        ``False`` if validation fails.

        In decorator mode, the decorated function's wrapped callable is
        returned. When invoked, the wrapped function returns the original
        function's return value after successful CSV validation.

    Raises:
        CsvValidationError: If ``func_or_path`` is not a callable, ``Path``,
            string, or ``None``.
        CsvValidationError: If a decorated function has no parameters.
        CsvValidationError: If the decorated function is called with an
            invalid argument signature.
        CsvValidationError: If the CSV path argument is missing or is neither
            a string nor a ``Path``.
        CsvValidationError: If CSV validation fails while the function is
            used as a decorator.
    """   
    resolved_file_size = (
        DEFAULT_MAX_FILE_SIZE
        if max_file_size is None
        else max_file_size
    )

    resolved_rows = (
        DEFAULT_MAX_ROWS
        if max_rows is None
        else max_rows
    )

    resolved_columns = (
        DEFAULT_MAX_COLUMNS
        if max_columns is None
        else max_columns
    )

    resolved_field_size = (
        DEFAULT_MAX_FIELD_SIZE
        if max_field_size is None
        else max_field_size
    )

    resolved_total_fields = (
        DEFAULT_MAX_TOTAL_FIELDS
        if max_total_fields is None
        else max_total_fields
    )

    resolved_row_size = (
        DEFAULT_MAX_ROW_SIZE
        if max_row_size is None
        else max_row_size
    )

    resolved_filename_length = (
        DEFAULT_MAX_FILENAME_LENGTH
        if max_filename_length is None
        else max_filename_length
    )

    def _validate(path):
        _validate_csv_file(
            path=path,
            max_file_size=resolved_file_size,
            max_rows=resolved_rows,
            max_columns=resolved_columns,
            max_field_size=resolved_field_size,
            max_total_fields=resolved_total_fields,
            max_row_size=resolved_row_size,
            max_filename_length=resolved_filename_length,
            reject_formula_injection=reject_formula_injection,
            reject_control_characters=reject_control_characters,
            encoding=encoding,
            dialect=dialect,
        )

    # ---------------------------------------------------------------
    # Determine decorator vs direct invocation
    # ---------------------------------------------------------------

    def _looks_like_file_path(value):
        if _WINDOWS_DRIVE_PATH.match(value):
            return True

        parsed = urlparse(value)

        if parsed.scheme:
            return True

        if value.startswith(("/", "\\")):
            return True

        if "/" in value or "\\" in value:
            return True

        if value.lower().endswith(".csv"):
            return True

        return False

    if func_or_path is None:
        is_decorator_mode = True

    elif callable(func_or_path):
        is_decorator_mode = True

    elif isinstance(func_or_path, Path):
        is_decorator_mode = False

    elif isinstance(func_or_path, str):
        is_decorator_mode = not _looks_like_file_path(
            func_or_path
        )

    else:
        raise CsvValidationError(
            f"Expected callable, Path, str, or None; "
            f"got {type(func_or_path).__name__}"
        )

    # ---------------------------------------------------------------
    # Direct / CLI mode
    # ---------------------------------------------------------------

    if (
        not is_decorator_mode
        and isinstance(func_or_path, (str, Path))
    ):
        try:
            _validate(func_or_path)
            return True
        except CsvValidationError as exc:
            print(f"Exception: {exc}")
            return False

    # ---------------------------------------------------------------
    # Decorator mode
    # ---------------------------------------------------------------

    def decorator(function):
        signature = inspect.signature(function)
        params = list(signature.parameters.keys())

        if not params:
            raise CsvValidationError(
                f"Decorator applied to '{function.__name__}', "
                "but it has no arguments."
            )

        # Explicit argument name:        
        #     @validate_csv("csv_path")        
        if (
            isinstance(func_or_path, str)
            and func_or_path in params
        ):
            target_arg = func_or_path
        else:
            target_arg = params[0]

        @wraps(function)
        def wrapper(*args, **kwargs):
            try:
                bound_args = signature.bind(*args, **kwargs)
                bound_args.apply_defaults()
            except TypeError as exc:
                raise CsvValidationError(
                    f"Invalid function call signature: {exc}"
                ) from exc

            csv_path = bound_args.arguments.get(target_arg)

            if csv_path is None:
                raise CsvValidationError(
                    f"Missing required argument: {target_arg}"
                )

            if not isinstance(csv_path, (str, Path)):
                raise CsvValidationError(
                    f"Expected Path or str for {target_arg}, "
                    f"got {type(csv_path).__name__}"
                )

            _validate(csv_path)

            return function(*args, **kwargs)

        return wrapper

    if callable(func_or_path):
        return decorator(func_or_path)

    return decorator