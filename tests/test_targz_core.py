# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0
"""
Crucial pytest unit tests for `validate_tar_gz`.

Mirrors the structure used for `validate_json` and covers:

Direct-call / CLI mode
- Valid path / Path / HTTPS URL → True
- Validation failure → False + exception printed
- Custom limits + defaults

Decorator mode
- Bare @validate_tar_gz
- @validate_tar_gz()
- @validate_tar_gz(...limits...)
- @validate_tar_gz("custom_arg")
- Validation runs before the wrapped body
- TarValidationError on failure (does not swallow)
- No-args, missing arg, wrong type, bind errors

Mode-detection heuristic is identical to the JSON counterpart.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from fileaudit.targz_check import (
    DEFAULT_MAX_DIRECTORY_DEPTH,
    DEFAULT_MAX_FILENAME_LENGTH,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
    DEFAULT_MAX_TAR_MEMBERS,
    DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
    DEFAULT_MAX_UNCOMPRESSED_RATIO,
    TarValidationError,
    validate_tar_gz,
    _validate_tar_gz_file,  # only for patching
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_validate():
    """Patch the internal validator so we can assert call arguments."""
    with patch("fileaudit.targz_check._validate_tar_gz_file") as m:
        yield m


# ---------------------------------------------------------------------------
# 1. Direct-call / CLI mode – success
# ---------------------------------------------------------------------------

def test_direct_call_valid_local_str(mock_validate, tmp_path):
    p = tmp_path / "ok.tar.gz"
    p.write_bytes(b"dummy")  # content irrelevant – validator is mocked
    result = validate_tar_gz(str(p))
    assert result is True
    mock_validate.assert_called_once_with(
        str(p),
        DEFAULT_MAX_FILE_SIZE,
        DEFAULT_MAX_UNCOMPRESSED_RATIO,
        DEFAULT_MAX_TAR_MEMBERS,
        DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
        DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
        DEFAULT_MAX_FILENAME_LENGTH,
        DEFAULT_MAX_DIRECTORY_DEPTH,
    )


def test_direct_call_valid_path_object(mock_validate, tmp_path):
    p = tmp_path / "ok.tar.gz"
    p.write_bytes(b"dummy")
    result = validate_tar_gz(p)
    assert result is True
    mock_validate.assert_called_once_with(
        p,
        DEFAULT_MAX_FILE_SIZE,
        DEFAULT_MAX_UNCOMPRESSED_RATIO,
        DEFAULT_MAX_TAR_MEMBERS,
        DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
        DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
        DEFAULT_MAX_FILENAME_LENGTH,
        DEFAULT_MAX_DIRECTORY_DEPTH,
    )


def test_direct_call_custom_limits(mock_validate, tmp_path):
    p = tmp_path / "ok.tar.gz"
    p.write_bytes(b"dummy")
    result = validate_tar_gz(
        str(p),
        max_file_size=111,
        max_uncompressed_ratio=22,
        max_tar_members=33,
        max_total_extracted_size=44,
        max_individual_file_size=55,
        max_filename_length=66,
        max_directory_depth=77,
    )
    assert result is True
    mock_validate.assert_called_once_with(
        str(p), 111, 22, 33, 44, 55, 66, 77
    )


def test_direct_call_https_url(mock_validate):
    url = "https://example.com/archive.tar.gz"
    result = validate_tar_gz(url, max_tar_members=10)
    assert result is True
    mock_validate.assert_called_once_with(
        url,
        DEFAULT_MAX_FILE_SIZE,
        DEFAULT_MAX_UNCOMPRESSED_RATIO,
        10,
        DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
        DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
        DEFAULT_MAX_FILENAME_LENGTH,
        DEFAULT_MAX_DIRECTORY_DEPTH,
    )


# ---------------------------------------------------------------------------
# 2. Direct-call / CLI mode – failure (swallows & returns False)
# ---------------------------------------------------------------------------

def test_direct_call_validation_failure_returns_false(mock_validate, capsys):
    mock_validate.side_effect = TarValidationError("boom")
    result = validate_tar_gz("https://example.com/bad.tar.gz")
    assert result is False
    captured = capsys.readouterr()
    # Implementation prints the exception's string representation
    assert "Exception:" in captured.out
    assert "boom" in captured.out


def test_direct_call_unexpected_exception_returns_false(mock_validate, capsys):
    mock_validate.side_effect = RuntimeError("unexpected")
    result = validate_tar_gz("/tmp/whatever.tar.gz")
    assert result is False
    assert "Exception: unexpected" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 3. Mode-detection heuristic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value, expected_decorator_mode",
    [
        # Identifiers → decorator mode
        ("archive_path", True),
        ("file", True),
        ("_private", True),
        ("tarData", True),
        # Paths / URLs → direct-call mode
        ("/abs/path.tar.gz", False),
        ("\\windows\\path.tar.gz", False),
        ("relative/path.tar.gz", False),
        ("file.tar.gz", False),          # contains dot → treated as path
        ("https://example.com/x.tar.gz", False),
        (Path("/tmp/x.tar.gz"), False),  # Path objects always direct
    ],
)
def test_mode_detection_heuristic(mock_validate, value, expected_decorator_mode):
    if expected_decorator_mode:
        dec = validate_tar_gz(value)
        assert callable(dec)

        @dec
        def dummy(archive_path):
            return "ok"

        assert dummy.__name__ == "dummy"
    else:
        result = validate_tar_gz(value)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# 4. Decorator mode – bare & factory forms
# ---------------------------------------------------------------------------

def test_bare_decorator_validates_first_arg(mock_validate):
    @validate_tar_gz
    def process(file_path, other=None):
        return "processed"

    process("/tmp/data.tar.gz")
    mock_validate.assert_called_once_with(
        "/tmp/data.tar.gz",
        DEFAULT_MAX_FILE_SIZE,
        DEFAULT_MAX_UNCOMPRESSED_RATIO,
        DEFAULT_MAX_TAR_MEMBERS,
        DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
        DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
        DEFAULT_MAX_FILENAME_LENGTH,
        DEFAULT_MAX_DIRECTORY_DEPTH,
    )


def test_factory_no_args(mock_validate):
    @validate_tar_gz()
    def process(file_path):
        return "ok"

    process("data.tar.gz")
    mock_validate.assert_called_once()


def test_factory_with_limits(mock_validate):
    @validate_tar_gz(max_file_size=999, max_tar_members=5)
    def process(path):
        return path

    process("https://example.com/x.tar.gz")
    mock_validate.assert_called_once_with(
        "https://example.com/x.tar.gz",
        999,
        DEFAULT_MAX_UNCOMPRESSED_RATIO,
        5,
        DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
        DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
        DEFAULT_MAX_FILENAME_LENGTH,
        DEFAULT_MAX_DIRECTORY_DEPTH,
    )


def test_named_target_argument(mock_validate):
    @validate_tar_gz("archive")
    def process(other, archive, more=None):
        return "done"

    process(1, archive="/etc/archive.tar.gz")
    mock_validate.assert_called_once_with(
        "/etc/archive.tar.gz",
        DEFAULT_MAX_FILE_SIZE,
        DEFAULT_MAX_UNCOMPRESSED_RATIO,
        DEFAULT_MAX_TAR_MEMBERS,
        DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
        DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
        DEFAULT_MAX_FILENAME_LENGTH,
        DEFAULT_MAX_DIRECTORY_DEPTH,
    )


def test_named_target_with_limits(mock_validate):
    @validate_tar_gz("cfg", max_directory_depth=3, max_filename_length=20)
    def process(cfg, x=0):
        return x

    process(cfg=Path("/tmp/c.tar.gz"))
    mock_validate.assert_called_once_with(
        Path("/tmp/c.tar.gz"),
        DEFAULT_MAX_FILE_SIZE,
        DEFAULT_MAX_UNCOMPRESSED_RATIO,
        DEFAULT_MAX_TAR_MEMBERS,
        DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
        DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
        20,
        3,
    )


# ---------------------------------------------------------------------------
# 5. Decorator mode – validation occurs *before* the body
# ---------------------------------------------------------------------------

def test_decorator_runs_validation_before_body(mock_validate):
    body_called = False

    @validate_tar_gz
    def process(path):
        nonlocal body_called
        body_called = True
        return "result"

    mock_validate.side_effect = TarValidationError("bad archive")
    with pytest.raises(TarValidationError, match="bad archive"):
        process("/bad.tar.gz")
    assert body_called is False


def test_decorator_passes_on_success(mock_validate):
    @validate_tar_gz
    def process(path):
        return "success"

    assert process("good.tar.gz") == "success"
    mock_validate.assert_called_once()


# ---------------------------------------------------------------------------
# 6. Decorator mode – error conditions (raise, do not swallow)
# ---------------------------------------------------------------------------

def test_decorator_no_arguments_raises():
    with pytest.raises(TarValidationError, match="has no arguments"):
        @validate_tar_gz
        def no_args():
            pass


def test_decorator_missing_argument_raises(mock_validate):
    # Give the parameter a default of None so bind() succeeds and the
    # explicit "Missing required argument" check is reached.
    @validate_tar_gz("missing_arg")
    def process(other=None):
        pass

    with pytest.raises(TarValidationError, match="Missing required argument"):
        process()


def test_decorator_wrong_type_raises(mock_validate):
    @validate_tar_gz
    def process(file_path):
        pass

    with pytest.raises(TarValidationError, match="Expected Path or str"):
        process(12345)


def test_decorator_bind_error_raises(mock_validate):
    @validate_tar_gz
    def process(a, b):
        pass

    with pytest.raises(TarValidationError, match="Invalid function call signature"):
        process()


def test_decorator_propagates_validation_error(mock_validate):
    mock_validate.side_effect = TarValidationError("size exceeded")
    @validate_tar_gz
    def process(path):
        return "never"

    with pytest.raises(TarValidationError, match="size exceeded"):
        process("big.tar.gz")


# ---------------------------------------------------------------------------
# 7. Interaction of defaults & explicit None
# ---------------------------------------------------------------------------

def test_explicit_none_falls_back_to_defaults(mock_validate, tmp_path):
    p = tmp_path / "x.tar.gz"
    p.write_bytes(b"dummy")
    result = validate_tar_gz(
        str(p),
        max_file_size=None,
        max_uncompressed_ratio=None,
        max_tar_members=None,
        max_total_extracted_size=None,
        max_individual_file_size=None,
        max_filename_length=None,
        max_directory_depth=None,
    )
    assert result is True
    mock_validate.assert_called_once_with(
        str(p),
        DEFAULT_MAX_FILE_SIZE,
        DEFAULT_MAX_UNCOMPRESSED_RATIO,
        DEFAULT_MAX_TAR_MEMBERS,
        DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
        DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
        DEFAULT_MAX_FILENAME_LENGTH,
        DEFAULT_MAX_DIRECTORY_DEPTH,
    )


# ---------------------------------------------------------------------------
# 8. Decorator preserves function metadata
# ---------------------------------------------------------------------------

def test_decorator_preserves_name_and_doc(mock_validate):
    @validate_tar_gz
    def my_func(path: str) -> str:
        """Docstring stays."""
        return path

    assert my_func.__name__ == "my_func"
    assert my_func.__doc__ == "Docstring stays."