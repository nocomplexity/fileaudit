# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0

from pathlib import Path
import gzip
import io
import os
import pytest

from fileaudit.gz_check import validate_gz, GzValidationError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_valid_gz(path: Path, content: bytes = b"hello world\n") -> Path:
    """Create a minimal valid gzip file on disk."""
    with gzip.open(path, "wb") as f:
        f.write(content)
    return path


def _write_invalid_gz(path: Path) -> Path:
    """Create a file that is not valid gzip data."""
    path.write_bytes(b"this is not a gzip file")
    return path


def _write_empty_file(path: Path) -> Path:
    path.write_bytes(b"")
    return path


# ---------------------------------------------------------------------------
# Direct-call success / failure
# ---------------------------------------------------------------------------

def test_direct_call_valid_local_file(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "valid.gz")
    assert validate_gz(gz_path) is True
    assert validate_gz(str(gz_path)) is True


def test_direct_call_valid_with_custom_limits(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "valid.gz", content=b"x" * 100)
    assert validate_gz(
        gz_path,
        max_file_size=10_000,
        max_uncompressed_ratio=100,
        max_uncompressed_size=10_000,
    ) is True


def test_direct_call_nonexistent_file(tmp_path):
    missing = tmp_path / "does_not_exist.gz"
    with pytest.raises(GzValidationError):
        validate_gz(missing)


def test_direct_call_invalid_gzip_content(tmp_path):
    bad = _write_invalid_gz(tmp_path / "bad.gz")
    with pytest.raises(GzValidationError):
        validate_gz(bad)


def test_direct_call_empty_file(tmp_path):
    empty = _write_empty_file(tmp_path / "empty.gz")
    with pytest.raises(GzValidationError):
        validate_gz(empty)


def test_direct_call_directory_instead_of_file(tmp_path):
    with pytest.raises(GzValidationError):
        validate_gz(tmp_path)


def test_direct_call_oversized_file(tmp_path):
    # Create a small valid gz, then force a very low max_file_size
    gz_path = _write_valid_gz(tmp_path / "small.gz", content=b"payload")
    with pytest.raises(GzValidationError):
        validate_gz(gz_path, max_file_size=1)


def test_direct_call_path_object(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "pathobj.gz")
    result = validate_gz(Path(gz_path))
    assert result is True


# ---------------------------------------------------------------------------
# URL / scheme checks (black-box)
# ---------------------------------------------------------------------------

def test_direct_call_rejects_http_url():
    with pytest.raises(GzValidationError):
        validate_gz("http://example.com/file.gz")


def test_direct_call_rejects_ftp_url():
    with pytest.raises(GzValidationError):
        validate_gz("ftp://example.com/file.gz")


def test_direct_call_rejects_file_scheme():
    with pytest.raises(GzValidationError):
        validate_gz("file:///tmp/file.gz")


def test_direct_call_rejects_protocol_relative():
    with pytest.raises(GzValidationError):
        validate_gz("//example.com/file.gz")


# ---------------------------------------------------------------------------
# Invalid configuration limits
# ---------------------------------------------------------------------------

def test_invalid_max_file_size_raises_valueerror():
    with pytest.raises(ValueError):
        validate_gz(max_file_size=0)
    with pytest.raises(ValueError):
        validate_gz(max_file_size=-1)


def test_invalid_max_uncompressed_ratio_raises_valueerror():
    with pytest.raises(ValueError):
        validate_gz(max_uncompressed_ratio=0)
    with pytest.raises(ValueError):
        validate_gz(max_uncompressed_ratio=-5)


def test_invalid_max_uncompressed_size_raises_valueerror():
    with pytest.raises(ValueError):
        validate_gz(max_uncompressed_size=0)
    with pytest.raises(ValueError):
        validate_gz(max_uncompressed_size=-100)


# ---------------------------------------------------------------------------
# Decorator mode – success paths
# ---------------------------------------------------------------------------

def test_bare_decorator_success(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "decorated.gz")

    @validate_gz
    def process(path):
        return f"ok:{path}"

    assert process(gz_path) == f"ok:{gz_path}"
    assert process(str(gz_path)) == f"ok:{gz_path}"


def test_decorator_factory_no_args_success(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "factory.gz")

    @validate_gz()
    def process(path):
        return "processed"

    assert process(gz_path) == "processed"


def test_decorator_with_custom_limits_success(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "limits.gz", content=b"data")

    @validate_gz(max_file_size=50_000, max_uncompressed_size=50_000)
    def process(path):
        return True

    assert process(gz_path) is True


def test_decorator_explicit_argument_name(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "named.gz")

    @validate_gz("archive")
    def process(archive, other=None):
        return archive

    assert process(gz_path) == gz_path
    assert process(archive=gz_path) == gz_path


def test_decorator_keyword_only_target(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "kw.gz")

    @validate_gz("path")
    def process(*, path):
        return "ok"

    assert process(path=gz_path) == "ok"


# ---------------------------------------------------------------------------
# Decorator mode – failure paths
# ---------------------------------------------------------------------------

def test_decorator_raises_on_missing_file(tmp_path):
    missing = tmp_path / "missing.gz"

    @validate_gz
    def process(path):
        return path

    with pytest.raises(GzValidationError):
        process(missing)


def test_decorator_raises_on_invalid_gzip(tmp_path):
    bad = _write_invalid_gz(tmp_path / "bad.gz")

    @validate_gz
    def process(path):
        return path

    with pytest.raises(GzValidationError):
        process(bad)


def test_decorator_raises_on_oversized(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "big.gz", content=b"payload")

    @validate_gz(max_file_size=1)
    def process(path):
        return path

    with pytest.raises(GzValidationError):
        process(gz_path)


def test_decorator_raises_when_no_arguments():
    with pytest.raises(GzValidationError):
        @validate_gz
        def no_args():
            pass


def test_decorator_raises_on_wrong_argument_type(tmp_path):
    @validate_gz
    def process(path):
        return path

    with pytest.raises(GzValidationError):
        process(12345)

    with pytest.raises(GzValidationError):
        process(None)


def test_decorator_raises_on_missing_required_argument():
    @validate_gz
    def process(path):
        return path

    with pytest.raises(GzValidationError):
        process()


def test_decorator_raises_when_target_is_varargs():
    with pytest.raises(GzValidationError):
        @validate_gz
        def process(*args):
            pass


def test_decorator_raises_when_target_is_kwargs():
    with pytest.raises(GzValidationError):
        @validate_gz
        def process(**kwargs):
            pass


# ---------------------------------------------------------------------------
# Mode detection / type checks
# ---------------------------------------------------------------------------

def test_rejects_unsupported_type():
    with pytest.raises(TypeError):
        validate_gz(42)

    with pytest.raises(TypeError):
        validate_gz([])


def test_string_that_looks_like_path_is_treated_as_direct_call(tmp_path):
    # A string containing a dot is treated as a path, not an argument name
    gz_path = _write_valid_gz(tmp_path / "file.gz")
    # Passing the full path string should succeed
    assert validate_gz(str(gz_path)) is True


def test_identifier_string_is_treated_as_argument_name(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "id.gz")

    @validate_gz("myfile")
    def process(myfile):
        return "ok"

    assert process(gz_path) == "ok"


# ---------------------------------------------------------------------------
# Return value contract
# ---------------------------------------------------------------------------

def test_direct_call_returns_true_on_success(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "ret.gz")
    result = validate_gz(gz_path)
    assert result is True
    assert isinstance(result, bool)


def test_decorator_returns_original_function_result(tmp_path):
    gz_path = _write_valid_gz(tmp_path / "orig.gz")

    @validate_gz
    def process(path):
        return 42

    assert process(gz_path) == 42