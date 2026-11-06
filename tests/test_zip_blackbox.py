# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0

"""
Black-box pytest suite for ``fileaudit.zip_check.validate_zip``.

Run from the project root:

    python -m pytest -q

These tests exercise only the public API. They create ZIP fixtures with the
standard library and mock the HTTPS opener for deterministic remote tests.
"""

from __future__ import annotations

import pytest
import io
import os
import stat
import zipfile
from pathlib import Path
from unittest.mock import Mock
import warnings

from fileaudit.zip_check import (
    validate_zip,
    ZipValidationError,
)



# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------

def make_zip(
    destination: Path,
    entries: list[tuple[str, bytes]] | None = None,
    *,
    compression: int = zipfile.ZIP_STORED,
) -> Path:
    """Create a ZIP archive containing the supplied name/content pairs."""
    with zipfile.ZipFile(destination, "w", compression=compression) as archive:
        for name, data in entries or [("hello.txt", b"hello world")]:
            archive.writestr(name, data)
    return destination


def make_zip_bytes(
    entries: list[tuple[str, bytes]] | None = None,
    *,
    compression: int = zipfile.ZIP_STORED,
) -> bytes:
    """Create a ZIP archive in memory."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in entries or [("hello.txt", b"hello world")]:
            archive.writestr(name, data)
    return buffer.getvalue()


@pytest.fixture
def valid_zip(tmp_path: Path) -> Path:
    return make_zip(tmp_path / "valid.zip")


@pytest.fixture
def valid_zip_bytes() -> bytes:
    return make_zip_bytes()


def test_valid_local_path_returns_true(valid_zip: Path) -> None:
    assert validate_zip(str(valid_zip)) is True


def test_valid_path_object_returns_true(valid_zip: Path) -> None:
    assert validate_zip(valid_zip) is True


def test_valid_zip_with_nested_directories_returns_true(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "nested.zip",
        [("one/two/three/data.txt", b"nested content")],
    )
    assert validate_zip(archive) is True


def test_valid_empty_zip_returns_true(tmp_path: Path) -> None:
    archive = tmp_path / "empty.zip"
    with zipfile.ZipFile(archive, "w"):
        pass
    assert validate_zip(archive) is True


def test_valid_supported_compression_methods_return_true(tmp_path: Path) -> None:
    methods = [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED]
    if hasattr(zipfile, "ZIP_BZIP2"):
        methods.append(zipfile.ZIP_BZIP2)
    if hasattr(zipfile, "ZIP_LZMA"):
        methods.append(zipfile.ZIP_LZMA)

    for index, method in enumerate(methods):
        archive = make_zip(
            tmp_path / f"compression-{index}.zip",
            [("payload.txt", b"some content " * 20)],
            compression=method,
        )
        assert validate_zip(archive) is True


# ---------------------------------------------------------------------------
# Input and archive errors
# ---------------------------------------------------------------------------

def test_missing_file_raises_validation_error(tmp_path: Path) -> None:
    with pytest.raises(ZipValidationError, match="does not exist"):
        validate_zip(tmp_path / "missing.zip")


def test_directory_instead_of_file_raises_validation_error(tmp_path: Path) -> None:
    with pytest.raises(ZipValidationError, match="not a regular file"):
        validate_zip(tmp_path)


@pytest.mark.parametrize("contents", [b"", b"not a zip", b"PK\x03\x04truncated"])
def test_corrupt_or_non_zip_input_raises_validation_error(
    tmp_path: Path, contents: bytes
) -> None:
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(contents)

    with pytest.raises(ZipValidationError):
        validate_zip(archive)


def test_http_url_is_rejected_before_network_access() -> None:
    with pytest.raises(ZipValidationError, match="only 'https' is allowed"):
        validate_zip("http://example.test/archive.zip")


def test_ftp_url_is_rejected() -> None:
    with pytest.raises(ZipValidationError, match="only 'https' is allowed"):
        validate_zip("ftp://example.test/archive.zip")


def test_https_url_without_hostname_is_rejected() -> None:
    with pytest.raises(ZipValidationError, match="Invalid HTTPS URL"):
        validate_zip("https:///archive.zip")


@pytest.mark.parametrize(
    "url",
    [
        "https://user@example.test/archive.zip",
        "https://user:secret@example.test/archive.zip",
    ],
)
def test_https_url_with_credentials_is_rejected(url: str) -> None:
    with pytest.raises(ZipValidationError, match="credentials"):
        validate_zip(url)


def test_protocol_relative_url_is_rejected() -> None:
    with pytest.raises(ZipValidationError, match="explicitly 'https'"):
        validate_zip("//example.test/archive.zip")


# ---------------------------------------------------------------------------
# Configurable size and structural limits
# ---------------------------------------------------------------------------

def test_max_file_size_is_enforced(valid_zip: Path) -> None:
    with pytest.raises(ZipValidationError, match="ZIP file is too large"):
        validate_zip(valid_zip, max_file_size=1)


def test_max_zip_members_is_enforced(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "many.zip",
        [("one.txt", b"1"), ("two.txt", b"2")],
    )
    with pytest.raises(ZipValidationError, match="too many members"):
        validate_zip(archive, max_zip_members=1)


def test_max_individual_file_size_is_enforced(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "large-member.zip", [("large.txt", b"x" * 100)])
    with pytest.raises(ZipValidationError, match="ZIP entry is too large"):
        validate_zip(archive, max_individual_file_size=50)


def test_max_total_extracted_size_is_enforced(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "large-total.zip",
        [("one.txt", b"a" * 40), ("two.txt", b"b" * 40)],
    )
    with pytest.raises(ZipValidationError, match="total uncompressed size"):
        validate_zip(archive, max_total_extracted_size=60)


def test_max_filename_length_is_enforced(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "long-name.zip", [("longname.txt", b"x")])
    with pytest.raises(ZipValidationError, match="filename is too long"):
        validate_zip(archive, max_filename_length=5)


def test_filename_length_counts_utf8_bytes(tmp_path: Path) -> None:
    # "é" is one Unicode code point but two UTF-8 bytes.
    archive = make_zip(tmp_path / "unicode-name.zip", [("é.txt", b"x")])
    with pytest.raises(ZipValidationError, match="filename is too long"):
        validate_zip(archive, max_filename_length=5)


def test_max_directory_depth_is_enforced(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "deep.zip",
        [("a/b/c/file.txt", b"x")],
    )
    with pytest.raises(ZipValidationError, match="directory depth"):
        validate_zip(archive, max_directory_depth=1)


def test_compression_ratio_limit_is_enforced(tmp_path: Path) -> None:
    # Highly repetitive data compresses to a very small stream.
    archive = make_zip(
        tmp_path / "high-ratio.zip",
        [("repetitive.txt", b"A" * 100_000)],
        compression=zipfile.ZIP_DEFLATED,
    )
    with pytest.raises(ZipValidationError, match="excessive compression ratio"):
        validate_zip(archive, max_uncompressed_ratio=2)


# ---------------------------------------------------------------------------
# Malicious ZIP member names and metadata
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "member_name",
    [
        "../outside.txt",
        "folder/../outside.txt",
        "./ambiguous.txt",
        "folder/./ambiguous.txt",
        "/absolute.txt",
        "C:/windows.txt",
        "folder\\windows-separator.txt",
    ],
)
def test_unsafe_member_paths_are_rejected(
    tmp_path: Path, member_name: str
) -> None:
    archive = make_zip(tmp_path / "unsafe-name.zip", [(member_name, b"x")])
    with pytest.raises(ZipValidationError):
        validate_zip(archive)



def test_duplicate_member_names_are_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "duplicates.zip"

    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r"Duplicate name:.*",
            category=UserWarning,
            module=r"zipfile",
        )

        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("same.txt", b"first")
            zf.writestr("same.txt", b"second")

    with pytest.raises(
        ZipValidationError,
        match="duplicate filename",
    ):
        validate_zip(archive)
        

def test_unicode_normalization_duplicate_names_are_rejected(tmp_path: Path) -> None:
    # NFC "é" and NFD "e + combining acute" normalize to the same name.
    archive = tmp_path / "unicode-duplicates.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("\u00e9.txt", b"first")
        zf.writestr("e\u0301.txt", b"second")

    with pytest.raises(ZipValidationError, match="duplicate filename"):
        validate_zip(archive)


def test_symlink_member_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16

    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(info, b"target.txt")

    with pytest.raises(ZipValidationError, match="symbolic link"):
        validate_zip(archive)


def test_directory_entry_with_data_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "directory-data.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("folder/", b"not empty")

    with pytest.raises(ZipValidationError, match="Directory entry contains data"):
        validate_zip(archive)


# ---------------------------------------------------------------------------
# Invalid limit configuration
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("argument", "value", "message"),
    [
        ("max_file_size", 0, "greater than zero"),
        ("max_file_size", -1, "greater than zero"),
        ("max_file_size", 1.5, "must be an integer"),
        ("max_file_size", True, "must be an integer"),
        ("max_zip_members", 0, "greater than zero"),
        ("max_total_extracted_size", -1, "greater than zero"),
        ("max_individual_file_size", 0, "greater than zero"),
        ("max_filename_length", 0, "greater than zero"),
        ("max_directory_depth", 0, "greater than zero"),
        ("max_uncompressed_ratio", 0, "greater than zero"),
        ("max_uncompressed_ratio", -1, "greater than zero"),
        ("max_uncompressed_ratio", "10", "must be a number"),
        ("max_uncompressed_ratio", True, "must be a number"),
    ],
)
def test_invalid_limit_values_raise_validation_error(
    valid_zip: Path, argument: str, value: object, message: str
) -> None:
    with pytest.raises(ZipValidationError, match=message):
        validate_zip(valid_zip, **{argument: value})


# ---------------------------------------------------------------------------
# Decorator API: bare, factory, named argument and custom limits
# ---------------------------------------------------------------------------

def test_bare_decorator_validates_first_argument(valid_zip: Path) -> None:
    @validate_zip
    def process(path):
        return f"processed:{Path(path).name}"

    assert process(valid_zip) == f"processed:{valid_zip.name}"


def test_decorator_factory_validates_first_argument(valid_zip: Path) -> None:
    @validate_zip()
    def process(path):
        return True

    assert process(str(valid_zip)) is True


def test_named_argument_decorator_validates_selected_argument(
    valid_zip: Path, tmp_path: Path
) -> None:
    @validate_zip("archive")
    def process(label, archive):
        return label

    assert process("job-1", valid_zip) == "job-1"

    bad_file = tmp_path / "bad.zip"
    bad_file.write_text("not a zip", encoding="utf-8")
    with pytest.raises(ZipValidationError):
        process("job-2", bad_file)


def test_decorator_supports_keyword_arguments(valid_zip: Path) -> None:
    @validate_zip("archive")
    def process(label, archive):
        return label

    assert process(label="job", archive=valid_zip) == "job"


def test_decorator_passes_custom_limits(valid_zip: Path) -> None:
    @validate_zip(max_file_size=1)
    def process(path):
        return "should not run"

    with pytest.raises(ZipValidationError, match="ZIP file is too large"):
        process(valid_zip)


def test_decorator_rejects_missing_target_argument() -> None:
    @validate_zip
    def process(path=None):
        return "should not run"

    with pytest.raises(ZipValidationError, match="Missing required argument"):
        process()


def test_decorator_rejects_non_path_argument() -> None:
    @validate_zip
    def process(path):
        return "should not run"

    with pytest.raises(ZipValidationError, match="Expected Path or str"):
        process(123)


def test_decorator_rejects_invalid_function_signature() -> None:
    @validate_zip
    def process(path):
        return "should not run"

    with pytest.raises(ZipValidationError, match="Invalid function call signature"):
        process()


def test_decorator_rejects_unknown_named_argument_target() -> None:
    with pytest.raises(ZipValidationError, match="is not an argument"):

        @validate_zip("unknown_argument")
        def process(path):
            return path


def test_decorator_rejects_function_without_parameters() -> None:
    with pytest.raises(ZipValidationError, match="has no arguments"):

        @validate_zip
        def process():
            return True


# ---------------------------------------------------------------------------
# Remote HTTPS behavior (network-free black-box tests)
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, payload: bytes, final_url: str = "https://example.test/archive.zip"):
        self._stream = io.BytesIO(payload)
        self._final_url = final_url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self._stream.close()

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def geturl(self) -> str:
        return self._final_url


def test_remote_https_zip_download_succeeds(monkeypatch, valid_zip_bytes: bytes) -> None:
    import fileaudit.zip_check as zip_check

    opener = Mock()
    opener.open.return_value = FakeResponse(valid_zip_bytes)
    monkeypatch.setattr(zip_check, "_https_opener", opener)

    assert validate_zip("https://example.test/archive.zip") is True
    opener.open.assert_called_once()


def test_remote_download_is_limited_by_max_file_size(
    monkeypatch, valid_zip_bytes: bytes
) -> None:
    import fileaudit.zip_check as zip_check

    opener = Mock()
    opener.open.return_value = FakeResponse(valid_zip_bytes)
    monkeypatch.setattr(zip_check, "_https_opener", opener)

    with pytest.raises(ZipValidationError, match="exceeded maximum size"):
        validate_zip("https://example.test/archive.zip", max_file_size=1)


def test_remote_final_url_must_remain_https(
    monkeypatch, valid_zip_bytes: bytes
) -> None:
    import fileaudit.zip_check as zip_check

    opener = Mock()
    opener.open.return_value = FakeResponse(
        valid_zip_bytes,
        final_url="http://example.test/archive.zip",
    )
    monkeypatch.setattr(zip_check, "_https_opener", opener)

    with pytest.raises(ZipValidationError):
        validate_zip("https://example.test/archive.zip")


def test_remote_http_error_is_wrapped_as_validation_error(monkeypatch) -> None:
    import urllib.error
    import fileaudit.zip_check as zip_check

    opener = Mock()
    opener.open.side_effect = urllib.error.HTTPError(
        "https://example.test/archive.zip",
        404,
        "Not Found",
        hdrs=None,
        fp=None,
    )
    monkeypatch.setattr(zip_check, "_https_opener", opener)

    with pytest.raises(ZipValidationError, match="HTTP 404"):
        validate_zip("https://example.test/archive.zip")


def test_remote_url_error_is_wrapped_as_validation_error(monkeypatch) -> None:
    import urllib.error
    import fileaudit.zip_check as zip_check

    opener = Mock()
    opener.open.side_effect = urllib.error.URLError("DNS lookup failed")
    monkeypatch.setattr(zip_check, "_https_opener", opener)

    with pytest.raises(ZipValidationError, match="Could not reach remote file"):
        validate_zip("https://example.test/archive.zip")


def test_remote_temporary_file_is_removed_after_success(
    monkeypatch, valid_zip_bytes: bytes, tmp_path: Path
) -> None:
    import fileaudit.zip_check as zip_check

    created_paths: list[str] = []
    real_named_temp_file = zip_check.tempfile.NamedTemporaryFile

    def recording_temp_file(*args, **kwargs):
        handle = real_named_temp_file(
            *args,
            dir=tmp_path,
            **{key: value for key, value in kwargs.items() if key != "dir"},
        )
        created_paths.append(handle.name)
        return handle

    opener = Mock()
    opener.open.return_value = FakeResponse(valid_zip_bytes)
    monkeypatch.setattr(zip_check, "_https_opener", opener)
    monkeypatch.setattr(zip_check.tempfile, "NamedTemporaryFile", recording_temp_file)

    assert validate_zip("https://example.test/archive.zip") is True
    assert created_paths
    assert all(not os.path.exists(path) for path in created_paths)


def test_remote_temporary_file_is_removed_after_validation_failure(
    monkeypatch, valid_zip_bytes: bytes, tmp_path: Path
) -> None:
    import fileaudit.zip_check as zip_check

    created_paths: list[str] = []
    real_named_temp_file = zip_check.tempfile.NamedTemporaryFile

    def recording_temp_file(*args, **kwargs):
        handle = real_named_temp_file(
            *args,
            dir=tmp_path,
            **{key: value for key, value in kwargs.items() if key != "dir"},
        )
        created_paths.append(handle.name)
        return handle

    opener = Mock()
    opener.open.return_value = FakeResponse(valid_zip_bytes)
    monkeypatch.setattr(zip_check, "_https_opener", opener)
    monkeypatch.setattr(zip_check.tempfile, "NamedTemporaryFile", recording_temp_file)

    with pytest.raises(ZipValidationError, match="exceeded maximum size"):
        validate_zip("https://example.test/archive.zip", max_file_size=1)

    assert created_paths
    assert all(not os.path.exists(path) for path in created_paths)
