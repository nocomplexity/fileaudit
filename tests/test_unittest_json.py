# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0

"""
Pytest test suite for FileAudit - File Security Checker.

Tests cover:
- Direct call / CLI mode (local files and HTTPS URLs)
- Decorator mode (bare, with args, targeting specific parameters)
- Security edge cases (size limits, depth limits, invalid JSON, TOCTOU, etc.)
- Error handling and exception types
"""

import json
import inspect
from pathlib import Path
from functools import wraps
from unittest.mock import patch, MagicMock, mock_open

import pytest
import urllib.request
import urllib.error
from urllib.parse import urlparse

# Import the module under test
# Adjust the import path to match your project structure
from fileaudit.json_check import (
    validate_json,
    _validate_json_file,
    limited_parse,
    FileValidationError,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_FILE_SIZE,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def valid_json_file(tmp_path):
    """Create a temporary valid JSON file."""
    file_path = tmp_path / "valid.json"
    file_path.write_text(json.dumps({"name": "test", "value": 42}))
    return file_path


@pytest.fixture
def deep_json_file(tmp_path):
    """Create a JSON file that exceeds default depth limits."""
    data = {}
    current = data
    for _ in range(DEFAULT_MAX_DEPTH + 10):
        current["nested"] = {}
        current = current["nested"]
    file_path = tmp_path / "deep.json"
    file_path.write_text(json.dumps(data))
    return file_path


@pytest.fixture
def large_json_file(tmp_path):
    """Create a JSON file that exceeds default size limits."""
    file_path = tmp_path / "large.json"
    # Create a file larger than DEFAULT_MAX_FILE_SIZE
    large_data = "x" * (DEFAULT_MAX_FILE_SIZE + 1000)
    file_path.write_text(json.dumps({"data": large_data}))
    return file_path


@pytest.fixture
def invalid_json_file(tmp_path):
    """Create a file with invalid JSON content."""
    file_path = tmp_path / "invalid.json"
    file_path.write_text("{invalid json: missing quotes}")
    return file_path


@pytest.fixture
def empty_file(tmp_path):
    """Create an empty file."""
    file_path = tmp_path / "empty.json"
    file_path.write_text("")
    return file_path


@pytest.fixture
def nested_list_json_file(tmp_path):
    """Create a JSON file with deeply nested lists."""
    data = []
    current = data
    for _ in range(DEFAULT_MAX_DEPTH + 5):
        new_list = []
        current.append(new_list)
        current = new_list
    file_path = tmp_path / "nested_list.json"
    file_path.write_text(json.dumps(data))
    return file_path


# =============================================================================
# TESTS: limited_parse
# =============================================================================

class TestLimitedParse:
    """Tests for the limited_parse depth validation function."""

    def test_valid_depth_dict(self):
        """Should not raise for dict nesting within limit."""
        data = {"a": {"b": {"c": "value"}}}
        limited_parse(data, max_depth=5)

    def test_valid_depth_list(self):
        """Should not raise for list nesting within limit."""
        data = [[["value"]]]
        limited_parse(data, max_depth=5)

    def test_valid_depth_mixed(self):
        """Should not raise for mixed dict/list nesting within limit."""
        data = {"a": [{"b": {"c": ["value"]}}]}
        limited_parse(data, max_depth=10)

    def test_depth_exceeded_dict(self):
        """Should raise FileValidationError when dict depth exceeds limit."""
        data = {}
        current = data
        for _ in range(6):
            current["next"] = {}
            current = current["next"]
        with pytest.raises(FileValidationError, match="JSON nesting depth exceeded"):
            limited_parse(data, max_depth=5)

    def test_depth_exceeded_list(self):
        """Should raise FileValidationError when list depth exceeds limit."""
        data = []
        current = data
        for _ in range(6):
            new_list = []
            current.append(new_list)
            current = new_list
        with pytest.raises(FileValidationError, match="JSON nesting depth exceeded"):
            limited_parse(data, max_depth=5)

    def test_exactly_at_limit(self):
        """Should not raise when depth is exactly at the limit."""
        data = {}
        current = data
        for _ in range(5):
            current["next"] = {}
            current = current["next"]
        limited_parse(data, max_depth=5)  # Should not raise

    def test_primitive_values(self):
        """Should handle primitive values without issues."""
        data = {
            "string": "value",
            "int": 42,
            "float": 3.14,
            "bool": True,
            "null": None,
        }
        limited_parse(data, max_depth=5)

    def test_empty_structures(self):
        """Should handle empty dicts and lists."""
        data = {"empty_dict": {}, "empty_list": []}
        limited_parse(data, max_depth=5)


# =============================================================================
# TESTS: _validate_json_file (Local Files)
# =============================================================================


# =============================================================================
# TESTS: _validate_json_file (Remote HTTPS URLs)
# =============================================================================



    @patch("urllib.request.urlopen")
    def test_remote_head_404(self, mock_urlopen):
        """Should handle HTTP 404 on HEAD request."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://example.com/missing.json", 404, "Not Found", {}, None
        )
        with pytest.raises(FileValidationError, match="Remote file unreachable"):
            _validate_json_file(
                "https://example.com/missing.json",
                DEFAULT_MAX_DEPTH,
                DEFAULT_MAX_FILE_SIZE,
            )


# =============================================================================
# TESTS: validate_json (Direct Call / CLI Mode)
# =============================================================================

class TestValidateJsonDirectCall:
    """Tests for validate_json in direct call / CLI mode."""

    def test_direct_call_local_valid(self, valid_json_file):
        """Should return True for valid local file."""
        result = validate_json(str(valid_json_file))
        assert result is True

    def test_direct_call_local_path_object(self, valid_json_file):
        """Should accept Path object directly."""
        result = validate_json(valid_json_file)
        assert result is True

    def test_direct_call_local_invalid(self, invalid_json_file):
        """Should return False for invalid local file."""
        result = validate_json(str(invalid_json_file))
        assert result is False

    def test_direct_call_local_missing(self, tmp_path):
        """Should return False for missing local file."""
        result = validate_json(str(tmp_path / "missing.json"))
        assert result is False

    def test_direct_call_remote_valid(self):
        """Should return True for valid remote HTTPS URL."""
        url = "https://pypi.org/pypi/codeaudit/json"
        result = validate_json(url)
        assert result is True

    def test_direct_call_remote_http_rejected(self):
        """Should return False for HTTP URL."""
        result = validate_json("http://example.com/data.json")
        assert result is False

    def test_direct_call_with_custom_depth(self, deep_json_file):
        """Should use custom depth limit."""
        result = validate_json(
            str(deep_json_file), max_depth=DEFAULT_MAX_DEPTH + 20
        )
        assert result is True

    def test_direct_call_with_custom_size(self, valid_json_file):
        """Should use custom size limit."""
        result = validate_json(
            str(valid_json_file), max_file_size=DEFAULT_MAX_FILE_SIZE * 2
        )
        assert result is True

    def test_direct_call_size_exceeded(self, large_json_file):
        """Should return False when file exceeds custom size."""
        result = validate_json(
            str(large_json_file), max_file_size=DEFAULT_MAX_FILE_SIZE
        )
        assert result is False

    def test_direct_call_depth_exceeded(self, deep_json_file):
        """Should return False when depth exceeds custom limit."""
        result = validate_json(
            str(deep_json_file), max_depth=DEFAULT_MAX_DEPTH
        )
        assert result is False


# =============================================================================
# TESTS: validate_json (Decorator Mode)
# =============================================================================

class TestValidateJsonDecorator:
    """Tests for validate_json in decorator mode."""

    def test_bare_decorator(self, valid_json_file):
        """Should work as bare @validate_json decorator."""

        @validate_json
        def process_file(file_path):
            return "processed"

        result = process_file(str(valid_json_file))
        assert result == "processed"

    def test_decorator_with_parens(self, valid_json_file):
        """Should work as @validate_json() decorator."""

        @validate_json()
        def process_file(file_path):
            return "processed"

        result = process_file(str(valid_json_file))
        assert result == "processed"

    def test_decorator_with_limits(self, deep_json_file):
        """Should apply custom limits in decorator mode."""

        @validate_json(max_depth=DEFAULT_MAX_DEPTH + 20)
        def process_file(file_path):
            return "processed"

        result = process_file(str(deep_json_file))
        assert result == "processed"

  
    def test_decorator_target_arg_by_name(self, valid_json_file):
        """Should target specific argument by name."""
        @validate_json("config_path")
        def process_data(config_path, other_arg):
            return f"processed {other_arg}"

        result = process_data(str(valid_json_file), "test")
        assert result == "processed test"

    
    def test_decorator_target_arg_wrong_name(self, valid_json_file):
        """Should raise when target argument is None/missing."""
        @validate_json
        def process_data(file_path, other_arg):
            return "processed"
        with pytest.raises(FileValidationError, match="Missing required argument"):
            process_data(None, "test")
            
    def test_decorator_no_arguments(self):
        """Should raise when decorating function with no arguments."""

        with pytest.raises(FileValidationError, match="has no arguments"):

            @validate_json
            def no_args():
                return "done"

    def test_decorator_invalid_json(self, invalid_json_file):
        """Should raise when argument points to invalid JSON."""

        @validate_json
        def process_file(file_path):
            return "processed"

        with pytest.raises(FileValidationError, match="Invalid JSON format"):
            process_file(str(invalid_json_file))

    def test_decorator_missing_file(self, tmp_path):
        """Should raise when argument points to missing file."""

        @validate_json
        def process_file(file_path):
            return "processed"

        with pytest.raises(FileValidationError, match="File not found"):
            process_file(str(tmp_path / "missing.json"))

    def test_decorator_path_object_arg(self, valid_json_file):
        """Should accept Path object as argument."""

        @validate_json
        def process_file(file_path):
            return "processed"

        result = process_file(valid_json_file)
        assert result == "processed"

    def test_decorator_invalid_arg_type(self):
        """Should raise when argument is not str or Path."""

        @validate_json
        def process_file(file_path):
            return "processed"

        with pytest.raises(FileValidationError, match="Expected Path or str"):
            process_file(12345)

    def test_decorator_missing_arg(self):
        """Should raise when required argument is None."""

        @validate_json
        def process_file(file_path):
            return "processed"

        with pytest.raises(FileValidationError, match="Missing required argument"):
            process_file(None)

    def test_decorator_remote_url(self):
        """Should work with remote HTTPS URL as argument."""

        @validate_json
        def fetch_data(url):
            return "fetched"

        result = fetch_data("https://pypi.org/pypi/codeaudit/json")
        assert result == "fetched"

    def test_decorator_remote_http_rejected(self):
        """Should raise for HTTP URL in decorator mode."""

        @validate_json
        def fetch_data(url):
            return "fetched"

        with pytest.raises(FileValidationError, match="only 'https' is allowed"):
            fetch_data("http://example.com/data.json")

    def test_decorator_with_max_file_size(self, large_json_file):
        """Should enforce custom max_file_size in decorator."""

        @validate_json(max_file_size=DEFAULT_MAX_FILE_SIZE)
        def process_file(file_path):
            return "processed"

        with pytest.raises(FileValidationError, match="exceeds maximum limit"):
            process_file(str(large_json_file))

    def test_decorator_preserves_function_metadata(self, valid_json_file):
        """Should preserve original function name and docstring."""

        @validate_json
        def my_function(file_path):
            """My docstring."""
            return "done"

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."

    def test_decorator_with_kwargs(self, valid_json_file):
        """Should work with keyword arguments."""

        @validate_json
        def process_file(file_path, mode="r"):
            return f"processed with {mode}"

        result = process_file(file_path=str(valid_json_file), mode="rb")
        assert result == "processed with rb"

    def test_decorator_with_default_arg(self, valid_json_file):
        """Should work when target arg has default value."""

        @validate_json
        def process_file(file_path="default.json"):
            return "processed"

        result = process_file(str(valid_json_file))
        assert result == "processed"

    def test_decorator_signature_mismatch(self):
        """Should raise for invalid function call signature."""

        @validate_json
        def process_file(file_path, required_arg):
            return "processed"

        with pytest.raises(FileValidationError, match="Invalid function call signature"):
            process_file(str("dummy"))  # Missing required_arg


# =============================================================================
# TESTS: FileValidationError
# =============================================================================

class TestFileValidationError:
    """Tests for the custom exception class."""

    def test_prefix_in_message(self):
        """Should include prefix in exception message."""
        err = FileValidationError("Something went wrong")
        assert "FileAudit Security Validation Failed -" in str(err)
        assert "Something went wrong" in str(err)

    def test_original_message_stored(self):
        """Should store original message separately."""
        err = FileValidationError("Original")
        assert err.original_message == "Original"

    def test_inheritance(self):
        """Should inherit from Exception."""
        assert issubclass(FileValidationError, Exception)

    def test_raises_correctly(self):
        """Should be raiseable and catchable."""
        with pytest.raises(FileValidationError):
            raise FileValidationError("test error")

    def test_from_chaining(self):
        """Should support exception chaining."""
        try:
            try:
                raise ValueError("original")
            except ValueError as e:
                raise FileValidationError("wrapped") from e
        except FileValidationError as e:
            assert e.__cause__ is not None
            assert isinstance(e.__cause__, ValueError)


# =============================================================================
# TESTS: Constants
# =============================================================================

class TestConstants:
    """Tests for module constants."""

    def test_default_max_depth_positive(self):
        """DEFAULT_MAX_DEPTH should be positive."""
        assert DEFAULT_MAX_DEPTH > 0

    def test_default_max_file_size_positive(self):
        """DEFAULT_MAX_FILE_SIZE should be positive."""
        assert DEFAULT_MAX_FILE_SIZE > 0

    def test_default_max_file_size_is_10mb(self):
        """DEFAULT_MAX_FILE_SIZE should equal 10 MiB."""
        assert DEFAULT_MAX_FILE_SIZE == 10 * 1024 * 1024


# =============================================================================
# TESTS: Edge Cases & Security
# =============================================================================

class TestEdgeCasesAndSecurity:
    """Edge cases and security-focused tests."""

    def test_unicode_in_json(self, tmp_path):
        """Should handle Unicode content correctly."""
        file_path = tmp_path / "unicode.json"
        file_path.write_text(json.dumps({"emoji": "🎉", "chinese": "中文"}))
        _validate_json_file(file_path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)

    def test_very_large_primitive_values(self, tmp_path):
        """Should handle very large string values."""
        file_path = tmp_path / "large_string.json"
        file_path.write_text(json.dumps({"data": "x" * 1000000}))
        _validate_json_file(file_path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)

    def test_special_characters_in_keys(self, tmp_path):
        """Should handle special characters in JSON keys."""
        file_path = tmp_path / "special.json"
        data = {"key-with-dashes": 1, "key.with.dots": 2, "key:with:colons": 3}
        file_path.write_text(json.dumps(data))
        _validate_json_file(file_path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)

    def test_null_bytes_in_filename(self, tmp_path):
        """Should handle or reject null bytes in path."""
        # This is more of an OS-level test, but good to check
        bad_path = tmp_path / "file\x00name.json"
        # Path() may raise ValueError on null bytes
        with pytest.raises((FileValidationError, ValueError)):
            _validate_json_file(bad_path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)

    def test_symlink_to_file(self, tmp_path, valid_json_file):
        """Should handle symlinks to valid files."""
        symlink = tmp_path / "link.json"
        symlink.symlink_to(valid_json_file)
        _validate_json_file(symlink, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)

    def test_circular_reference_not_possible(self):
        """JSON cannot have circular references, but test deep nesting."""
        # This is more of a conceptual test - json.dumps would fail on circular refs
        pass


    def test_toctou_protection(self, valid_json_file):
        """Should handle a file disappearing between validation and reading."""
        original_open = Path.open
        deleted = False

        def evil_open(self, *args, **kwargs):
            nonlocal deleted

            if self == valid_json_file and not deleted:
                deleted = True
                self.unlink()

            return original_open(self, *args, **kwargs)

        with patch.object(Path, "open", evil_open):
            with pytest.raises((FileValidationError, OSError)):
                _validate_json_file(
                    valid_json_file,
                    DEFAULT_MAX_DEPTH,
                    DEFAULT_MAX_FILE_SIZE,
                )


   

    def test_bom_in_json(self, tmp_path):
        """Should reject JSON with UTF-8 BOM — Python's json module does not support BOM."""
        file_path = tmp_path / "bom.json"
        file_path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"key": "value"}).encode())
        with pytest.raises(FileValidationError, match="Invalid JSON format"):
            _validate_json_file(file_path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)

    def test_trailing_comma_json(self, tmp_path):
        """Should reject JSON with trailing commas."""
        file_path = tmp_path / "trailing.json"
        file_path.write_text('{"key": "value",}')
        with pytest.raises(FileValidationError, match="Invalid JSON format"):
            _validate_json_file(file_path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)

    def test_single_quoted_json(self, tmp_path):
        """Should reject JSON with single quotes."""
        file_path = tmp_path / "single_quote.json"
        file_path.write_text("{'key': 'value'}")
        with pytest.raises(FileValidationError, match="Invalid JSON format"):
            _validate_json_file(file_path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)

    def test_json_lines_format(self, tmp_path):
        """Should reject JSON Lines format (not valid single JSON)."""
        file_path = tmp_path / "jsonl.json"
        file_path.write_text('{"a": 1}\n{"b": 2}\n')
        with pytest.raises(FileValidationError, match="Invalid JSON format"):
            _validate_json_file(file_path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)

    def test_remote_url_with_query_params(self):
        """Should handle URLs with query parameters."""
        # We won't actually fetch, just verify parsing
        url = "https://example.com/api?format=json&key=value"
        parsed = urlparse(url)
        assert parsed.scheme == "https"
        assert "example.com" in parsed.netloc

    def test_remote_url_with_fragment(self):
        """Should handle URLs with fragments."""
        url = "https://pypi.org/pypi/codeaudit/json#section"
        parsed = urlparse(url)
        assert parsed.scheme == "https"

    def test_zero_byte_file(self, tmp_path):
        """Should reject zero-byte file."""
        file_path = tmp_path / "zero.json"
        file_path.write_text("")
        with pytest.raises(FileValidationError, match="Invalid JSON format"):
            _validate_json_file(file_path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)

    def test_whitespace_only_file(self, tmp_path):
        """Should reject whitespace-only file."""
        file_path = tmp_path / "whitespace.json"
        file_path.write_text("   \n\t  ")
        with pytest.raises(FileValidationError, match="Invalid JSON format"):
            _validate_json_file(file_path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)

    def test_json_with_comments(self, tmp_path):
        """Should reject JSON with comments (not standard JSON)."""
        file_path = tmp_path / "comments.json"
        file_path.write_text('{"key": "value" /* comment */}')
        with pytest.raises(FileValidationError, match="Invalid JSON format"):
            _validate_json_file(file_path, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE)


