# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Crucial pytest unit tests for `validate_json`.

Covers both operating modes and the mode-detection heuristic:

Direct-call / CLI mode
- Valid local file / Path → True
- Invalid file → False + exception printed
- HTTPS URL treated as path
- Defaults applied when limits omitted

Decorator mode
- Bare @validate_json
- @validate_json()
- @validate_json(max_depth=…, max_file_size=…)
- @validate_json("custom_arg")
- Default target = first parameter
- Validation runs *before* the wrapped function
- FileValidationError on failure (does *not* swallow)
- No-args function, missing arg, wrong type, bind errors

The lower-level `_validate_json_file` is mocked so these tests stay focused
on the decorator / mode-dispatch logic.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from fileaudit.json_check import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_FILE_SIZE,
    FileValidationError,
    validate_json,
    _validate_json_file,  # only for patching
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_validate():
    """Patch the internal validator so we can assert call arguments."""
    with patch("fileaudit.json_check._validate_json_file") as m:
        yield m


# ---------------------------------------------------------------------------
# 1. Direct-call / CLI mode – success
# ---------------------------------------------------------------------------

def test_direct_call_valid_local_str(mock_validate, tmp_path):
    p = tmp_path / "ok.json"
    p.write_text("{}")
    result = validate_json(str(p))
    assert result is True
    mock_validate.assert_called_once_with(
        str(p), DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE
    )


def test_direct_call_valid_path_object(mock_validate, tmp_path):
    p = tmp_path / "ok.json"
    p.write_text("{}")
    result = validate_json(p)
    assert result is True
    mock_validate.assert_called_once_with(
        p, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE
    )


def test_direct_call_custom_limits(mock_validate, tmp_path):
    p = tmp_path / "ok.json"
    p.write_text("{}")
    result = validate_json(str(p), max_depth=7, max_file_size=42)
    assert result is True
    mock_validate.assert_called_once_with(str(p), 7, 42)


def test_direct_call_https_url(mock_validate):
    url = "https://example.com/data.json"
    result = validate_json(url, max_depth=3)
    assert result is True
    mock_validate.assert_called_once_with(url, 3, DEFAULT_MAX_FILE_SIZE)


# ---------------------------------------------------------------------------
# 2. Direct-call / CLI mode – failure (swallows & returns False)
# ---------------------------------------------------------------------------
def test_direct_call_validation_failure_returns_false(mock_validate, capsys):
    mock_validate.side_effect = FileValidationError("boom")
    result = validate_json("https://example.com/bad.json")
    assert result is False
    captured = capsys.readouterr()
    assert "Exception: FileAudit Security Validation Failed - boom" in captured.out
    # or, more loosely:
    # assert "FileAudit Security Validation Failed - boom" in captured.out



def test_direct_call_unexpected_exception_returns_false(mock_validate, capsys):
    mock_validate.side_effect = RuntimeError("unexpected")
    result = validate_json("/tmp/whatever.json")
    assert result is False
    assert "Exception: unexpected" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 3. Mode-detection heuristic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value, expected_decorator_mode",
    [
        # Identifiers → decorator mode
        ("config_path", True),
        ("file", True),
        ("_private", True),
        ("jsonData", True),
        # Paths / URLs → direct-call mode
        ("/abs/path.json", False),
        ("\\windows\\path.json", False),
        ("relative/path.json", False),
        ("file.json", False),          # contains dot → treated as path
        ("https://example.com/x", False),
        (Path("/tmp/x.json"), False),  # Path objects always direct
    ],
)
def test_mode_detection_heuristic(mock_validate, value, expected_decorator_mode):
    """
    When the first positional argument is a string/Path we decide mode
    solely by the heuristic.  We never call the real validator for pure
    mode-detection tests; we only check the returned type / behaviour.
    """
    if expected_decorator_mode:
        # Should return a decorator (callable that expects a function)
        dec = validate_json(value)
        assert callable(dec)
        # Applying it to a dummy function must succeed
        @dec
        def dummy(config_path):
            return "ok"
        assert dummy.__name__ == "dummy"
    else:
        # Should go straight into direct-call mode and return bool
        result = validate_json(value)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# 4. Decorator mode – bare & factory forms
# ---------------------------------------------------------------------------

def test_bare_decorator_validates_first_arg(mock_validate):
    @validate_json
    def process(file_path, other=None):
        return "processed"

    process("/tmp/data.json")
    mock_validate.assert_called_once_with(
        "/tmp/data.json", DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE
    )


def test_factory_no_args(mock_validate):
    @validate_json()
    def process(file_path):
        return "ok"

    process("data.json")
    mock_validate.assert_called_once()


def test_factory_with_limits(mock_validate):
    @validate_json(max_depth=9, max_file_size=1234)
    def process(path):
        return path

    process("https://example.com/x.json")
    mock_validate.assert_called_once_with(
        "https://example.com/x.json", 9, 1234
    )


def test_named_target_argument(mock_validate):
    @validate_json("config")
    def process(other, config, more=None):
        return "done"

    process(1, config="/etc/config.json")
    mock_validate.assert_called_once_with(
        "/etc/config.json", DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE
    )


def test_named_target_with_limits(mock_validate):
    @validate_json("cfg", max_depth=2, max_file_size=100)
    def process(cfg, x=0):
        return x

    process(cfg=Path("/tmp/c.json"))
    mock_validate.assert_called_once_with(Path("/tmp/c.json"), 2, 100)


# ---------------------------------------------------------------------------
# 5. Decorator mode – validation occurs *before* the body
# ---------------------------------------------------------------------------

def test_decorator_runs_validation_before_body(mock_validate):
    body_called = False

    @validate_json
    def process(path):
        nonlocal body_called
        body_called = True
        return "result"

    # Make validator raise → body must never run
    mock_validate.side_effect = FileValidationError("bad file")
    with pytest.raises(FileValidationError, match="bad file"):
        process("/bad.json")
    assert body_called is False


def test_decorator_passes_on_success(mock_validate):
    @validate_json
    def process(path):
        return "success"

    assert process("good.json") == "success"
    mock_validate.assert_called_once()


# ---------------------------------------------------------------------------
# 6. Decorator mode – error conditions (raise, do not swallow)
# ---------------------------------------------------------------------------

def test_decorator_no_arguments_raises():
    with pytest.raises(FileValidationError, match="has no arguments"):
        @validate_json
        def no_args():
            pass

def test_decorator_missing_argument_raises(mock_validate):
    @validate_json("missing_arg")          # name not in signature → falls back to first param
    def process(other=None):               # default None so bind() succeeds
        pass

    with pytest.raises(FileValidationError, match="Missing required argument"):
        process()                          # other is None → hits the explicit check


def test_decorator_wrong_type_raises(mock_validate):
    @validate_json
    def process(file_path):
        pass

    with pytest.raises(FileValidationError, match="Expected Path or str"):
        process(12345)   # int is illegal


def test_decorator_bind_error_raises(mock_validate):
    @validate_json
    def process(a, b):
        pass

    with pytest.raises(FileValidationError, match="Invalid function call signature"):
        process()   # missing both required args


def test_decorator_propagates_validation_error(mock_validate):
    mock_validate.side_effect = FileValidationError("size exceeded")
    @validate_json
    def process(path):
        return "never"

    with pytest.raises(FileValidationError, match="size exceeded"):
        process("big.json")


# ---------------------------------------------------------------------------
# 7. Interaction of defaults & explicit None
# ---------------------------------------------------------------------------

def test_explicit_none_falls_back_to_defaults(mock_validate, tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{}")
    # Passing None explicitly must still resolve to the module defaults
    result = validate_json(str(p), max_depth=None, max_file_size=None)
    assert result is True
    mock_validate.assert_called_once_with(
        str(p), DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE
    )


# ---------------------------------------------------------------------------
# 8. Decorator preserves function metadata
# ---------------------------------------------------------------------------

def test_decorator_preserves_name_and_doc(mock_validate):
    @validate_json
    def my_func(path: str) -> str:
        """Docstring stays."""
        return path

    assert my_func.__name__ == "my_func"
    assert my_func.__doc__ == "Docstring stays."