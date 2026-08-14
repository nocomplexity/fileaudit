# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

import inspect
from pathlib import Path

import pytest

import fileaudit.zip_check as zip_check
from fileaudit.zip_check import (
    validate_zip,
    ZipValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_zip_validator(monkeypatch):
    """
    Replace the internal ZIP validator so these tests focus on
    validate_zip() rather than _validate_zip_file().
    """
    calls = []

    def fake_validate_zip_file(*args):
        calls.append(args)

    monkeypatch.setattr(
        zip_check,
        "_validate_zip_file",
        fake_validate_zip_file,
    )

    return calls


@pytest.fixture
def failing_zip_validator(monkeypatch):
    """
    Make the internal validator fail with the supplied exception.
    """

    def install(exception):
        def fake_validate_zip_file(*args):
            raise exception

        monkeypatch.setattr(
            zip_check,
            "_validate_zip_file",
            fake_validate_zip_file,
        )

    return install


# ===========================================================================
# Direct-call / CLI mode
# ===========================================================================

def test_direct_call_with_string_path_returns_true(
    mock_zip_validator,
):
    result = validate_zip("archive.zip")

    assert result is True
    assert mock_zip_validator[0][0] == "archive.zip"


def test_direct_call_with_path_object_returns_true(
    mock_zip_validator,
):
    path = Path("archive.zip")

    result = validate_zip(path)

    assert result is True
    assert mock_zip_validator[0][0] == path


def test_direct_call_returns_false_when_validation_fails(
    failing_zip_validator,
    capsys,
):
    failing_zip_validator(
        ZipValidationError("ZIP contains unsafe path")
    )

    result = validate_zip("archive.zip")

    assert result is False

    captured = capsys.readouterr()

    assert "Exception:" in captured.out
    assert "ZIP contains unsafe path" in captured.out

    def test_direct_call_catches_unexpected_exception(
        failing_zip_validator,
        capsys,
    ):
        failing_zip_validator(RuntimeError("unexpected failure"))

        # This must stay a boolean, never a function
        result = validate_zip("archive.zip")
        assert result is False
        assert not callable(result)

        captured = capsys.readouterr()
        assert "Exception:" in captured.out
        assert "unexpected failure" in captured.out
    
# ===========================================================================
# Default limit resolution
# ===========================================================================

def test_default_limits_are_passed_to_internal_validator(
    mock_zip_validator,
):
    validate_zip("archive.zip")

    args = mock_zip_validator[0]

    assert args[0] == "archive.zip"
    assert args[1] == zip_check.DEFAULT_MAX_FILE_SIZE
    assert args[2] == zip_check.DEFAULT_MAX_UNCOMPRESSED_RATIO
    assert args[3] == zip_check.DEFAULT_MAX_ZIP_MEMBERS
    assert args[4] == zip_check.DEFAULT_MAX_TOTAL_EXTRACTED_SIZE
    assert args[5] == zip_check.DEFAULT_MAX_INDIVIDUAL_FILE_SIZE
    assert args[6] == zip_check.DEFAULT_MAX_FILENAME_LENGTH
    assert args[7] == zip_check.DEFAULT_MAX_DIRECTORY_DEPTH


def test_custom_limits_are_passed_to_internal_validator(
    mock_zip_validator,
):
    result = validate_zip(
        "archive.zip",
        max_file_size=500,
        max_uncompressed_ratio=10,
        max_zip_members=20,
        max_total_extracted_size=30,
        max_individual_file_size=40,
        max_filename_length=50,
        max_directory_depth=60,
    )

    assert result is True

    assert mock_zip_validator == [
        (
            "archive.zip",
            500,
            10,
            20,
            30,
            40,
            50,
            60,
        )
    ]


def test_none_limits_use_defaults(
    mock_zip_validator,
):
    validate_zip(
        "archive.zip",
        max_file_size=None,
        max_uncompressed_ratio=None,
        max_zip_members=None,
        max_total_extracted_size=None,
        max_individual_file_size=None,
        max_filename_length=None,
        max_directory_depth=None,
    )

    args = mock_zip_validator[0]

    assert args[1] == zip_check.DEFAULT_MAX_FILE_SIZE
    assert args[2] == zip_check.DEFAULT_MAX_UNCOMPRESSED_RATIO
    assert args[3] == zip_check.DEFAULT_MAX_ZIP_MEMBERS
    assert args[4] == zip_check.DEFAULT_MAX_TOTAL_EXTRACTED_SIZE
    assert args[5] == zip_check.DEFAULT_MAX_INDIVIDUAL_FILE_SIZE
    assert args[6] == zip_check.DEFAULT_MAX_FILENAME_LENGTH
    assert args[7] == zip_check.DEFAULT_MAX_DIRECTORY_DEPTH


# ===========================================================================
# Bare decorator: @validate_zip
# ===========================================================================

def test_bare_decorator_validates_first_argument(
    mock_zip_validator,
):
    @validate_zip
    def process(path):
        return "processed"

    result = process("archive.zip")

    assert result == "processed"
    assert mock_zip_validator[0][0] == "archive.zip"


def test_bare_decorator_supports_path_argument(
    mock_zip_validator,
):
    @validate_zip
    def process(path):
        return path

    path = Path("archive.zip")

    result = process(path)

    assert result == path
    assert mock_zip_validator[0][0] == path


def test_bare_decorator_preserves_function_metadata(
    mock_zip_validator,
):
    @validate_zip
    def process(path):
        """Process a ZIP file."""
        return path

    assert process.__name__ == "process"
    assert process.__doc__ == "Process a ZIP file."


def test_bare_decorator_preserves_signature(
    mock_zip_validator,
):
    @validate_zip
    def process(path, verbose=False):
        return path

    signature = inspect.signature(process)

    assert list(signature.parameters) == [
        "path",
        "verbose",
    ]


# ===========================================================================
# Decorator factory: @validate_zip()
# ===========================================================================

def test_empty_decorator_factory_uses_first_argument(
    mock_zip_validator,
):
    @validate_zip()
    def process(path):
        return "ok"

    result = process("archive.zip")

    assert result == "ok"
    assert mock_zip_validator[0][0] == "archive.zip"


def test_empty_decorator_factory_supports_multiple_arguments(
    mock_zip_validator,
):
    @validate_zip()
    def process(zip_path, output_path):
        return output_path

    result = process(
        "archive.zip",
        "output.txt",
    )

    assert result == "output.txt"
    assert mock_zip_validator[0][0] == "archive.zip"


# ===========================================================================
# Named argument: @validate_zip("zip_path")
# ===========================================================================

def test_named_argument_is_validated(
    mock_zip_validator,
):
    @validate_zip("zip_path")
    def process(zip_path):
        return "ok"

    result = process("archive.zip")

    assert result == "ok"
    assert mock_zip_validator[0][0] == "archive.zip"


def test_named_argument_is_used_instead_of_first_argument(
    mock_zip_validator,
):
    @validate_zip("zip_path")
    def process(other, zip_path):
        return "ok"

    result = process(
        "not-the-zip",
        "archive.zip",
    )

    assert result == "ok"
    assert mock_zip_validator[0][0] == "archive.zip"


def test_named_argument_works_with_keyword_call(
    mock_zip_validator,
):
    @validate_zip("zip_path")
    def process(zip_path):
        return "ok"

    result = process(
        zip_path="archive.zip"
    )

    assert result == "ok"
    assert mock_zip_validator[0][0] == "archive.zip"


def test_named_argument_works_with_mixed_arguments(
    mock_zip_validator,
):
    @validate_zip("zip_path")
    def process(other, zip_path, flag=False):
        return flag

    result = process(
        "other",
        zip_path="archive.zip",
        flag=True,
    )

    assert result is True
    assert mock_zip_validator[0][0] == "archive.zip"


# ===========================================================================
# Named argument + custom limits
# ===========================================================================

def test_named_argument_with_custom_limits(
    mock_zip_validator,
):
    @validate_zip(
        "zip_path",
        max_file_size=500,
        max_uncompressed_ratio=10,
        max_zip_members=100,
        max_total_extracted_size=1000,
        max_individual_file_size=200,
        max_filename_length=80,
        max_directory_depth=5,
    )
    def process(zip_path):
        return "ok"

    result = process("archive.zip")

    assert result == "ok"

    assert mock_zip_validator == [
        (
            "archive.zip",
            500,
            10,
            100,
            1000,
            200,
            80,
            5,
        )
    ]


# ===========================================================================
# Function return value
# ===========================================================================

def test_original_function_return_value_is_preserved(
    mock_zip_validator,
):
    @validate_zip
    def process(path):
        return {
            "path": path,
            "status": "processed",
        }

    result = process("archive.zip")

    assert result == {
        "path": "archive.zip",
        "status": "processed",
    }


def test_original_function_receives_original_arguments(
    mock_zip_validator,
):
    received = {}

    @validate_zip
    def process(path, value):
        received["path"] = path
        received["value"] = value
        return value

    result = process(
        "archive.zip",
        123,
    )

    assert result == 123

    assert received == {
        "path": "archive.zip",
        "value": 123,
    }


# ===========================================================================
# Validation failure in decorator mode
# ===========================================================================

def test_decorator_raises_zip_validation_error(
    failing_zip_validator,
):
    failing_zip_validator(
        ZipValidationError("unsafe ZIP")
    )

    @validate_zip
    def process(path):
        return "should not execute"

    with pytest.raises(
        ZipValidationError,
        match="unsafe ZIP",
    ):
        process("archive.zip")


def test_original_function_is_not_called_when_validation_fails(
    failing_zip_validator,
):
    failing_zip_validator(
        ZipValidationError("validation failed")
    )

    called = False

    @validate_zip
    def process(path):
        nonlocal called
        called = True

    with pytest.raises(ZipValidationError):
        process("archive.zip")

    assert called is False


def test_unexpected_validation_exception_is_propagated(
    failing_zip_validator,
):
    failing_zip_validator(
        RuntimeError("validator crashed")
    )

    @validate_zip
    def process(path):
        return "ok"

    with pytest.raises(
        RuntimeError,
        match="validator crashed",
    ):
        process("archive.zip")


# ===========================================================================
# Function argument validation
# ===========================================================================

def test_missing_argument_is_rejected():
    with pytest.raises(
        ZipValidationError,
        match="has no arguments",
    ):
        @validate_zip
        def process():
            pass


def test_invalid_function_call_signature_is_rejected(
    mock_zip_validator,
):
    @validate_zip
    def process(path):
        return "ok"

    with pytest.raises(
        ZipValidationError,
        match="Invalid function call signature",
    ):
        process()


def test_non_path_argument_is_rejected(
    mock_zip_validator,
):
    @validate_zip
    def process(path):
        return "ok"

    with pytest.raises(
        ZipValidationError,
        match="Expected Path or str",
    ):
        process(123)


def test_none_path_is_rejected(
    mock_zip_validator,
):
    @validate_zip
    def process(path):
        return "ok"

    with pytest.raises(
        ZipValidationError,
        match="Missing required argument",
    ):
        process(None)


def test_named_argument_with_default_none_is_rejected(
    mock_zip_validator,
):
    @validate_zip("zip_path")
    def process(zip_path=None):
        return "ok"

    with pytest.raises(
        ZipValidationError,
        match="Missing required argument",
    ):
        process()


def test_pathlib_path_is_accepted(
    mock_zip_validator,
):
    @validate_zip
    def process(path):
        return path

    path = Path("/tmp/archive.zip")

    assert process(path) == path
    assert mock_zip_validator[0][0] == path


# ===========================================================================
# Decorator argument-name behavior
# ===========================================================================

def test_non_matching_identifier_raises(
    mock_zip_validator,
):
    with pytest.raises(
        ZipValidationError,
        match="'does_not_exist' is not an argument of 'process'"
    ):
        @validate_zip("does_not_exist")
        def process(path, other):
            return "ok"
        

def test_named_argument_that_matches_parameter_is_selected(
    mock_zip_validator,
):
    @validate_zip("zip_path")
    def process(first, zip_path):
        return "ok"

    process(
        "first-value",
        "archive.zip",
    )

    assert mock_zip_validator[0][0] == "archive.zip"


def test_identifier_detection_distinguishes_path_from_argument_name(
    mock_zip_validator,
):
    @validate_zip("zip_path")
    def process(zip_path):
        return "ok"

    assert process("archive.zip") == "ok"

    # "archive.zip" is not a valid Python identifier, so this
    # is interpreted as direct-call mode.
    assert validate_zip("archive.zip") is True


# ===========================================================================
# Keyword/default argument binding
# ===========================================================================

def test_default_arguments_are_applied(
    mock_zip_validator,
):
    @validate_zip
    def process(path, mode="safe"):
        return mode

    result = process("archive.zip")

    assert result == "safe"
    assert mock_zip_validator[0][0] == "archive.zip"


def test_keyword_arguments_are_bound_correctly(
    mock_zip_validator,
):
    @validate_zip
    def process(path, *, mode):
        return mode

    result = process(
        path="archive.zip",
        mode="safe",
    )

    assert result == "safe"
    assert mock_zip_validator[0][0] == "archive.zip"


def test_positional_and_keyword_arguments_are_bound(
    mock_zip_validator,
):
    @validate_zip("zip_path")
    def process(first, zip_path, *, enabled=False):
        return enabled

    result = process(
        "first",
        zip_path="archive.zip",
        enabled=True,
    )

    assert result is True
    assert mock_zip_validator[0][0] == "archive.zip"


# ===========================================================================
# Direct-call edge cases
# ===========================================================================

def test_direct_call_with_relative_path(
    mock_zip_validator,
):
    assert validate_zip("./archive.zip") is True

    assert mock_zip_validator[0][0] == "./archive.zip"


def test_direct_call_with_absolute_path(
    mock_zip_validator,
):
    path = "/tmp/archive.zip"

    assert validate_zip(path) is True

    assert mock_zip_validator[0][0] == path


def test_direct_call_with_path_object(
    mock_zip_validator,
):
    path = Path("/tmp/archive.zip")

    assert validate_zip(path) is True

    assert mock_zip_validator[0][0] == path


# ===========================================================================
# Decorator construction
# ===========================================================================

def test_validate_zip_returns_decorator_for_empty_factory():
    decorator = validate_zip()

    assert callable(decorator)


def test_validate_zip_returns_decorator_for_named_argument():
    decorator = validate_zip("zip_path")

    assert callable(decorator)


def test_bare_validate_zip_returns_function_when_used_as_decorator(
    mock_zip_validator,
):
    def process(path):
        return "ok"

    decorated = validate_zip(process)

    assert callable(decorated)
    assert decorated("archive.zip") == "ok"


# ===========================================================================
# Security-limit forwarding
# ===========================================================================

@pytest.mark.parametrize(
    "argument,value,index",
    [
        ("max_file_size", 123, 1),
        ("max_uncompressed_ratio", 12.5, 2),
        ("max_zip_members", 50, 3),
        ("max_total_extracted_size", 456, 4),
        ("max_individual_file_size", 789, 5),
        ("max_filename_length", 99, 6),
        ("max_directory_depth", 7, 7),
    ],
)
def test_each_security_limit_is_forwarded(
    mock_zip_validator,
    argument,
    value,
    index,
):
    result = validate_zip(
        "archive.zip",
        **{argument: value},
    )

    assert result is True
    assert mock_zip_validator[0][index] == value


# ===========================================================================
# No validation bypass
# ===========================================================================

def test_decorated_function_cannot_execute_before_validation(
    failing_zip_validator,
):
    failing_zip_validator(
        ZipValidationError("blocked")
    )

    execution_order = []

    @validate_zip
    def process(path):
        execution_order.append("function")
        return "executed"

    with pytest.raises(ZipValidationError):
        process("archive.zip")

    assert execution_order == []


def test_validation_happens_on_every_function_call(
    mock_zip_validator,
):
    calls = []

    @validate_zip
    def process(path):
        calls.append(path)
        return path

    assert process("one.zip") == "one.zip"
    assert process("two.zip") == "two.zip"

    assert calls == [
        "one.zip",
        "two.zip",
    ]

    assert [
        call[0]
        for call in mock_zip_validator
    ] == [
        "one.zip",
        "two.zip",
    ]
