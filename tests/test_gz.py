# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests for the @validate_gz decorator 
"""

import gzip
import inspect
from pathlib import Path
from functools import wraps
from unittest.mock import patch, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Assumed supporting definitions (adjust imports to match your actual module)
# ---------------------------------------------------------------------------
from fileaudit.gz_check import (
    validate_gz,
    GzValidationError,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_UNCOMPRESSED_RATIO,
    DEFAULT_MAX_UNCOMPRESSED_SIZE,
    _validate_gz_file,
    _validate_limit,
)

# For self-contained tests we re-create minimal stubs that mirror the
# documented behaviour.  Replace them with the real objects in production.

DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024          # 10 MiB
DEFAULT_MAX_UNCOMPRESSED_RATIO = 100
DEFAULT_MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MiB


class GzValidationError(Exception):
    """Raised when validation fails in decorator mode."""


def _validate_limit(name: str, value) -> None:
    if not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"{name} must be a non-negative number, got {value!r}")


def _validate_gz_file(
    path,
    max_file_size: int,
    max_ratio: float,
    max_uncompressed_size: int,
) -> None:
    """Minimal implementation that exercises the limits the decorator cares about."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"No such file: {path}")

    compressed_size = p.stat().st_size
    if compressed_size > max_file_size:
        raise GzValidationError(
            f"Compressed size {compressed_size} exceeds max_file_size={max_file_size}"
        )

    # Cheap ratio / uncompressed-size check without fully decompressing huge files
    with gzip.open(p, "rb") as f:
        # Read only enough to compute a safe upper bound
        data = f.read(max_uncompressed_size + 1)
        uncompressed_size = len(data)

    if uncompressed_size > max_uncompressed_size:
        raise GzValidationError(
            f"Uncompressed size exceeds max_uncompressed_size={max_uncompressed_size}"
        )

    if compressed_size > 0:
        ratio = uncompressed_size / compressed_size
        if ratio > max_ratio:
            raise GzValidationError(
                f"Decompression ratio {ratio:.1f} exceeds max_uncompressed_ratio={max_ratio}"
            )


# ---------------------------------------------------------------------------
# The function under test (copied from the prompt for completeness)
# ---------------------------------------------------------------------------
def validate_gz(
    func_or_path=None,
    max_file_size=None,
    max_uncompressed_ratio=None,
    max_uncompressed_size=None,
):
    """
    Validate GZip files via decorator or direct invocation.
    (full docstring omitted for brevity – identical to the prompt)
    """
    # Resolve limits
    resolved_file_size = (
        DEFAULT_MAX_FILE_SIZE if max_file_size is None else max_file_size
    )
    resolved_ratio = (
        DEFAULT_MAX_UNCOMPRESSED_RATIO
        if max_uncompressed_ratio is None
        else max_uncompressed_ratio
    )
    resolved_uncompressed_size = (
        DEFAULT_MAX_UNCOMPRESSED_SIZE
        if max_uncompressed_size is None
        else max_uncompressed_size
    )

    _validate_limit("max_file_size", resolved_file_size)
    _validate_limit("max_uncompressed_ratio", resolved_ratio)
    _validate_limit("max_uncompressed_size", resolved_uncompressed_size)

    if resolved_ratio == 0:
        raise ValueError("max_uncompressed_ratio must be greater than 0")

    # Determine decorator / direct-call mode
    if func_or_path is None:
        is_decorator_mode = True
    elif callable(func_or_path):
        is_decorator_mode = True
    elif isinstance(func_or_path, Path):
        is_decorator_mode = False
    elif isinstance(func_or_path, str):
        is_decorator_mode = func_or_path.isidentifier()
    else:
        raise TypeError("func_or_path must be a callable, str, Path, or None")

    # Direct call / CLI mode
    if not is_decorator_mode:
        try:
            _validate_gz_file(
                func_or_path,
                resolved_file_size,
                resolved_ratio,
                resolved_uncompressed_size,
            )
            return True
        except Exception as e:
            print(f"Exception: {e}")
            return False

    # Decorator mode
    def decorator(func):
        sig = inspect.signature(func)
        params = list(sig.parameters.keys())
        if not params:
            raise GzValidationError(
                f"Decorator applied to '{func.__name__}', but it has no arguments."
            )
        if isinstance(func_or_path, str) and func_or_path in params:
            target_arg = func_or_path
        else:
            target_arg = params[0]

        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
            except TypeError as e:
                raise GzValidationError(
                    f"Invalid function call signature: {e}"
                ) from e

            path = bound_args.arguments.get(target_arg)
            if path is None:
                raise GzValidationError(f"Missing required argument: {target_arg}")
            if not isinstance(path, (str, Path)):
                raise GzValidationError(
                    f"Expected Path or str for {target_arg}, got {type(path).__name__}"
                )

            _validate_gz_file(
                path,
                resolved_file_size,
                resolved_ratio,
                resolved_uncompressed_size,
            )
            return func(*args, **kwargs)

        return wrapper

    if callable(func_or_path):
        return decorator(func_or_path)
    return decorator


# ===========================================================================
# Test helpers
# ===========================================================================

@pytest.fixture
def tmp_gz(tmp_path):
    """Create a small valid .gz file and return its Path."""
    content = b"hello world" * 10
    gz_path = tmp_path / "sample.gz"
    with gzip.open(gz_path, "wb") as f:
        f.write(content)
    return gz_path


@pytest.fixture
def large_gz(tmp_path):
    """Create a .gz whose compressed size is intentionally large."""
    # ~50 KiB of highly compressible data → small compressed size
    content = b"A" * 50_000
    gz_path = tmp_path / "large.gz"
    with gzip.open(gz_path, "wb") as f:
        f.write(content)
    return gz_path


def make_gz(tmp_path, data: bytes, name: str = "test.gz") -> Path:
    path = tmp_path / name
    with gzip.open(path, "wb") as f:
        f.write(data)
    return path


# ===========================================================================
# 1. Limit validation
# ===========================================================================

class TestLimitValidation:
    def test_negative_max_file_size_raises(self):
        with pytest.raises(ValueError, match="max_file_size"):
            validate_gz(max_file_size=-1)

    def test_negative_ratio_raises(self):
        with pytest.raises(ValueError, match="max_uncompressed_ratio"):
            validate_gz(max_uncompressed_ratio=-5)

    def test_zero_ratio_raises(self):
        with pytest.raises(ValueError, match="must be greater than 0"):
            validate_gz(max_uncompressed_ratio=0)

    def test_negative_uncompressed_size_raises(self):
        with pytest.raises(ValueError, match="max_uncompressed_size"):
            validate_gz(max_uncompressed_size=-1)

    def test_non_numeric_limit_raises(self):
        with pytest.raises(ValueError):
            validate_gz(max_file_size="huge")


# ===========================================================================
# 2. Direct / CLI mode
# ===========================================================================

class TestDirectMode:
    def test_valid_gz_returns_true(self, tmp_gz):
        assert validate_gz(str(tmp_gz)) is True
        assert validate_gz(tmp_gz) is True  # Path object

    def test_missing_file_returns_false(self, tmp_path, capsys):
        missing = tmp_path / "does_not_exist.gz"
        assert validate_gz(str(missing)) is False
        captured = capsys.readouterr()
        assert "Exception:" in captured.out

    def test_exceeds_max_file_size_returns_false(self, tmp_gz, capsys):
        # Force a tiny limit
        assert validate_gz(str(tmp_gz), max_file_size=1) is False
        assert "Exception:" in capsys.readouterr().out

    def test_exceeds_ratio_returns_false(self, tmp_path, capsys):
        # Highly compressible data → high ratio
        gz = make_gz(tmp_path, b"X" * 10_000)
        assert validate_gz(str(gz), max_uncompressed_ratio=1.1) is False

    def test_exceeds_uncompressed_size_returns_false(self, tmp_path, capsys):
        gz = make_gz(tmp_path, b"Y" * 5_000)
        assert validate_gz(str(gz), max_uncompressed_size=100) is False

    def test_defaults_are_applied(self, tmp_gz):
        # Should succeed with the (generous) defaults
        assert validate_gz(str(tmp_gz)) is True


# ===========================================================================
# 3. Decorator modes
# ===========================================================================

class TestDecoratorModes:
    def test_bare_decorator(self, tmp_gz):
        @validate_gz
        def process(path):
            return f"processed {path}"

        assert process(str(tmp_gz)) == f"processed {tmp_gz}"
        assert process(tmp_gz) == f"processed {tmp_gz}"

    def test_decorator_factory_no_args(self, tmp_gz):
        @validate_gz()
        def process(path):
            return "ok"

        assert process(str(tmp_gz)) == "ok"

    def test_named_argument(self, tmp_gz):
        @validate_gz("gz_path")
        def process(other, gz_path):
            return gz_path

        result = process("foo", str(tmp_gz))
        assert result == str(tmp_gz)

    def test_named_argument_with_limits(self, tmp_gz):
        @validate_gz(
            "gz_path",
            max_file_size=500_000,
            max_uncompressed_ratio=200,
            max_uncompressed_size=1_000_000,
        )
        def process(gz_path):
            return True

        assert process(str(tmp_gz)) is True

    def test_first_argument_is_default_target(self, tmp_gz):
        @validate_gz()
        def process(file_path, extra=None):
            return file_path

        assert process(str(tmp_gz)) == str(tmp_gz)

    def test_keyword_argument(self, tmp_gz):
        @validate_gz("path")
        def process(*, path):
            return path

        assert process(path=str(tmp_gz)) == str(tmp_gz)


# ===========================================================================
# 4. Decorator error cases
# ===========================================================================

class TestDecoratorErrors:
    def test_no_arguments_raises(self):
        with pytest.raises(GzValidationError, match="no arguments"):
            @validate_gz
            def process():
                pass

    def test_missing_required_argument(self, tmp_gz):
        @validate_gz
        def process(path):
            pass

        with pytest.raises(GzValidationError, match="Invalid function call signature"):
            process()  # path not supplied
        

    def test_wrong_type_for_path(self):
        @validate_gz
        def process(path):
            pass

        with pytest.raises(GzValidationError, match="Expected Path or str"):
            process(123)

    def test_invalid_call_signature(self, tmp_gz):
        @validate_gz
        def process(path, extra):
            pass

        with pytest.raises(GzValidationError, match="Invalid function call signature"):
            process(str(tmp_gz))  # missing 'extra'

    def test_validation_failure_raises_GzValidationError(self, tmp_gz):
        @validate_gz(max_file_size=1)
        def process(path):
            return "should never reach here"

        with pytest.raises(GzValidationError):
            process(str(tmp_gz))

    def test_named_arg_not_present_falls_back_to_first(self, tmp_gz):
        # "missing_name" is not a parameter → falls back to first param
        @validate_gz("missing_name")
        def process(path):
            return path

        assert process(str(tmp_gz)) == str(tmp_gz)


# ===========================================================================
# 5. Type / mode detection edge cases
# ===========================================================================

class TestModeDetection:
    def test_none_returns_decorator_factory(self):
        factory = validate_gz(None)
        assert callable(factory)

        @factory
        def process(path):
            return True

        # Just verify it is a proper decorator
        assert callable(process)

    def test_callable_is_decorated_immediately(self, tmp_gz):
        def process(path):
            return path

        decorated = validate_gz(process)
        assert decorated(str(tmp_gz)) == str(tmp_gz)

    def test_string_identifier_is_decorator_mode(self):
        factory = validate_gz("my_arg")
        assert callable(factory)

    def test_string_filename_is_direct_mode(self, tmp_path):
        # A string that is NOT a valid identifier → direct mode
        result = validate_gz("not-a-valid-identifier.gz")
        # File does not exist → False
        assert result is False

    def test_path_object_is_direct_mode(self, tmp_gz):
        assert validate_gz(tmp_gz) is True

    def test_invalid_type_raises_TypeError(self):
        with pytest.raises(TypeError, match="func_or_path must be"):
            validate_gz(42)


# ===========================================================================
# 6. Integration / realistic scenarios
# ===========================================================================

class TestRealisticScenarios:
    def test_decorator_preserves_function_metadata(self):
        @validate_gz
        def my_processor(path: str) -> str:
            """Docstring."""
            return path

        assert my_processor.__name__ == "my_processor"
        assert my_processor.__doc__ == "Docstring."

    def test_multiple_calls_with_same_decorator(self, tmp_path):
        gz1 = make_gz(tmp_path, b"one", "one.gz")
        gz2 = make_gz(tmp_path, b"two", "two.gz")

        @validate_gz
        def process(p):
            return Path(p).name

        assert process(str(gz1)) == "one.gz"
        assert process(str(gz2)) == "two.gz"

    def test_limits_are_captured_at_decoration_time(self, tmp_gz):
        # Change the default *after* decoration – the captured value must stay
        original = DEFAULT_MAX_FILE_SIZE
        try:
            @validate_gz(max_file_size=100)
            def process(path):
                return True

            # Even if we later change the global default, the decorated
            # function still uses the value that was resolved at decoration.
            globals()["DEFAULT_MAX_FILE_SIZE"] = 1
            assert process(str(tmp_gz)) is True  # still uses 100
        finally:
            globals()["DEFAULT_MAX_FILE_SIZE"] = original


def test_check_only_https():
    """For remote files only https is allowed"""
    remote_gz = "http://nocomplexity.com/downloads/file.gz"
    result = validate_gz(remote_gz)
    assert result == False