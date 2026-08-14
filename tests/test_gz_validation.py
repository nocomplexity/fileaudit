# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Additional Tests for the @validate_gz decorator 

Comprehensive pytest suite for validate_gz 

Covers:
  - Mode resolution (decorator vs direct call)
  - Limit resolution and validation
  - Bare decorator usage: @validate_gz
  - Factory usage: @validate_gz()
  - Named-argument decorator: @validate_gz("custom_arg_name")
  - Direct call mode: validate_gz("path/to/file.gz")
  - Direct call with Path object
  - Error propagation and exception handling
  - Argument binding edge cases
  - File-path heuristic detection
"""


import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_defaults():
    """Ensure DEFAULT_* constants are patched for every test."""
    with patch("fileaudit.gz_check.DEFAULT_MAX_FILE_SIZE", 10_000_000), \
         patch("fileaudit.gz_check.DEFAULT_MAX_UNCOMPRESSED_RATIO", 100), \
         patch("fileaudit.gz_check.DEFAULT_MAX_UNCOMPRESSED_SIZE", 100_000_000):
        yield


@pytest.fixture
def mock_validate_limit():
    with patch("fileaudit.gz_check._validate_limit") as m:
        yield m


@pytest.fixture
def mock_validate_gz_file():
    with patch("fileaudit.gz_check._validate_gz_file") as m:
        yield m


@pytest.fixture
def gz_validation_error():
    """Return a fresh GzValidationError class for use in tests."""
    from fileaudit.gz_check import GzValidationError
    return GzValidationError


# ---------------------------------------------------------------------------
# 1. Mode resolution & type-checking
# ---------------------------------------------------------------------------

class TestModeResolution:
    """Tests for the logic that decides decorator vs direct-call mode."""

    def test_none_returns_decorator_factory(self, mock_validate_limit, mock_validate_gz_file):
        """validate_gz(None) -> returns a decorator factory."""
        from fileaudit.gz_check import validate_gz
        result = validate_gz(None)
        assert callable(result)
        # result itself is not the wrapped function yet
        def dummy(path):  # Must have at least one argument
            pass
        wrapped = result(dummy)
        assert callable(wrapped)

    def test_callable_returns_decorator(self, mock_validate_limit, mock_validate_gz_file):
        """Bare decorator: validate_gz(func) -> wrapped function immediately."""
        from fileaudit.gz_check import validate_gz
        def dummy(path):
            pass
        wrapped = validate_gz(dummy)
        assert callable(wrapped)
        assert wrapped is not dummy

    def test_pathlike_direct_mode(self, mock_validate_limit, mock_validate_gz_file):
        """Passing a Path object forces direct-call mode."""
        from fileaudit.gz_check import validate_gz
        mock_validate_gz_file.return_value = None
        result = validate_gz(Path("/tmp/test.gz"))
        assert result is True
        mock_validate_gz_file.assert_called_once()

    def test_string_that_looks_like_path_direct_mode(self, mock_validate_limit, mock_validate_gz_file):
        """Strings that look like file paths trigger direct-call mode."""
        from fileaudit.gz_check import validate_gz
        mock_validate_gz_file.return_value = None
        assert validate_gz("/tmp/test.gz") is True
        assert validate_gz("http://example.com/file.gz") is True
        assert validate_gz("rel/path/file.gz") is True
        assert validate_gz("file.name.gz") is True
        assert mock_validate_gz_file.call_count == 4

    def test_string_identifier_decorator_mode(self, mock_validate_limit, mock_validate_gz_file):
        """Strings that are valid Python identifiers (and not paths) -> decorator mode."""
        from fileaudit.gz_check import validate_gz
        def dummy(path):
            pass
        wrapped = validate_gz("my_arg")(dummy)
        assert callable(wrapped)

    def test_invalid_type_raises_typeerror(self, mock_validate_limit, mock_validate_gz_file):
        """Passing an unsupported type (e.g. int) raises TypeError."""
        from fileaudit.gz_check import validate_gz
        with pytest.raises(TypeError):
            validate_gz(12345)

    def test_dotfile_string_is_path_not_identifier(self, mock_validate_limit, mock_validate_gz_file):
        """.hidden.gz starts with '.' so it's not a valid Python identifier,
        so it should be treated as direct mode."""
        from fileaudit.gz_check import validate_gz
        mock_validate_gz_file.return_value = None
        # ".hidden.gz" is not a valid identifier, so it should be treated as a path
        result = validate_gz(".hidden.gz")
        assert result is True
        mock_validate_gz_file.assert_called_once()


# ---------------------------------------------------------------------------
# 2. Limit resolution
# ---------------------------------------------------------------------------

class TestLimitResolution:
    """Tests that limits are resolved to defaults or overridden correctly."""

    def test_defaults_used_when_none(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz
        validate_gz("/tmp/f.gz")
        # _validate_limit should be called 3 times with default values
        assert mock_validate_limit.call_count == 3
        mock_validate_limit.assert_any_call("max_file_size", 10_000_000)
        mock_validate_limit.assert_any_call("max_uncompressed_ratio", 100)
        mock_validate_limit.assert_any_call("max_uncompressed_size", 100_000_000)

    def test_custom_limits_override_defaults(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz
        validate_gz(
            "/tmp/f.gz",
            max_file_size=5000,
            max_uncompressed_ratio=50,
            max_uncompressed_size=1_000_000
        )
        mock_validate_limit.assert_any_call("max_file_size", 5000)
        mock_validate_limit.assert_any_call("max_uncompressed_ratio", 50)
        mock_validate_limit.assert_any_call("max_uncompressed_size", 1_000_000)

    def test_zero_limits_are_valid(self, mock_validate_gz_file):
        """Zero is NOT a valid limit - should raise ValueError."""
        from fileaudit.gz_check import validate_gz
        # validator raises ValueError for max_file_size=0.
        with pytest.raises(ValueError):
            validate_gz("/tmp/f.gz", max_file_size=0)
            


# ---------------------------------------------------------------------------
# 3. Direct call / CLI mode
# ---------------------------------------------------------------------------

class TestDirectCallMode:
    """Tests for validate_gz(path) usage."""

    def test_direct_call_returns_true_on_success(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz
        mock_validate_gz_file.return_value = None  # success
        assert validate_gz("/tmp/ok.gz") is True

    def test_direct_call_returns_false_on_gzvalidationerror(
        self, mock_validate_limit, mock_validate_gz_file, gz_validation_error
    ):
        from fileaudit.gz_check import validate_gz
        mock_validate_gz_file.side_effect = gz_validation_error("boom")
        assert validate_gz("/tmp/bad.gz") is False

    def test_direct_call_propagates_other_exceptions(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        """Non-GzValidationError exceptions must NOT be swallowed."""
        from fileaudit.gz_check import validate_gz
        mock_validate_gz_file.side_effect = RuntimeError("unexpected")
        with pytest.raises(RuntimeError, match="unexpected"):
            validate_gz("/tmp/bad.gz")

    def test_direct_call_with_path_object(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz
        p = Path("/tmp/ok.gz")
        assert validate_gz(p) is True
        mock_validate_gz_file.assert_called_once_with(
            p, 10_000_000, 100, 100_000_000
        )

    def test_direct_call_with_all_custom_limits(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz
        validate_gz(
            "/tmp/f.gz",
            max_file_size=1024,
            max_uncompressed_ratio=10,
            max_uncompressed_size=2048
        )
        mock_validate_gz_file.assert_called_once_with(
            "/tmp/f.gz", 1024, 10, 2048
        )


# ---------------------------------------------------------------------------
# 4. Decorator mode -- argument resolution
# ---------------------------------------------------------------------------

class TestDecoratorArgumentResolution:
    """Tests for how the decorator discovers the target argument."""

    def test_bare_decorator_uses_first_positional_arg(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        from fileaudit.gz_check import validate_gz

        @validate_gz
        def process(path):
            return "done"

        assert process("/tmp/f.gz") == "done"
        mock_validate_gz_file.assert_called_once()

    def test_factory_decorator_uses_first_positional_arg(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        from fileaudit.gz_check import validate_gz

        @validate_gz()
        def process(path):
            return "done"

        assert process("/tmp/f.gz") == "done"
        mock_validate_gz_file.assert_called_once()

    def test_named_decorator_uses_specified_arg(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        from fileaudit.gz_check import validate_gz

        @validate_gz("custom_path")
        def process(custom_path, other):
            return "done"

        assert process("/tmp/f.gz", 42) == "done"
        mock_validate_gz_file.assert_called_once()

    def test_named_decorator_ignores_first_positional(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        from fileaudit.gz_check import validate_gz

        @validate_gz("second")
        def process(first, second):
            return f"{first}-{second}"

        assert process("ignore.gz", "/tmp/validate.gz") == "ignore.gz-/tmp/validate.gz"
        args, _ = mock_validate_gz_file.call_args
        assert args[0] == "/tmp/validate.gz"

    def test_no_positional_args_raises(self, mock_validate_limit, mock_validate_gz_file, gz_validation_error):
        from fileaudit.gz_check import validate_gz

        def process(**kwargs):
            return kwargs

        with pytest.raises(gz_validation_error):
            validate_gz()(process)

    def test_no_args_at_all_raises(self, mock_validate_limit, mock_validate_gz_file, gz_validation_error):
        from fileaudit.gz_check import validate_gz

        def process():
            return "done"

        with pytest.raises(gz_validation_error):
            validate_gz()(process)

    def test_var_positional_arg_raises(self, mock_validate_limit, mock_validate_gz_file, gz_validation_error):
        from fileaudit.gz_check import validate_gz

        def process(*paths):
            return paths

        with pytest.raises(gz_validation_error):
            validate_gz()(process)

    def test_var_keyword_arg_raises(self, mock_validate_limit, mock_validate_gz_file, gz_validation_error):
        from fileaudit.gz_check import validate_gz

        def process(**kwargs):
            return kwargs

        # Even if we name it, VAR_KEYWORD is invalid
        with pytest.raises(gz_validation_error):
            validate_gz("kwargs")(process)


    def test_uninspectable_function_raises(self, mock_validate_limit, mock_validate_gz_file, gz_validation_error):
        from fileaudit.gz_check import validate_gz
        import inspect

        class BadCallable:
            __name__ = "BadCallable"
            # Make it callable so validate_gz enters decorator mode
            def __call__(self):
                pass
            # Force inspect.signature to fail
            __signature__ = "not a signature object"

        bad = BadCallable()
        with pytest.raises(gz_validation_error):
            validate_gz(bad)
        
# ---------------------------------------------------------------------------
# 5. Decorator mode -- wrapper execution
# ---------------------------------------------------------------------------

class TestDecoratorWrapperExecution:
    """Tests for the runtime behaviour of the decorator wrapper."""

    def test_wrapper_calls_original_function(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz

        @validate_gz
        def process(path):
            return f"processed {path}"

        result = process("/tmp/f.gz")
        assert result == "processed /tmp/f.gz"

    def test_wrapper_passes_all_args_to_original(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz

        @validate_gz
        def process(path, mode, extra=None):
            return (path, mode, extra)

        assert process("/tmp/f.gz", "r", extra="x") == ("/tmp/f.gz", "r", "x")

    def test_wrapper_passes_kwargs(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz

        @validate_gz
        def process(path, mode="r"):
            return (path, mode)

        assert process("/tmp/f.gz", mode="w") == ("/tmp/f.gz", "w")

    def test_wrapper_validates_before_calling_original(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz

        call_order = []

        def side_effect(*args, **kwargs):
            call_order.append("validate")

        mock_validate_gz_file.side_effect = side_effect

        @validate_gz
        def process(path):
            call_order.append("original")
            return "done"

        process("/tmp/f.gz")
        assert call_order == ["validate", "original"]

    def test_missing_target_arg_raises(self, mock_validate_limit, mock_validate_gz_file, gz_validation_error):
        from fileaudit.gz_check import validate_gz

        @validate_gz("path")
        def process(path=None):
            return path

        with pytest.raises(gz_validation_error):
            process()

    def test_wrong_type_for_path_raises(self, mock_validate_limit, mock_validate_gz_file, gz_validation_error):
        from fileaudit.gz_check import validate_gz

        @validate_gz
        def process(path):
            return path

        with pytest.raises(gz_validation_error):
            process(12345)

    def test_pathlike_object_accepted(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz

        @validate_gz
        def process(path):
            return str(path)  # Convert to string for comparison

        class MyPath(os.PathLike):
            def __fspath__(self):
                return "/tmp/my.gz"
            def __str__(self):
                return "/tmp/my.gz"

        result = process(MyPath())
        assert result == "/tmp/my.gz"

    def test_invalid_call_signature_raises(self, mock_validate_limit, mock_validate_gz_file, gz_validation_error):
        from fileaudit.gz_check import validate_gz

        @validate_gz
        def process(path, required):
            return (path, required)

        with pytest.raises(gz_validation_error):
            process("/tmp/f.gz")  # missing 'required'


# ---------------------------------------------------------------------------
# 6. Decorator mode -- exception handling inside wrapper
# ---------------------------------------------------------------------------

class TestDecoratorExceptionHandling:
    """Tests that GzValidationError is raised (not returned) in decorator mode."""

    def test_validation_failure_raises_in_decorator_mode(
        self, mock_validate_limit, mock_validate_gz_file, gz_validation_error
    ):
        from fileaudit.gz_check import validate_gz

        mock_validate_gz_file.side_effect = gz_validation_error("corrupt gzip")

        @validate_gz
        def process(path):
            return "done"

        with pytest.raises(gz_validation_error):
            process("/tmp/bad.gz")

    def test_non_gzvalidation_error_propagates(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        from fileaudit.gz_check import validate_gz

        mock_validate_gz_file.side_effect = MemoryError("oom")

        @validate_gz
        def process(path):
            return "done"

        with pytest.raises(MemoryError):
            process("/tmp/bad.gz")


# ---------------------------------------------------------------------------
# 7. Edge cases for file-path heuristic
# ---------------------------------------------------------------------------

class TestFilePathHeuristic:
    """Tests for _looks_like_file_path behaviour."""

    def test_url_prefixes_look_like_path(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz
        mock_validate_gz_file.return_value = None
        for prefix in ("http://", "https://", "ftp://", "file://"):
            assert validate_gz(prefix + "x.gz") is True

    def test_absolute_paths_look_like_path(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz
        mock_validate_gz_file.return_value = None
        assert validate_gz("/unix/path.gz") is True
        assert validate_gz("\\windows\\path.gz") is True

    def test_relative_paths_look_like_path(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz
        mock_validate_gz_file.return_value = None
        assert validate_gz("dir/file.gz") is True
        assert validate_gz("dir\\file.gz") is True

    def test_dotted_name_looks_like_path(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz
        mock_validate_gz_file.return_value = None
        assert validate_gz("archive.tar.gz") is True

    def test_plain_identifier_not_path(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz
        # Should enter decorator mode, not direct-call mode
        def dummy(path):
            pass
        wrapped = validate_gz("myfile")(dummy)
        assert callable(wrapped)

    def test_single_word_no_dot_not_path(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz
        def dummy(path):
            pass
        wrapped = validate_gz("filename")(dummy)
        assert callable(wrapped)


# ---------------------------------------------------------------------------
# 8. Integration-style tests (with real _validate_gz_file mocked)
# ---------------------------------------------------------------------------

class TestIntegrationScenarios:
    """Higher-level scenarios combining multiple features."""

    def test_decorator_with_custom_limits_applies_them(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        from fileaudit.gz_check import validate_gz

        @validate_gz(max_file_size=1024, max_uncompressed_ratio=5, max_uncompressed_size=2048)
        def process(path):
            return path

        process("/tmp/f.gz")
        mock_validate_gz_file.assert_called_once_with(
            "/tmp/f.gz", 1024, 5, 2048
        )

    def test_decorator_named_arg_with_custom_limits(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        from fileaudit.gz_check import validate_gz

        @validate_gz("archive", max_file_size=512)
        def process(archive, output_dir):
            return (archive, output_dir)

        process("/tmp/f.gz", "/out")
        mock_validate_gz_file.assert_called_once_with(
            "/tmp/f.gz", 512, 100, 100_000_000
        )

    def test_chained_decorators_work(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz

        def another_decorator(f):
            def wrapper(*args, **kwargs):
                return f(*args, **kwargs)
            return wrapper

        @another_decorator
        @validate_gz
        def process(path):
            return path

        assert process("/tmp/f.gz") == "/tmp/f.gz"
        mock_validate_gz_file.assert_called_once()

    def test_function_with_only_keyword_args_falls_back_to_first_positional_or_raises(
        self, mock_validate_limit, mock_validate_gz_file, gz_validation_error
    ):
        from fileaudit.gz_check import validate_gz

        def process(*, path):
            return path

        # No positional params -> raises at decoration time
        with pytest.raises(gz_validation_error):
            validate_gz()(process)

    def test_keyword_only_with_named_arg_works(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        from fileaudit.gz_check import validate_gz

        @validate_gz("path")
        def process(*, path):
            return path

        assert process(path="/tmp/f.gz") == "/tmp/f.gz"
        mock_validate_gz_file.assert_called_once()

    def test_positional_only_arg_works(self, mock_validate_limit, mock_validate_gz_file):
        from fileaudit.gz_check import validate_gz

        # Python 3.8+ syntax
        exec_globals = {}
        exec("""
def process(path, /):
    return path
""", exec_globals)
        process = exec_globals["process"]

        wrapped = validate_gz()(process)
        assert wrapped("/tmp/f.gz") == "/tmp/f.gz"
        mock_validate_gz_file.assert_called_once()


# ---------------------------------------------------------------------------
# 9. Regression / safety tests
# ---------------------------------------------------------------------------

class TestSafetyRegressions:
    """Tests ensuring security-critical behaviour is not accidentally broken."""

    def test_direct_mode_does_not_swallow_runtime_error(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        """Critical: programming errors must bubble up in direct mode."""
        from fileaudit.gz_check import validate_gz
        mock_validate_gz_file.side_effect = RuntimeError("bug")
        with pytest.raises(RuntimeError):
            validate_gz("/tmp/f.gz")

    def test_decorator_mode_does_not_swallow_runtime_error(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        from fileaudit.gz_check import validate_gz

        mock_validate_gz_file.side_effect = RuntimeError("bug")

        @validate_gz
        def process(path):
            return path

        with pytest.raises(RuntimeError):
            process("/tmp/f.gz")

    def test_validate_limit_called_before_any_validation(
        self, mock_validate_limit, mock_validate_gz_file
    ):
        """Limits must be validated before _validate_gz_file is ever called."""
        from fileaudit.gz_check import validate_gz

        call_order = []
        mock_validate_limit.side_effect = lambda *a, **k: call_order.append("limit")
        mock_validate_gz_file.side_effect = lambda *a, **k: call_order.append("file")

        validate_gz("/tmp/f.gz")
        assert call_order == ["limit", "limit", "limit", "file"]

    def test_wrapper_preserves_function_metadata(self, mock_validate_limit, mock_validate_gz_file):
        """@wraps should preserve __name__, __doc__, etc."""
        from fileaudit.gz_check import validate_gz

        @validate_gz
        def process(path):
            """My docstring."""
            return path

        assert process.__name__ == "process"
        assert process.__doc__ == "My docstring."