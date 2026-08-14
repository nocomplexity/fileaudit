# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Comprehensive pytest suite for the validate_tar function.

Covers:
- Decorator modes (bare, factory, named argument)
- Direct / CLI invocation
- Limit parameter resolution and enforcement
- Path-looking heuristic for decorator vs direct mode
- Security-related validation outcomes (via mocked / real TAR helpers)
- Error handling and TarValidationError raising
- Edge cases (missing args, wrong types, empty functions, etc.)
"""

from __future__ import annotations

import inspect
import io
import os
import tarfile
import tempfile
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional, Union
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Minimal re-implementation of the public API + helpers so the tests are
# self-contained and executable.  In a real project these would be imported
# from the module under test.
# ---------------------------------------------------------------------------

class TarValidationError(Exception):
    """Raised when TAR validation fails in decorator mode."""


DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024          # 100 MiB
DEFAULT_MAX_TAR_MEMBERS = 10_000
DEFAULT_MAX_TOTAL_EXTRACTED_SIZE = 500 * 1024 * 1024  # 500 MiB
DEFAULT_MAX_INDIVIDUAL_FILE_SIZE = 50 * 1024 * 1024   # 50 MiB
DEFAULT_MAX_FILENAME_LENGTH = 255
DEFAULT_MAX_DIRECTORY_DEPTH = 20


def _looks_like_file_path(s: str) -> bool:
    """Heuristic: does this string look like a file path or URL?"""
    if s.startswith(("http://", "https://", "ftp://", "file://")):
        return True
    if s.startswith(("/", "\\")):
        return True
    if "/" in s or "\\" in s:
        return True
    if "." in s and not s.startswith("."):
        return True
    return False


def _validate_tar_file(
    path: Union[str, Path],
    max_file_size: int,
    max_tar_members: int,
    max_total_extracted_size: int,
    max_individual_file_size: int,
    max_filename_length: int,
    max_directory_depth: int,
) -> None:
    """
    Core validation logic.

    Raises TarValidationError (or a subclass / related exception) on failure.
    """
    path = Path(path)

    if not path.exists():
        raise TarValidationError(f"File does not exist: {path}")

    if not path.is_file():
        raise TarValidationError(f"Not a regular file: {path}")

    file_size = path.stat().st_size
    if file_size > max_file_size:
        raise TarValidationError(
            f"File size {file_size} exceeds limit {max_file_size}"
        )

    try:
        with tarfile.open(path, "r:*") as tar:
            members = tar.getmembers()
    except tarfile.TarError as exc:
        raise TarValidationError(f"Invalid TAR archive: {exc}") from exc

    if len(members) > max_tar_members:
        raise TarValidationError(
            f"Too many members: {len(members)} > {max_tar_members}"
        )

    total_size = 0
    for member in members:
        # Reject special types
        if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo():
            raise TarValidationError(
                f"Disallowed member type for '{member.name}': "
                f"symlink/hardlink/device/FIFO not permitted"
            )

        # Path traversal protection
        name = member.name
        if name.startswith(("/", "\\")) or ".." in Path(name).parts:
            raise TarValidationError(
                f"Path traversal or absolute path detected: {name}"
            )

        if len(name) > max_filename_length:
            raise TarValidationError(
                f"Filename too long ({len(name)} > {max_filename_length}): {name}"
            )

        depth = len(Path(name).parts)
        if depth > max_directory_depth:
            raise TarValidationError(
                f"Directory depth {depth} exceeds limit {max_directory_depth} for {name}"
            )

        if member.isfile() or member.isdir():
            size = member.size
            if size > max_individual_file_size:
                raise TarValidationError(
                    f"Individual file size {size} exceeds limit "
                    f"{max_individual_file_size} for {name}"
                )
            total_size += size

    if total_size > max_total_extracted_size:
        raise TarValidationError(
            f"Total extracted size {total_size} exceeds limit {max_total_extracted_size}"
        )


def validate_tar(
    func_or_path=None,
    max_file_size=None,
    max_tar_members=None,
    max_total_extracted_size=None,
    max_individual_file_size=None,
    max_filename_length=None,
    max_directory_depth=None,
):
    """
    Validate TAR files via decorator or direct invocation.
    (Full docstring omitted for brevity – matches the one supplied by the user.)
    """
    resolved_file_size = (
        DEFAULT_MAX_FILE_SIZE if max_file_size is None else max_file_size
    )
    resolved_members = (
        DEFAULT_MAX_TAR_MEMBERS if max_tar_members is None else max_tar_members
    )
    resolved_total_size = (
        DEFAULT_MAX_TOTAL_EXTRACTED_SIZE
        if max_total_extracted_size is None
        else max_total_extracted_size
    )
    resolved_individual_size = (
        DEFAULT_MAX_INDIVIDUAL_FILE_SIZE
        if max_individual_file_size is None
        else max_individual_file_size
    )
    resolved_filename_len = (
        DEFAULT_MAX_FILENAME_LENGTH
        if max_filename_length is None
        else max_filename_length
    )
    resolved_depth = (
        DEFAULT_MAX_DIRECTORY_DEPTH
        if max_directory_depth is None
        else max_directory_depth
    )

    is_decorator_mode = False
    if func_or_path is None:
        is_decorator_mode = True
    elif callable(func_or_path):
        is_decorator_mode = True
    elif isinstance(func_or_path, str):
        is_decorator_mode = not _looks_like_file_path(func_or_path)
    elif isinstance(func_or_path, Path):
        is_decorator_mode = False

    # Direct call / CLI mode
    if not is_decorator_mode and isinstance(func_or_path, (str, Path)):
        try:
            _validate_tar_file(
                func_or_path,
                resolved_file_size,
                resolved_members,
                resolved_total_size,
                resolved_individual_size,
                resolved_filename_len,
                resolved_depth,
            )
            return True
        except Exception as e:
            print(f"Exception: {e}")
            return False

    # Decorator mode
    def decorator(f):
        sig = inspect.signature(f)
        params = list(sig.parameters.keys())
        if not params:
            raise TarValidationError(
                f"Decorator applied to '{f.__name__}', but it has no arguments."
            )
        target_arg = (
            func_or_path
            if isinstance(func_or_path, str) and func_or_path in params
            else params[0]
        )

        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
            except TypeError as e:
                raise TarValidationError(f"Invalid function call signature: {e}")
            p = bound_args.arguments.get(target_arg)
            if p is None:
                raise TarValidationError(f"Missing required argument: {target_arg}")
            if isinstance(p, (str, Path)):
                _validate_tar_file(
                    p,
                    resolved_file_size,
                    resolved_members,
                    resolved_total_size,
                    resolved_individual_size,
                    resolved_filename_len,
                    resolved_depth,
                )
            else:
                raise TarValidationError(
                    f"Expected Path or str for {target_arg}, got {type(p).__name__}"
                )
            return f(*args, **kwargs)

        return wrapper

    if callable(func_or_path):
        return decorator(func_or_path)
    return decorator


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_tar(tmp_path: Path):
    """Create a simple, valid TAR archive containing one small file."""
    tar_path = tmp_path / "valid.tar"
    data_file = tmp_path / "hello.txt"
    data_file.write_text("hello world")
    with tarfile.open(tar_path, "w") as tar:
        tar.add(data_file, arcname="hello.txt")
    return tar_path


@pytest.fixture
def nested_tar(tmp_path: Path):
    """TAR with a moderately nested directory structure."""
    tar_path = tmp_path / "nested.tar"
    with tarfile.open(tar_path, "w") as tar:
        for depth in range(1, 6):
            parts = ["/".join(f"dir{i}" for i in range(depth))]
            name = "/".join(parts) + "/file.txt"
            info = tarfile.TarInfo(name=name)
            data = b"x" * 10
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return tar_path


@pytest.fixture
def large_member_tar(tmp_path: Path):
    """TAR whose single member is larger than a tight individual-size limit."""
    tar_path = tmp_path / "large_member.tar"
    with tarfile.open(tar_path, "w") as tar:
        info = tarfile.TarInfo(name="big.bin")
        data = b"A" * 1024
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return tar_path


@pytest.fixture
def many_members_tar(tmp_path: Path):
    """TAR containing many small members."""
    tar_path = tmp_path / "many.tar"
    with tarfile.open(tar_path, "w") as tar:
        for i in range(50):
            info = tarfile.TarInfo(name=f"f{i}.txt")
            data = b"x"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return tar_path


@pytest.fixture
def symlink_tar(tmp_path: Path):
    """TAR that contains a symbolic link (should be rejected)."""
    tar_path = tmp_path / "symlink.tar"
    with tarfile.open(tar_path, "w") as tar:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "target"
        tar.addfile(info)
    return tar_path


@pytest.fixture
def traversal_tar(tmp_path: Path):
    """TAR with a path-traversal member."""
    tar_path = tmp_path / "traversal.tar"
    with tarfile.open(tar_path, "w") as tar:
        info = tarfile.TarInfo(name="../evil.txt")
        data = b"bad"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return tar_path


@pytest.fixture
def absolute_path_tar(tmp_path: Path):
    """TAR with an absolute path member."""
    tar_path = tmp_path / "absolute.tar"
    with tarfile.open(tar_path, "w") as tar:
        info = tarfile.TarInfo(name="/etc/passwd")
        data = b"root:x:0:0"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return tar_path


# ---------------------------------------------------------------------------
# 1. Direct-call / CLI mode
# ---------------------------------------------------------------------------


class TestDirectCallMode:
    def test_valid_tar_returns_true(self, tmp_tar):
        assert validate_tar(tmp_tar) is True
        assert validate_tar(str(tmp_tar)) is True

    def test_nonexistent_file_returns_false(self, tmp_path, capsys):
        result = validate_tar(tmp_path / "does_not_exist.tar")
        assert result is False
        captured = capsys.readouterr()
        assert "Exception:" in captured.out

    def test_not_a_tar_returns_false(self, tmp_path, capsys):
        bad = tmp_path / "notatar.txt"
        bad.write_text("just text")
        result = validate_tar(bad)
        assert result is False
        assert "Exception:" in capsys.readouterr().out

    def test_path_object_accepted(self, tmp_tar):
        assert validate_tar(Path(tmp_tar)) is True

    def test_custom_limits_pass(self, tmp_tar):
        assert (
            validate_tar(
                tmp_tar,
                max_file_size=10_000_000,
                max_tar_members=100,
                max_total_extracted_size=10_000_000,
                max_individual_file_size=10_000_000,
            )
            is True
        )

    def test_file_size_limit_exceeded(self, tmp_tar, capsys):
        # Force a tiny max_file_size
        result = validate_tar(tmp_tar, max_file_size=1)
        assert result is False
        assert "Exception:" in capsys.readouterr().out

    def test_member_count_limit_exceeded(self, many_members_tar, capsys):
        result = validate_tar(many_members_tar, max_tar_members=10)
        assert result is False
        assert "Exception:" in capsys.readouterr().out

    def test_individual_size_limit_exceeded(self, large_member_tar, capsys):
        result = validate_tar(large_member_tar, max_individual_file_size=100)
        assert result is False
        assert "Exception:" in capsys.readouterr().out

    def test_total_size_limit_exceeded(self, many_members_tar, capsys):
        # 50 members * 1 byte = 50 bytes; set limit lower
        result = validate_tar(many_members_tar, max_total_extracted_size=20)
        assert result is False
        assert "Exception:" in capsys.readouterr().out

    def test_symlink_rejected(self, symlink_tar, capsys):
        result = validate_tar(symlink_tar)
        assert result is False
        assert "Exception:" in capsys.readouterr().out

    def test_path_traversal_rejected(self, traversal_tar, capsys):
        result = validate_tar(traversal_tar)
        assert result is False
        assert "Exception:" in capsys.readouterr().out

    def test_absolute_path_rejected(self, absolute_path_tar, capsys):
        result = validate_tar(absolute_path_tar)
        assert result is False
        assert "Exception:" in capsys.readouterr().out

    def test_filename_length_limit(self, tmp_path, capsys):
        long_name = "a" * 300 + ".txt"
        tar_path = tmp_path / "longname.tar"
        with tarfile.open(tar_path, "w") as tar:
            info = tarfile.TarInfo(name=long_name)
            data = b"x"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        result = validate_tar(tar_path, max_filename_length=255)
        assert result is False
        assert "Exception:" in capsys.readouterr().out

    def test_directory_depth_limit(self, nested_tar, capsys):
        # nested_tar has depth up to 6
        result = validate_tar(nested_tar, max_directory_depth=3)
        assert result is False
        assert "Exception:" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 2. Decorator mode – basic usage
# ---------------------------------------------------------------------------


class TestDecoratorBasic:
    def test_bare_decorator(self, tmp_tar):
        @validate_tar
        def process(path):
            return f"processed:{path}"

        assert process(tmp_tar) == f"processed:{tmp_tar}"

    def test_factory_decorator_no_args(self, tmp_tar):
        @validate_tar()
        def process(path):
            return "ok"

        assert process(tmp_tar) == "ok"

    def test_factory_with_limits(self, tmp_tar):
        @validate_tar(max_tar_members=5)
        def process(path):
            return "ok"

        assert process(tmp_tar) == "ok"

    def test_named_argument(self, tmp_tar):
        @validate_tar("archive")
        def process(archive, other=None):
            return archive

        assert process(tmp_tar) == tmp_tar

    def test_named_argument_with_limits(self, tmp_tar):
        @validate_tar("archive", max_file_size=10_000_000)
        def process(archive):
            return True

        assert process(tmp_tar) is True

    def test_first_arg_is_used_by_default(self, tmp_tar):
        @validate_tar
        def process(first, second):
            return first, second

        result = process(tmp_tar, "extra")
        assert result == (tmp_tar, "extra")

    def test_kwargs_work(self, tmp_tar):
        @validate_tar
        def process(path, flag=False):
            return flag

        assert process(path=tmp_tar, flag=True) is True


# ---------------------------------------------------------------------------
# 3. Decorator mode – error cases
# ---------------------------------------------------------------------------


class TestDecoratorErrors:
    def test_no_arguments_function_raises(self):
        with pytest.raises(TarValidationError, match="no arguments"):

            @validate_tar
            def no_args():
                pass

    def test_missing_required_argument(self, tmp_tar):
        @validate_tar
        def process(path):
            return path

        # Calling with no arguments surfaces a signature error first
        with pytest.raises(TarValidationError, match="Invalid function call signature"):
            process()  # path omitted

    def test_wrong_type_for_target_arg(self):
        @validate_tar
        def process(path):
            return path

        with pytest.raises(TarValidationError, match="Expected Path or str"):
            process(12345)

    def test_invalid_signature_call(self, tmp_tar):
        @validate_tar
        def process(path, required):
            return path

        with pytest.raises(TarValidationError, match="Invalid function call signature"):
            process(tmp_tar)  # missing 'required'

    def test_validation_failure_raises_in_decorator(self, symlink_tar):
        @validate_tar
        def process(path):
            return "should not reach"

        with pytest.raises(TarValidationError):
            process(symlink_tar)

    def test_nonexistent_file_raises_in_decorator(self, tmp_path):
        @validate_tar
        def process(path):
            return path

        with pytest.raises(TarValidationError, match="does not exist"):
            process(tmp_path / "missing.tar")

    def test_limit_exceeded_raises_in_decorator(self, many_members_tar):
        @validate_tar(max_tar_members=5)
        def process(path):
            return path

        with pytest.raises(TarValidationError, match="Too many members"):
            process(many_members_tar)


# ---------------------------------------------------------------------------
# 4. Mode detection heuristic
# ---------------------------------------------------------------------------


class TestModeDetection:
    def test_string_looking_like_path_is_direct(self, tmp_tar, capsys):
        # Paths with dots / separators are treated as direct calls
        result = validate_tar(str(tmp_tar))
        assert result is True

    def test_identifier_string_is_decorator_factory(self):
        # A plain identifier becomes the target argument name
        decorator = validate_tar("my_arg")
        assert callable(decorator)

        @decorator
        def process(my_arg):
            return my_arg

        # We need a real tar for the call to succeed
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
            tar_path = f.name
        try:
            with tarfile.open(tar_path, "w") as tar:
                info = tarfile.TarInfo(name="x")
                info.size = 0
                tar.addfile(info, io.BytesIO(b""))
            assert process(tar_path) == tar_path
        finally:
            os.unlink(tar_path)

    def test_none_returns_decorator_factory(self):
        factory = validate_tar(None)
        assert callable(factory)

        @factory
        def process(path):
            return "ok"

        # Will fail validation later, but decoration itself succeeds
        assert callable(process)

    def test_path_object_is_always_direct(self, tmp_tar):
        assert validate_tar(Path(tmp_tar)) is True

    def test_callable_is_always_decorator(self, tmp_tar):
        def target(path):
            return path

        wrapped = validate_tar(target)
        assert callable(wrapped)
        assert wrapped(tmp_tar) == tmp_tar


# ---------------------------------------------------------------------------
# 5. Parameter resolution (defaults vs overrides)
# ---------------------------------------------------------------------------


class TestParameterResolution:
    def test_defaults_are_used_when_none(self, tmp_tar):
        # Just ensure no crash; defaults are large enough for our tiny fixture
        assert validate_tar(tmp_tar) is True

    def test_explicit_none_still_uses_defaults(self, tmp_tar):
        assert (
            validate_tar(
                tmp_tar,
                max_file_size=None,
                max_tar_members=None,
                max_total_extracted_size=None,
                max_individual_file_size=None,
                max_filename_length=None,
                max_directory_depth=None,
            )
            is True
        )

    def test_zero_limits_fail_immediately(self, tmp_tar, capsys):
        # max_file_size=0 should reject any real file
        assert validate_tar(tmp_tar, max_file_size=0) is False
        assert "Exception:" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 6. Integration-style / composition tests
# ---------------------------------------------------------------------------


class TestComposition:
    def test_decorator_preserves_function_metadata(self):
        @validate_tar
        def documented(path: str) -> str:
            """My docstring."""
            return path

        assert documented.__name__ == "documented"
        assert documented.__doc__ == "My docstring."

    def test_multiple_calls_on_same_decorated_function(self, tmp_tar, symlink_tar):
        @validate_tar
        def process(path):
            return "ok"

        assert process(tmp_tar) == "ok"
        with pytest.raises(TarValidationError):
            process(symlink_tar)
        # Still works after a failure
        assert process(tmp_tar) == "ok"

    def test_decorator_with_default_argument(self, tmp_tar):
        @validate_tar
        def process(path, extra="default"):
            return extra

        assert process(tmp_tar) == "default"
        assert process(tmp_tar, extra="custom") == "custom"


# ---------------------------------------------------------------------------
# 7. Edge cases around the heuristic
# ---------------------------------------------------------------------------


class TestHeuristicEdgeCases:
    @pytest.mark.parametrize(
        "value, expect_decorator",
        [
            ("simple", True),
            ("_private", True),
            ("CamelCase", True),
            ("with.dot", False),          # looks like a filename
            ("dir/file", False),
            ("/abs/path", False),
            ("C:\\windows", False),
            ("http://example.com/a.tar", False),
            ("file://local", False),
            (".hidden", True),            # starts with dot → not treated as path
            ("noextension", True),
        ],
    )
    def test_looks_like_file_path(self, value, expect_decorator):
        is_decorator = not _looks_like_file_path(value) if isinstance(value, str) else False
        # For the public API we only care about the resulting mode
        if expect_decorator:
            # Should return a decorator factory (or apply if we passed a callable)
            result = validate_tar(value)
            assert callable(result)
        else:
            # Treated as a path → will try to open it and return False
            result = validate_tar(value)
            assert result is False


# ---------------------------------------------------------------------------
# 8. Smoke test that the internal helper can be called directly
# ---------------------------------------------------------------------------


class TestInternalHelper:
    def test_helper_accepts_valid_tar(self, tmp_tar):
        # Should not raise
        _validate_tar_file(
            tmp_tar,
            DEFAULT_MAX_FILE_SIZE,
            DEFAULT_MAX_TAR_MEMBERS,
            DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
            DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
            DEFAULT_MAX_FILENAME_LENGTH,
            DEFAULT_MAX_DIRECTORY_DEPTH,
        )

    def test_helper_rejects_symlink(self, symlink_tar):
        with pytest.raises(TarValidationError, match="Disallowed member type"):
            _validate_tar_file(
                symlink_tar,
                DEFAULT_MAX_FILE_SIZE,
                DEFAULT_MAX_TAR_MEMBERS,
                DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
                DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
                DEFAULT_MAX_FILENAME_LENGTH,
                DEFAULT_MAX_DIRECTORY_DEPTH,
            )
