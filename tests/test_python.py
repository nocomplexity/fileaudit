# SPDX-FileCopyrightText: 2026-present Maikel Mardjan and contributors
# SPDX-License-Identifier: MPL-2.0

import ast
import os
import signal
from pathlib import Path

import pytest

from fileaudit.python_check import (
    validate_python,
    PythonValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_python(tmp_path, name="example.py", source="x = 1\n"):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


def assert_invalid(path, **kwargs):
    with pytest.raises(PythonValidationError):
        validate_python(path, **kwargs)


# ---------------------------------------------------------------------------
# Direct-call API
# ---------------------------------------------------------------------------

def test_valid_path_returns_true(tmp_path):
    path = write_python(tmp_path)
    assert validate_python(path) is True


def test_string_path_returns_true(tmp_path):
    path = write_python(tmp_path)
    assert validate_python(str(path)) is True


def test_path_object_returns_true(tmp_path):
    path = write_python(tmp_path)
    assert validate_python(Path(path)) is True


@pytest.mark.parametrize(
    "source",
    [
        "x = 1\n",
        "def greet(name):\n    return name\n",
        "class Example:\n    pass\n",
        "import os\n",
        "from pathlib import Path\n",
        "async def run():\n    await task()\n",
        "items = [x * 2 for x in range(5)]\n",
        "if True:\n    value = 1\nelse:\n    value = 2\n",
    ],
)
def test_valid_python_constructs_are_accepted(tmp_path, source):
    path = write_python(tmp_path, source=source)
    assert validate_python(path) is True


@pytest.mark.parametrize(
    "name, source",
    [
        ("missing.py", None),
        ("invalid.py", "def broken(:\n"),
        ("wrong_extension.txt", "x = 1\n"),
    ],
)
def test_invalid_files_raise_validation_error(tmp_path, name, source):
    path = tmp_path / name

    if source is not None:
        path.write_text(source, encoding="utf-8")

    assert_invalid(path)


def test_directory_is_rejected(tmp_path):
    directory = tmp_path / "folder.py"
    directory.mkdir()

    assert_invalid(directory)


def test_empty_python_file_is_valid(tmp_path):
    path = write_python(tmp_path, source="")
    assert validate_python(path) is True


def test_relative_path_is_supported(tmp_path, monkeypatch):
    write_python(tmp_path, "relative.py")

    monkeypatch.chdir(tmp_path)

    assert validate_python("relative.py") is True


def test_dotted_filename_is_supported(tmp_path):
    path = write_python(tmp_path, "my.test.file.py")
    assert validate_python(path) is True


def test_hidden_python_filename_is_supported(tmp_path):
    path = write_python(tmp_path, ".hidden.py")
    assert validate_python(path) is True


# ---------------------------------------------------------------------------
# Direct-call error behaviour
# ---------------------------------------------------------------------------

def test_invalid_python_raises_instead_of_returning_false(tmp_path):
    path = write_python(tmp_path, source="def broken(:\n")

    with pytest.raises(PythonValidationError):
        result = validate_python(path)

        # This line must not be reached.
        assert result is False


def test_direct_call_does_not_print_errors(tmp_path, capsys):
    path = write_python(tmp_path, source="def broken(:\n")

    with pytest.raises(PythonValidationError):
        validate_python(path)

    captured = capsys.readouterr()
    assert captured.out == ""



# ---------------------------------------------------------------------------
# Decorator forms
# ---------------------------------------------------------------------------

def test_bare_decorator_validates_argument(tmp_path):
    path = write_python(tmp_path)

    @validate_python
    def process(source_path):
        return "processed"

    assert process(path) == "processed"


def test_decorator_factory_validates_argument(tmp_path):
    path = write_python(tmp_path)

    @validate_python()
    def process(source_path):
        return "processed"

    assert process(path) == "processed"


def test_decorator_preserves_return_value(tmp_path):
    path = write_python(tmp_path)

    @validate_python
    def process(source_path):
        return 12345

    assert process(path) == 12345


def test_decorator_preserves_function_metadata():
    @validate_python
    def process(source_path):
        """Example docstring."""
        return True

    assert process.__name__ == "process"
    assert process.__doc__ == "Example docstring."


def test_decorator_rejects_invalid_file_before_calling_function(tmp_path):
    path = write_python(tmp_path, source="def broken(:\n")

    @validate_python
    def process(source_path):
        pytest.fail("The wrapped function must not execute.")

    with pytest.raises(PythonValidationError):
        process(path)


def test_decorator_rejects_missing_argument():
    @validate_python
    def process(source_path):
        return True

    with pytest.raises(PythonValidationError):
        process()


def test_decorator_rejects_none_argument():
    @validate_python
    def process(source_path):
        return True

    with pytest.raises(PythonValidationError):
        process(None)


def test_decorator_rejects_non_path_argument():
    @validate_python
    def process(source_path):
        return True

    with pytest.raises(PythonValidationError):
        process(123)


def test_decorator_rejects_function_without_parameters():
    with pytest.raises(PythonValidationError):

        @validate_python
        def process():
            return True


# ---------------------------------------------------------------------------
# Decorator argument selection
# ---------------------------------------------------------------------------

def test_first_parameter_is_default_target(tmp_path):
    path = write_python(tmp_path)

    @validate_python()
    def process(source_path, other):
        return other

    assert process(path, "result") == "result"


def test_custom_target_parameter(tmp_path):
    path = write_python(tmp_path)

    @validate_python("source_path")
    def process(other, source_path):
        return other

    assert process("hello", path) == "hello"


def test_custom_target_parameter_as_keyword(tmp_path):
    path = write_python(tmp_path)

    @validate_python("source_path")
    def process(other, source_path):
        return other

    assert process("hello", source_path=path) == "hello"


def test_unknown_custom_target_is_rejected():
    with pytest.raises(PythonValidationError):

        @validate_python("does_not_exist")
        def process(source_path):
            return True


# ---------------------------------------------------------------------------
# File-size, line-count and line-length limits
# ---------------------------------------------------------------------------

def test_explicit_none_file_size_uses_default(tmp_path):
    path = write_python(tmp_path)
    assert validate_python(path, max_file_size=None) is True


def test_file_size_limit_accepts_file_at_limit(tmp_path):
    source = "x = 1\n"
    path = write_python(tmp_path, source=source)

    assert validate_python(
        path,
        max_file_size=len(source.encode("utf-8")),
    ) is True


def test_file_size_limit_rejects_oversized_file(tmp_path):
    path = write_python(tmp_path, source="x = 1\n")

    assert_invalid(path, max_file_size=2)


def test_max_lines_accepts_file_at_limit(tmp_path):
    path = write_python(tmp_path, source="x = 1\ny = 2\n")

    assert validate_python(path, max_lines=2) is True


def test_max_lines_rejects_file_above_limit(tmp_path):
    path = write_python(tmp_path, source="x = 1\ny = 2\n")

    assert_invalid(path, max_lines=1)


def test_max_line_length_accepts_line_at_limit(tmp_path):
    source = "x = 123\n"
    path = write_python(tmp_path, source=source)

    assert validate_python(path, max_line_length=8) is True


def test_max_line_length_rejects_long_line(tmp_path):
    path = write_python(tmp_path, source="x = " + "a" * 100 + "\n")

    assert_invalid(path, max_line_length=10)


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_file_size": -1},
        {"max_lines": -1},
        {"max_line_length": -1},
        {"max_ast_nodes": -1},
        {"parse_timeout": -1},
        {"max_lines": 1.5},
        {"max_line_length": "100"},
        {"max_ast_nodes": None},
        {"max_file_size": True},
        {"max_lines": False},
    ],
)
def test_invalid_configuration_raises_value_error(tmp_path, kwargs):
    path = write_python(tmp_path)

    with pytest.raises(ValueError):
        validate_python(path, **kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_file_size": 0},
        {"max_lines": 0},
        {"max_line_length": 0},
        {"max_ast_nodes": 0},
    ],
)
def test_zero_limits_are_rejected_as_configuration(tmp_path, kwargs):
    path = write_python(tmp_path)

    with pytest.raises(ValueError):
        validate_python(path, **kwargs)


def test_zero_parse_timeout_is_allowed(tmp_path):
    path = write_python(tmp_path)

    assert validate_python(path, parse_timeout=0) is True


# ---------------------------------------------------------------------------
# AST node limits
# ---------------------------------------------------------------------------

def test_ast_node_limit_accepts_file_at_limit(tmp_path):
    source = "x = 1\n"
    node_count = sum(1 for _ in ast.walk(ast.parse(source)))
    path = write_python(tmp_path, source=source)

    assert validate_python(path, max_ast_nodes=node_count) is True


def test_ast_node_limit_rejects_file_above_limit(tmp_path):
    path = write_python(
        tmp_path,
        source="x = 1\ny = 2\nz = 3\n",
    )

    assert_invalid(path, max_ast_nodes=1)


@pytest.mark.parametrize(
    "exception",
    [
        SyntaxError,
        ValueError,
        MemoryError,
        RecursionError,
    ],
)
def test_ast_parser_errors_become_validation_errors(
    tmp_path,
    monkeypatch,
    exception,
):
    import fileaudit.python_check as module

    path = write_python(tmp_path)

    def fake_parse(*args, **kwargs):
        raise exception("simulated parser failure")

    monkeypatch.setattr(module.ast, "parse", fake_parse)

    with pytest.raises(PythonValidationError):
        validate_python(path)


# ---------------------------------------------------------------------------
# File encoding and content handling
# ---------------------------------------------------------------------------

def test_utf8_file_is_accepted(tmp_path):
    path = write_python(
        tmp_path,
        source="# café\nmessage = 'héllo'\n",
    )

    assert validate_python(path) is True


def test_utf8_bom_file_is_accepted(tmp_path):
    path = tmp_path / "bom.py"
    path.write_bytes(b"\xef\xbb\xbf" + b"x = 1\n")

    assert validate_python(path) is True


def test_null_byte_is_rejected(tmp_path):
    path = tmp_path / "null_byte.py"
    path.write_bytes(b"x = 1\x00\n")

    assert_invalid(path)


def test_invalid_encoding_is_rejected(tmp_path):
    path = tmp_path / "invalid_encoding.py"
    path.write_bytes(b"\xff\xfe\xfa")

    assert_invalid(path)


# ---------------------------------------------------------------------------
# Allowed base directory and symlinks
# ---------------------------------------------------------------------------

def test_file_inside_allowed_directory_is_accepted(tmp_path):
    base = tmp_path / "allowed"
    base.mkdir()

    path = write_python(base)

    assert validate_python(
        path,
        allowed_base_dir=base,
    ) is True


def test_file_outside_allowed_directory_is_rejected(tmp_path):
    base = tmp_path / "allowed"
    base.mkdir()

    outside = write_python(tmp_path, "outside.py")

    assert_invalid(outside, allowed_base_dir=base)


def test_symlink_is_rejected_by_default(tmp_path):
    target = write_python(tmp_path, "target.py")
    link = tmp_path / "link.py"

    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Cannot create symlinks on this platform.")

    assert_invalid(link)


def test_symlink_can_be_allowed(tmp_path):
    target = write_python(tmp_path, "target.py")
    link = tmp_path / "link.py"

    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Cannot create symlinks on this platform.")

    assert validate_python(link, allow_symlinks=True) is True


# ---------------------------------------------------------------------------
# URL-like strings must not trigger network access
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/test.py",
        "https://example.com/test.py",
        "ftp://example.com/test.py",
    ],
)
def test_url_like_string_is_rejected_without_network(
    monkeypatch,
    url,
):
    import fileaudit.python_check as module

    def reject_remote(path, *args, **kwargs):
        raise PythonValidationError("Remote paths are not supported.")

    monkeypatch.setattr(module, "_validate_python_file", reject_remote)

    with pytest.raises(PythonValidationError):
        validate_python(url)


# ---------------------------------------------------------------------------
# Parse timeout
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    os.name == "nt" or not hasattr(signal, "SIGALRM"),
    reason="SIGALRM is unavailable on this platform.",
)
def test_normal_file_completes_with_parse_timeout(tmp_path):
    path = write_python(tmp_path)

    assert validate_python(path, parse_timeout=1) is True


@pytest.mark.skipif(
    os.name == "nt"
    or not hasattr(signal, "SIGALRM")
    or not hasattr(signal, "setitimer"),
    reason="POSIX interval timers are unavailable.",
)
def test_existing_alarm_is_not_replaced(tmp_path):
    path = write_python(tmp_path)

    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)

    def handler(signum, frame):
        pass

    try:
        signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, 30)

        assert validate_python(path, parse_timeout=1) is True

        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        assert remaining > 0
        assert interval == 0
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)