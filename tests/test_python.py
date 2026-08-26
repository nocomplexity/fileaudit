# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0


import ast
import os
from pathlib import Path

import pytest

from fileaudit.python_check import (
    validate_python,
    PythonValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_python(path: Path, source: str, encoding="utf-8") -> Path:
    path.write_text(source, encoding=encoding)
    return path


def write_bytes(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


# ===========================================================================
# DIRECT CALL MODE — BASIC SUCCESS / FAILURE
# ===========================================================================

def test_direct_call_valid_python(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    assert validate_python(path) is True


def test_direct_call_accepts_string_path(tmp_path):
    path = write_python(tmp_path / "valid.py", "print('hello')\n")

    assert validate_python(str(path)) is True


def test_direct_call_accepts_path_object(tmp_path):
    path = write_python(tmp_path / "valid.py", "def hello():\n    return 1\n")

    assert validate_python(path) is True


def test_direct_call_rejects_nonexistent_file(tmp_path):
    path = tmp_path / "missing.py"

    assert validate_python(path) is False


def test_direct_call_rejects_directory(tmp_path):
    directory = tmp_path / "example.py"
    directory.mkdir()

    assert validate_python(directory) is False


def test_direct_call_rejects_non_python_extension(tmp_path):
    path = tmp_path / "example.txt"
    path.write_text("x = 1\n", encoding="utf-8")

    assert validate_python(path) is False


def test_direct_call_rejects_syntax_error(tmp_path):
    path = write_python(tmp_path / "invalid.py", "def broken(:\n")

    assert validate_python(path) is False


# ===========================================================================
# MODE-DETECTION HEURISTIC
# ===========================================================================

def test_string_looking_like_path_is_direct_mode(tmp_path):
    path = write_python(tmp_path / "example.py", "x = 1\n")

    assert validate_python(str(path)) is True


def test_path_object_is_always_direct_mode(tmp_path):
    path = write_python(tmp_path / "example.py", "x = 1\n")

    assert validate_python(Path(path)) is True


def test_url_looking_string_is_direct_mode(monkeypatch):
    # Avoid an actual network request. Verify that URL input reaches
    # validation rather than being interpreted as a decorator argument.
    import fileaudit.python_check as module

    called = {}

    def fake_validate(path, *args, **kwargs):
        called["path"] = path

    monkeypatch.setattr(module, "_validate_python_file", fake_validate)

    assert validate_python("https://example.com/test.py") is True
    assert called["path"] == "https://example.com/test.py"


# ===========================================================================
# DECORATOR — BARE @validate_python
# ===========================================================================

def test_bare_decorator_validates_first_argument(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    @validate_python
    def process(source_path):
        return "processed"

    assert process(path) == "processed"


def test_bare_decorator_rejects_invalid_file(tmp_path):
    path = write_python(tmp_path / "invalid.py", "def broken(:\n")

    @validate_python
    def process(source_path):
        pytest.fail("function body must not execute")

    with pytest.raises(Exception):
        process(path)


def test_bare_decorator_preserves_return_value(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    @validate_python
    def process(source_path):
        return 12345

    assert process(path) == 12345


def test_bare_decorator_preserves_function_metadata(tmp_path):
    @validate_python
    def process(source_path):
        """Important docstring."""
        return True

    assert process.__name__ == "process"
    assert process.__doc__ == "Important docstring."


# ===========================================================================
# DECORATOR FACTORY — @validate_python()
# ===========================================================================

def test_empty_decorator_factory(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    @validate_python()
    def process(source_path):
        return "ok"

    assert process(path) == "ok"


def test_decorator_factory_rejects_invalid_python(tmp_path):
    path = write_python(tmp_path / "invalid.py", "if:\n")

    @validate_python()
    def process(source_path):
        pytest.fail("body should not execute")

    with pytest.raises(Exception):
        process(path)


# ===========================================================================
# DECORATOR — CUSTOM TARGET ARGUMENT
# ===========================================================================

def test_custom_argument_name(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    @validate_python("source_path")
    def process(other, source_path):
        return other

    assert process("hello", path) == "hello"


def test_custom_argument_name_works_with_keyword(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    @validate_python("source_path")
    def process(other, source_path):
        return other

    assert process("hello", source_path=path) == "hello"


def test_unknown_custom_argument_name_falls_back_to_first_parameter(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    @validate_python("does_not_exist")
    def process(source_path):
        return "ok"

    assert process(path) == "ok"


# ===========================================================================
# DECORATOR — PATH TYPES
# ===========================================================================

@pytest.mark.parametrize("path_factory", [str, Path])
def test_decorator_accepts_str_and_path(tmp_path, path_factory):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    @validate_python
    def process(source_path):
        return True

    assert process(path_factory(path)) is True


def test_decorator_rejects_invalid_argument_type():
    @validate_python
    def process(source_path):
        return True

    with pytest.raises(PythonValidationError, match="Expected Path or str"):
        process(123)


def test_decorator_rejects_none_argument():
    @validate_python
    def process(source_path):
        return True

    with pytest.raises(PythonValidationError, match="Missing required argument"):
        process(None)


# ===========================================================================
# DECORATOR — FUNCTION SIGNATURE / BINDING
# ===========================================================================

def test_decorator_rejects_function_without_arguments():
    with pytest.raises(
        PythonValidationError,
        match="has no arguments",
    ):
        @validate_python
        def process():
            return True


def test_decorator_reports_invalid_call_signature(tmp_path):
    @validate_python
    def process(source_path, required):
        return True

    with pytest.raises(
        PythonValidationError,
        match="Invalid function call signature",
    ):
        process(tmp_path / "valid.py")


def test_decorator_supports_default_target_argument(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    @validate_python
    def process(source_path, option=True):
        return option

    assert process(path) is True


def test_decorator_supports_keyword_arguments(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    @validate_python
    def process(source_path):
        return "ok"

    assert process(source_path=path) == "ok"


# ===========================================================================
# FILE SIZE LIMIT
# ===========================================================================

def test_file_size_limit_accepts_file_at_limit(tmp_path):
    path = write_python(tmp_path / "small.py", "x = 1\n")

    assert validate_python(path, max_file_size=path.stat().st_size) is True


def test_file_size_limit_rejects_oversized_file(tmp_path):
    path = write_python(tmp_path / "large.py", "x = 1\n")

    assert validate_python(path, max_file_size=1) is False


def test_file_size_limit_is_checked_before_parsing(tmp_path, monkeypatch):
    path = write_python(tmp_path / "large.py", "x = 1\n")

    import fileaudit.python_check as module

    def fail_if_called(*args, **kwargs):
        pytest.fail("parser/reader should not be reached")

    monkeypatch.setattr(ast, "parse", fail_if_called)

    assert validate_python(path, max_file_size=1) is False


# ===========================================================================
# LINE LIMITS
# ===========================================================================

def test_max_lines_accepts_file_at_limit(tmp_path):
    path = write_python(
        tmp_path / "lines.py",
        "x = 1\ny = 2\nz = 3\n",
    )

    assert validate_python(path, max_lines=3) is True


def test_max_lines_rejects_too_many_lines(tmp_path):
    path = write_python(
        tmp_path / "lines.py",
        "x = 1\ny = 2\nz = 3\n",
    )

    assert validate_python(path, max_lines=2) is False


def test_max_line_length_accepts_line_at_limit(tmp_path):
    source = "x = " + ("a" * 20) + "\n"
    path = write_python(tmp_path / "length.py", source)

    assert validate_python(path, max_line_length=len(source.rstrip("\n"))) is True


def test_max_line_length_rejects_long_line(tmp_path):
    source = "x = " + ("a" * 20) + "\n"
    path = write_python(tmp_path / "length.py", source)

    assert validate_python(path, max_line_length=10) is False


# ===========================================================================
# UTF-8 / BOM / NULL BYTE HANDLING
# ===========================================================================

def test_utf8_source_is_accepted(tmp_path):
    path = write_bytes(
        tmp_path / "unicode.py",
        "message = 'héllo 世界'\n".encode("utf-8"),
    )

    assert validate_python(path) is True


def test_utf8_bom_is_accepted_and_stripped(tmp_path):
    path = write_bytes(
        tmp_path / "bom.py",
        b"\xef\xbb\xbf" + b"x = 1\n",
    )

    assert validate_python(path) is True


def test_invalid_utf8_is_rejected(tmp_path):
    path = write_bytes(
        tmp_path / "invalid_utf8.py",
        b"x = \xff\xfe\n",
    )

    assert validate_python(path) is False


def test_null_byte_is_rejected(tmp_path):
    path = write_bytes(
        tmp_path / "null.py",
        b"x = 1\x00\n",
    )

    assert validate_python(path) is False


# ===========================================================================
# PATH TRAVERSAL / ALLOWED BASE DIRECTORY
# ===========================================================================

def test_allowed_base_dir_accepts_file_inside_base(tmp_path):
    base = tmp_path / "allowed"
    base.mkdir()

    path = write_python(base / "valid.py", "x = 1\n")

    assert validate_python(
        path,
        allowed_base_dir=base,
    ) is True


def test_allowed_base_dir_rejects_file_outside_base(tmp_path):
    base = tmp_path / "allowed"
    base.mkdir()

    outside = write_python(tmp_path / "outside.py", "x = 1\n")

    assert validate_python(
        outside,
        allowed_base_dir=base,
    ) is False


def test_allowed_base_dir_accepts_nested_file(tmp_path):
    base = tmp_path / "allowed"
    nested = base / "nested" / "deeper"
    nested.mkdir(parents=True)

    path = write_python(nested / "valid.py", "x = 1\n")

    assert validate_python(
        path,
        allowed_base_dir=base,
    ) is True


def test_allowed_base_dir_rejects_sibling_prefix(tmp_path):
    base = tmp_path / "allowed"
    sibling = tmp_path / "allowed_evil"

    base.mkdir()
    sibling.mkdir()

    path = write_python(sibling / "evil.py", "x = 1\n")

    assert validate_python(
        path,
        allowed_base_dir=base,
    ) is False


# ===========================================================================
# SYMLINK SECURITY
# ===========================================================================

@pytest.mark.skipif(
    not hasattr(os, "symlink"),
    reason="Symbolic links are not supported",
)
def test_symlink_rejected_by_default(tmp_path):
    target = write_python(tmp_path / "target.py", "x = 1\n")
    link = tmp_path / "link.py"

    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Unable to create symbolic link")

    assert validate_python(link) is False


@pytest.mark.skipif(
    not hasattr(os, "symlink"),
    reason="Symbolic links are not supported",
)
def test_symlink_can_be_allowed(tmp_path):
    target = write_python(tmp_path / "target.py", "x = 1\n")
    link = tmp_path / "link.py"

    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Unable to create symbolic link")

    assert validate_python(link, allow_symlinks=True) is True


# ===========================================================================
# AST NODE LIMIT
# ===========================================================================

def test_ast_node_limit_accepts_file_at_limit(tmp_path):
    source = "x = 1\n"
    tree = ast.parse(source)
    node_count = sum(1 for _ in ast.walk(tree))

    path = write_python(tmp_path / "ast.py", source)

    assert validate_python(
        path,
        max_ast_nodes=node_count,
    ) is True


def test_ast_node_limit_rejects_file_above_limit(tmp_path):
    path = write_python(
        tmp_path / "ast.py",
        "x = 1\ny = 2\nz = 3\n",
    )

    assert validate_python(path, max_ast_nodes=1) is False


def test_ast_node_limit_zero_rejects_nonempty_python(tmp_path):
    path = write_python(tmp_path / "ast.py", "x = 1\n")

    assert validate_python(path, max_ast_nodes=0) is False


# ===========================================================================
# AST PARSER EXCEPTIONS
# ===========================================================================

@pytest.mark.parametrize(
    "exception",
    [
        SyntaxError,
        ValueError,
        MemoryError,
        RecursionError,
    ],
)
def test_ast_parse_exceptions_are_rejected(
    tmp_path,
    monkeypatch,
    exception,
):
    path = write_python(tmp_path / "parse.py", "x = 1\n")

    def fake_parse(*args, **kwargs):
        raise exception("simulated parser failure")

    monkeypatch.setattr(ast, "parse", fake_parse)

    assert validate_python(path) is False


# ===========================================================================
# PARSE TIMEOUT
# ===========================================================================

@pytest.mark.skipif(
    os.name == "nt",
    reason="SIGALRM is unavailable on Windows",
)
def test_parse_timeout_is_supported(tmp_path):
    path = write_python(tmp_path / "parse.py", "x = 1\n")

    # A normal tiny file should complete before a one-second timeout.
    assert validate_python(path, parse_timeout=1) is True


# ===========================================================================
# REMOTE FILES
# ===========================================================================

def test_http_url_is_rejected(tmp_path, monkeypatch):
    import fileaudit.python_check as module

    # If the implementation reaches the remote handler, make it fail
    # deterministically rather than making a network request.
    def fake_validate(path, *args, **kwargs):
        raise ValueError("HTTP URLs are not allowed")

    monkeypatch.setattr(module, "_validate_python_file", fake_validate)

    assert validate_python("http://example.com/test.py") is False


def test_ftp_url_is_rejected(tmp_path, monkeypatch):
    import fileaudit.python_check as module

    def fake_validate(path, *args, **kwargs):
        raise ValueError("FTP URLs are not allowed")

    monkeypatch.setattr(module, "_validate_python_file", fake_validate)

    assert validate_python("ftp://example.com/test.py") is False


# ===========================================================================
# ERROR REPORTING IN DIRECT MODE
# ===========================================================================

def test_direct_mode_returns_false_instead_of_raising(tmp_path):
    path = write_python(tmp_path / "bad.py", "this is not valid python: !")

    result = validate_python(path)

    assert result is False


def test_direct_mode_prints_exception(tmp_path, capsys):
    path = write_python(tmp_path / "bad.py", "def broken(:\n")

    result = validate_python(path)

    captured = capsys.readouterr()

    assert result is False
    assert "Exception:" in captured.out


# ===========================================================================
# DECORATOR VALIDATION HAPPENS BEFORE FUNCTION BODY
# ===========================================================================

def test_function_body_does_not_execute_when_validation_fails(tmp_path):
    path = write_python(tmp_path / "bad.py", "def broken(:\n")
    executed = False

    @validate_python
    def process(source_path):
        nonlocal executed
        executed = True

    with pytest.raises(Exception):
        process(path)

    assert executed is False


def test_function_body_executes_after_successful_validation(tmp_path):
    path = write_python(tmp_path / "good.py", "x = 1\n")
    executed = False

    @validate_python
    def process(source_path):
        nonlocal executed
        executed = True
        return "done"

    assert process(path) == "done"
    assert executed is True


# ===========================================================================
# VALID PYTHON CONSTRUCTS
# ===========================================================================

@pytest.mark.parametrize(
    "source",
    [
        "x = 1\n",
        "def foo(x):\n    return x + 1\n",
        "class Foo:\n    pass\n",
        "import os\n",
        "from pathlib import Path\n",
        "if True:\n    x = 1\nelse:\n    x = 2\n",
        "for x in range(3):\n    print(x)\n",
        "with open('x') as f:\n    data = f.read()\n",
        "async def foo():\n    await bar()\n",
        "lambda x: x + 1\n",
        "[x * 2 for x in range(10)]\n",
    ],
)
def test_valid_python_constructs_are_accepted(tmp_path, source):
    path = write_python(tmp_path / "valid.py", source)

    assert validate_python(path) is True


# ===========================================================================
# DECORATOR CONFIGURATION
# ===========================================================================

def test_decorator_respects_max_file_size(tmp_path):
    path = write_python(tmp_path / "large.py", "x = 1\n")

    @validate_python(max_file_size=1)
    def process(source_path):
        pytest.fail("body must not execute")

    with pytest.raises(Exception):
        process(path)


def test_decorator_respects_max_lines(tmp_path):
    path = write_python(tmp_path / "many_lines.py", "x = 1\ny = 2\n")

    @validate_python(max_lines=1)
    def process(source_path):
        pytest.fail("body must not execute")

    with pytest.raises(Exception):
        process(path)


def test_decorator_respects_max_line_length(tmp_path):
    path = write_python(tmp_path / "long_line.py", "x = " + "a" * 100 + "\n")

    @validate_python(max_line_length=10)
    def process(source_path):
        pytest.fail("body must not execute")

    with pytest.raises(Exception):
        process(path)


def test_decorator_respects_max_ast_nodes(tmp_path):
    path = write_python(tmp_path / "many_nodes.py", "x = 1\ny = 2\n")

    @validate_python(max_ast_nodes=1)
    def process(source_path):
        pytest.fail("body must not execute")

    with pytest.raises(Exception):
        process(path)


# ===========================================================================
# DEFAULT ARGUMENT / TARGET SELECTION EDGE CASES
# ===========================================================================

def test_first_parameter_is_used_when_custom_target_not_supplied(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    @validate_python()
    def process(source_path, other):
        return other

    assert process(path, "value") == "value"


def test_custom_target_is_not_confused_with_other_arguments(tmp_path):
    valid = write_python(tmp_path / "valid.py", "x = 1\n")

    @validate_python("source_path")
    def process(value, source_path, another):
        return value

    assert process("value", valid, "another") == "value"


# ===========================================================================
# DEFAULT / NONE LIMIT HANDLING
# ===========================================================================

def test_explicit_none_file_size_uses_default(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    assert validate_python(path, max_file_size=None) is True


def test_zero_max_lines_rejects_nonempty_file(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    assert validate_python(path, max_lines=0) is False


def test_zero_max_line_length_rejects_nonempty_line(tmp_path):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    assert validate_python(path, max_line_length=0) is False


# ===========================================================================
# PATH / DIRECTORY EDGE CASES
# ===========================================================================

def test_relative_path_is_supported(tmp_path, monkeypatch):
    path = write_python(tmp_path / "valid.py", "x = 1\n")

    monkeypatch.chdir(tmp_path)

    assert validate_python("valid.py") is True


def test_filename_with_dots_is_supported(tmp_path):
    path = write_python(tmp_path / "my.test.file.py", "x = 1\n")

    assert validate_python(path) is True


def test_hidden_python_file_is_supported(tmp_path):
    path = write_python(tmp_path / ".hidden.py", "x = 1\n")

    assert validate_python(path) is True
