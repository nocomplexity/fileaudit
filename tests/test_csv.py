# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0
"""
Simple black-box pytest suite for validate_csv.

Only public interfaces are exercised:
  - validate_csv(...) direct validation mode (returns True / raises)
  - validate_csv as a decorator (bare, called, and with arg-name string)
  - CsvValidationError as the sole expected failure type

"""

import pytest

from fileaudit.csv_check import (
    validate_csv,
    CsvValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_csv(tmp_path, name="data.csv", content=b"a,b,c\n1,2,3\n"):
    path = tmp_path / name
    path.write_bytes(content)
    return path


# ---------------------------------------------------------------------------
# Direct-invocation: happy paths
# ---------------------------------------------------------------------------

def test_valid_simple_csv_returns_true(tmp_path):
    csv_file = _write_csv(tmp_path)
    assert validate_csv(str(csv_file)) is True


def test_valid_path_object_returns_true(tmp_path):
    csv_file = _write_csv(tmp_path)
    assert validate_csv(csv_file) is True


def test_valid_empty_file_returns_true(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"")
    assert validate_csv(str(csv_file)) is True


def test_valid_header_only_csv_returns_true(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"name,age\n")
    assert validate_csv(str(csv_file)) is True


def test_valid_utf8_multibyte_returns_true(tmp_path):
    csv_file = _write_csv(
        tmp_path,
        content="naam,stad\nJosé,Łódź\n".encode("utf-8"),
    )
    assert validate_csv(str(csv_file)) is True


# ---------------------------------------------------------------------------
# Direct-invocation: path / extension errors
# ---------------------------------------------------------------------------

def test_missing_file_raises(tmp_path):
    with pytest.raises(CsvValidationError):
        validate_csv(str(tmp_path / "does_not_exist.csv"))


def test_wrong_extension_raises(tmp_path):
    csv_file = _write_csv(tmp_path, name="data.txt")
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file))


def test_no_extension_raises(tmp_path):
    csv_file = _write_csv(tmp_path, name="data")
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file))


def test_directory_path_raises(tmp_path):
    directory = tmp_path / "adir.csv"
    directory.mkdir()
    with pytest.raises(CsvValidationError):
        validate_csv(str(directory))

def test_empty_string_raises():
    @validate_csv
    def process(csv_path):
        return "should not run"

    with pytest.raises(CsvValidationError):
        process("")
        

def test_unsupported_scheme_raises():
    with pytest.raises(CsvValidationError):
        validate_csv("http://example.com/data.csv")


def test_ftp_scheme_raises():
    with pytest.raises(CsvValidationError):
        validate_csv("ftp://example.com/data.csv")


def test_https_url_with_credentials_raises():
    with pytest.raises(CsvValidationError):
        validate_csv("https://user:pass@example.com/data.csv")


def test_non_string_non_path_raises():
    with pytest.raises(CsvValidationError):
        validate_csv(12345)


# ---------------------------------------------------------------------------
# Direct-invocation: security checks
# ---------------------------------------------------------------------------

def test_formula_injection_equals_raises(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b\n=1+1,2\n")
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file))


def test_formula_injection_plus_raises(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b\n+cmd,2\n")
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file))


def test_formula_injection_at_sign_raises(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b\n@SUM(A1),2\n")
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file))


def test_formula_injection_allowed_when_disabled(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b\n=1+1,2\n")
    assert (
        validate_csv(
            str(csv_file),
            reject_formula_injection=False,
        )
        is True
    )


def test_nul_byte_raises(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b\nx\x00y,2\n")
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file))


def test_control_character_raises(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b\nx\x01y,2\n")
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file))


def test_control_character_allowed_when_disabled(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b\nx\x01y,2\n")
    assert (
        validate_csv(
            str(csv_file),
            reject_control_characters=False,
        )
        is True
    )


def test_utf8_bom_raises(tmp_path):
    csv_file = _write_csv(
        tmp_path,
        content=b"\xef\xbb\xbfa,b\n1,2\n",
    )
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file))


def test_invalid_utf8_raises(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b\n\xff\xfe,2\n")
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file))


# ---------------------------------------------------------------------------
# Direct-invocation: size / count limits
# ---------------------------------------------------------------------------

def test_file_size_limit_raises(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b\n1,2\n3,4\n")
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file), max_file_size=3)


def test_max_rows_raises(tmp_path):
    csv_file = _write_csv(
        tmp_path,
        content=b"a,b\n1,2\n3,4\n5,6\n",
    )
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file), max_rows=1)


def test_max_columns_raises(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b,c\n1,2,3\n")
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file), max_columns=1)


def test_max_total_fields_raises(tmp_path):
    csv_file = _write_csv(
        tmp_path,
        content=b"a,b,c\n1,2,3\n4,5,6\n",
    )
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file), max_total_fields=2)


def test_max_field_size_raises(tmp_path):
    csv_file = _write_csv(
        tmp_path,
        content=b"a,b\n" + b"x" * 200 + b",2\n",
    )
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file), max_field_size=10)


def test_max_row_size_raises(tmp_path):
    csv_file = _write_csv(
        tmp_path,
        content=b"a,b\nxxxxxxxxxx,xxxxxxxxxx\n",
    )
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file), max_row_size=5)


def test_max_filename_length_raises(tmp_path):
    csv_file = _write_csv(tmp_path, name="a_very_long_name.csv")
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file), max_filename_length=3)


def test_invalid_config_non_positive_raises(tmp_path):
    csv_file = _write_csv(tmp_path)
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file), max_rows=0)


def test_invalid_config_bool_raises(tmp_path):
    csv_file = _write_csv(tmp_path)
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file), max_rows=True)


def test_invalid_config_non_integer_raises(tmp_path):
    csv_file = _write_csv(tmp_path)
    with pytest.raises(CsvValidationError):
        validate_csv(str(csv_file), max_rows="10")


# ---------------------------------------------------------------------------
# Decorator mode
# ---------------------------------------------------------------------------

def test_decorator_bare_uses_first_arg(tmp_path):
    csv_file = _write_csv(tmp_path)

    @validate_csv
    def process(csv_path):
        return f"ok:{csv_path}"

    assert process(str(csv_file)) == f"ok:{csv_file}"


def test_decorator_bare_rejects_invalid_csv(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b\n=1+1,2\n")

    @validate_csv
    def process(csv_path):
        return "should not run"

    with pytest.raises(CsvValidationError):
        process(str(csv_file))


def test_decorator_called_form(tmp_path):
    csv_file = _write_csv(tmp_path)

    @validate_csv()
    def process(csv_path):
        return "ran"

    assert process(str(csv_file)) == "ran"


def test_decorator_explicit_arg_name(tmp_path):
    csv_file = _write_csv(tmp_path)

    @validate_csv("input_file")
    def process(other, input_file):
        return "ran"

    assert process("ignored", str(csv_file)) == "ran"


def test_decorator_with_limits(tmp_path):
    csv_file = _write_csv(tmp_path, content=b"a,b\n1,2\n3,4\n")

    @validate_csv(max_rows=1)
    def process(csv_path):
        return "ran"

    with pytest.raises(CsvValidationError):
        process(str(csv_file))


def test_decorator_kwargs_call(tmp_path):
    csv_file = _write_csv(tmp_path)

    @validate_csv
    def process(csv_path):
        return "ran"

    assert process(csv_path=str(csv_file)) == "ran"


def test_decorator_missing_path_argument_raises():
    @validate_csv
    def process(csv_path):
        return "ran"

    with pytest.raises(CsvValidationError):
        process(None)


def test_decorator_non_str_path_raises(tmp_path):
    @validate_csv
    def process(csv_path):
        return "ran"

    with pytest.raises(CsvValidationError):
        process(123)


def test_decorator_no_parameters_raises():
    with pytest.raises(CsvValidationError):
        @validate_csv
        def process():
            return "ran"


def test_decorator_preserves_function_name(tmp_path):
    csv_file = _write_csv(tmp_path)

    @validate_csv
    def process(csv_path):
        return "ran"

    assert process.__name__ == "process"