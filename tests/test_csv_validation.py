# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026-present Maikel Mardjan (https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0

"""Black-box tests for fileaudit.csv_check.validate_csv."""

from pathlib import Path

import pytest

from fileaudit.csv_check import (
    validate_csv,
    CsvValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_csv(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Direct-call success
# ---------------------------------------------------------------------------

def test_direct_valid_local_csv(tmp_path):
    csv_path = _write_csv(tmp_path / "ok.csv", "a,b\n1,2\n")
    assert validate_csv(csv_path) is True
    assert validate_csv(str(csv_path)) is True


def test_direct_valid_with_custom_limits(tmp_path):
    csv_path = _write_csv(tmp_path / "ok.csv", "col1,col2\nx,y\n")
    assert (
        validate_csv(
            csv_path,
            max_file_size=10_000,
            max_rows=100,
            max_columns=10,
            max_field_size=1000,
        )
        is True
    )


def test_direct_path_object(tmp_path):
    csv_path = _write_csv(tmp_path / "pathobj.csv", "a,b\n1,2\n")
    assert validate_csv(Path(csv_path)) is True


# ---------------------------------------------------------------------------
# Direct-call failures – file / path issues
# ---------------------------------------------------------------------------

def test_direct_nonexistent_file(tmp_path):
    with pytest.raises(CsvValidationError) as exc_info:
        validate_csv(tmp_path / "missing.csv")
    assert "not found" in str(exc_info.value).lower() or "File not found" in str(
        exc_info.value
    )


def test_direct_directory_instead_of_file(tmp_path):
    with pytest.raises(CsvValidationError):
        validate_csv(tmp_path)


def test_direct_wrong_extension(tmp_path):
    bad = _write_csv(tmp_path / "data.txt", "a,b\n1,2\n")
    with pytest.raises(CsvValidationError) as exc_info:
        validate_csv(bad)
    assert ".csv" in str(exc_info.value).lower() or "extension" in str(
        exc_info.value
    ).lower()

def test_direct_empty_string():
    # An empty string does not look like a file path, so validate_csv
    # treats it as decorator mode and returns a decorator (no raise).
    result = validate_csv("")
    assert callable(result)
    

def test_direct_unsupported_type():
    with pytest.raises(CsvValidationError):
        validate_csv(123)
    with pytest.raises(CsvValidationError):
        validate_csv([])


# ---------------------------------------------------------------------------
# Direct-call failures – content / security checks
# ---------------------------------------------------------------------------

def test_direct_formula_injection(tmp_path):
    csv_path = _write_csv(tmp_path / "formula.csv", "name,value\n=cmd|calc,1\n")
    with pytest.raises(CsvValidationError) as exc_info:
        validate_csv(csv_path)
    assert "formula" in str(exc_info.value).lower()


def test_direct_formula_injection_can_be_disabled(tmp_path):
    csv_path = _write_csv(tmp_path / "formula.csv", "name,value\n=1+1,ok\n")
    # Should succeed when rejection is turned off
    assert validate_csv(csv_path, reject_formula_injection=False) is True


def test_direct_control_character(tmp_path):
    # BEL (U+0007) is a disallowed control character
    csv_path = _write_csv(tmp_path / "ctrl.csv", "a,b\n1,\x07evil\n")
    with pytest.raises(CsvValidationError) as exc_info:
        validate_csv(csv_path)
    assert "control" in str(exc_info.value).lower()


def test_direct_nul_byte(tmp_path):
    csv_path = tmp_path / "nul.csv"
    csv_path.write_bytes(b"a,b\n1,2\x00\n")
    with pytest.raises(CsvValidationError) as exc_info:
        validate_csv(csv_path)
    assert "nul" in str(exc_info.value).lower() or "\\0" in str(exc_info.value)


def test_direct_too_many_rows(tmp_path):
    content = "a,b\n" + "\n".join(f"{i},x" for i in range(20))
    csv_path = _write_csv(tmp_path / "rows.csv", content)
    with pytest.raises(CsvValidationError) as exc_info:
        validate_csv(csv_path, max_rows=5)
    assert "rows" in str(exc_info.value).lower()


def test_direct_too_many_columns(tmp_path):
    csv_path = _write_csv(tmp_path / "cols.csv", "a,b,c,d,e\n1,2,3,4,5\n")
    with pytest.raises(CsvValidationError) as exc_info:
        validate_csv(csv_path, max_columns=3)
    assert "column" in str(exc_info.value).lower()


def test_direct_oversized_file(tmp_path):
    csv_path = _write_csv(tmp_path / "big.csv", "a,b\n" + "x" * 200)
    with pytest.raises(CsvValidationError) as exc_info:
        validate_csv(csv_path, max_file_size=50)
    assert "size" in str(exc_info.value).lower()


def test_direct_oversized_field(tmp_path):
    csv_path = _write_csv(tmp_path / "field.csv", "a,b\n" + "x" * 100 + ",y\n")
    with pytest.raises(CsvValidationError) as exc_info:
        validate_csv(csv_path, max_field_size=20)
    assert "field" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# URL / scheme checks
# ---------------------------------------------------------------------------

def test_direct_rejects_http():
    with pytest.raises(CsvValidationError) as exc_info:
        validate_csv("http://example.com/data.csv")
    assert "https" in str(exc_info.value).lower()


def test_direct_rejects_ftp():
    with pytest.raises(CsvValidationError):
        validate_csv("ftp://example.com/data.csv")


def test_direct_rejects_file_scheme():
    with pytest.raises(CsvValidationError):
        validate_csv("file:///tmp/data.csv")


def test_direct_rejects_credentials_in_url():
    with pytest.raises(CsvValidationError) as exc_info:
        validate_csv("https://user:pass@example.com/data.csv")
    assert "credential" in str(exc_info.value).lower() or "password" in str(
        exc_info.value
    ).lower()


# ---------------------------------------------------------------------------
# Invalid configuration
# ---------------------------------------------------------------------------
def test_invalid_max_file_size(tmp_path):
    csv_path = _write_csv(tmp_path / "x.csv", "a,b\n1,2\n")
    with pytest.raises(CsvValidationError):
        validate_csv(csv_path, max_file_size=0)
    with pytest.raises(CsvValidationError):
        validate_csv(csv_path, max_file_size=-1)

def test_invalid_max_rows(tmp_path):
    csv_path = _write_csv(tmp_path / "x.csv", "a,b\n1,2\n")
    with pytest.raises(CsvValidationError):
        validate_csv(csv_path, max_rows=0)       

def test_invalid_max_columns(tmp_path):
    csv_path = _write_csv(tmp_path / "x.csv", "a,b\n1,2\n")
    with pytest.raises(CsvValidationError):
        validate_csv(csv_path, max_columns=-5)


# ---------------------------------------------------------------------------
# Decorator mode – success
# ---------------------------------------------------------------------------

def test_bare_decorator_success(tmp_path):
    csv_path = _write_csv(tmp_path / "d.csv", "a,b\n1,2\n")

    @validate_csv
    def process(path):
        return f"ok:{path}"

    assert process(csv_path) == f"ok:{csv_path}"


def test_decorator_factory_success(tmp_path):
    csv_path = _write_csv(tmp_path / "f.csv", "x,y\n3,4\n")

    @validate_csv()
    def process(path):
        return "processed"

    assert process(csv_path) == "processed"


def test_decorator_explicit_arg_name(tmp_path):
    csv_path = _write_csv(tmp_path / "named.csv", "a,b\n1,2\n")

    @validate_csv("input_file")
    def process(input_file, other=None):
        return input_file

    assert process(csv_path) == csv_path
    assert process(input_file=csv_path) == csv_path


def test_decorator_with_limits(tmp_path):
    csv_path = _write_csv(tmp_path / "lim.csv", "a,b\n1,2\n")

    @validate_csv(max_rows=100, max_columns=20)
    def process(path):
        return True

    assert process(path=csv_path) is True


# ---------------------------------------------------------------------------
# Decorator mode – failure
# ---------------------------------------------------------------------------

def test_decorator_raises_on_missing_file(tmp_path):
    @validate_csv
    def process(path):
        return path

    with pytest.raises(CsvValidationError):
        process(tmp_path / "missing.csv")


def test_decorator_raises_on_formula(tmp_path):
    csv_path = _write_csv(tmp_path / "bad.csv", "a\n=1+1\n")

    @validate_csv
    def process(path):
        return path

    with pytest.raises(CsvValidationError) as exc_info:
        process(csv_path)
    assert "formula" in str(exc_info.value).lower()


def test_decorator_no_arguments():
    with pytest.raises(CsvValidationError):

        @validate_csv
        def no_args():
            pass


def test_decorator_wrong_arg_type(tmp_path):
    @validate_csv
    def process(path):
        return path

    with pytest.raises(CsvValidationError):
        process(123)

    with pytest.raises(CsvValidationError):
        process(None)


def test_decorator_missing_required_arg():
    @validate_csv
    def process(path):
        return path

    with pytest.raises(CsvValidationError):
        process()


# ---------------------------------------------------------------------------
# Mode detection
# ---------------------------------------------------------------------------

def test_string_ending_with_csv_is_treated_as_path(tmp_path):
    csv_path = _write_csv(tmp_path / "data.csv", "a,b\n1,2\n")
    # Full path string that ends with .csv must be direct-call mode
    assert validate_csv(str(csv_path)) is True


def test_identifier_string_is_treated_as_arg_name(tmp_path):
    csv_path = _write_csv(tmp_path / "id.csv", "a,b\n1,2\n")

    @validate_csv("csv_path")
    def process(csv_path):
        return "ok"

    assert process(csv_path) == "ok"