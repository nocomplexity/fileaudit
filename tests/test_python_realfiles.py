# SPDX-FileCopyrightText: 2026-present Maikel Mardjan and contributors
# SPDX-License-Identifier: MPL-2.0

from pathlib import Path
import pytest
import warnings
from fileaudit.python_check import validate_python, PythonValidationError  # adjust import if needed


def test_check_real_files():
    current_file_directory = Path(__file__).parent
    directory = current_file_directory / "validationfiles" / "python"

    # Should fail (invalid syntax)
    with pytest.raises(PythonValidationError):
        validate_python(directory / "incorrect_python_file.py")

    # Should fail (Python 2 syntax is invalid in Python 3)
    with pytest.raises(PythonValidationError):
        validate_python(directory / "python2_file_willnotwork.py")

    # Should fail (contains null byte)
    with pytest.raises(PythonValidationError):
        validate_python(directory / "sample_with_null.py")

    # Warning is succeed (valid Python – warnings are expected and irrelevant for this checker)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        assert validate_python(directory / "file_with_warnings.py") is True

    
    


