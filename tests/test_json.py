# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0

"""
Tests for the @validate_json decorator and secure JSON loading.
"""

import json
from pathlib import Path
import pytest

from fileaudit.json_check import validate_json


# Test data paths
current_file_directory = Path(__file__).parent
VALID_JSON = ( current_file_directory / "validationfiles" / "json" / "codeaudit_scan.json" )  # This file can NOT be parsed



@validate_json()
def load_config(filepath):
    """Example function using the decorator."""
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def test_load_config_valid_json():
    """Test that load_config works correctly with a valid JSON file."""
    validjson = str(VALID_JSON)  # or use Path object
    
    jsonfile_good = load_config(validjson)
    
    assert jsonfile_good is not None
    assert isinstance(jsonfile_good, dict)
    

def test_remote_json_check():
    """Checks OK flow for valid remote json"""
    remote_json = "https://pypi.org/pypi/codeaudit/json" 
    assert validate_json(remote_json) is True


def test_remote_json_check_error():
    """Checks OK flow for valid remote json"""
    remote_json = "https://pypi.org/pypi/codeaudid/json" 
    assert validate_json(remote_json) is False