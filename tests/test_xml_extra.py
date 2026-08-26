# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0

"""
Pytest tests for FileAudit 
Some extra tests for XML validation - based on real world data / use-cases
"""

import pytest
from pathlib import Path
from fileaudit.xml_check import validate_xml, FileValidationError


def test_validate_xml_decorator_rejects_too_many_elements():
    """max_elements lower than the real element count must raise."""
    current_file_directory = Path(__file__).parent
    validation_file = current_file_directory / "validationfiles" / "xml" / "nlnetfeed.atom"

    @validate_xml  # default max_elements=10_000, feed has ~21k
    def process_xml(file_path):
        return True

    with pytest.raises(FileValidationError, match="more than 10000 elements"):
        process_xml(validation_file)

def test_validate_xml_decorator_many_elements():
    """With a high enough max_elements limit the feed must be accepted."""
    current_file_directory = Path(__file__).parent
    validation_file = current_file_directory / "validationfiles" / "xml" / "nlnetfeed.atom"

    @validate_xml(max_elements=30_000)  # feed has ~21k elements → must pass
    def process_xml(file_path):
        return True

    assert process_xml(validation_file) is True

def test_https_only_check():
    """for remote files - only https is allowed"""
    no_https_feed = "http://nocomplexity.com/rss"
    result = validate_xml(no_https_feed)    
    assert result is False