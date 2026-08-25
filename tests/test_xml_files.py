# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Pytest suite for FileAudit XML validation. Some extra nasty xml files!

Some Test files derived from defusedxml (https://github.com/tiran/defusedxml).
Copyright (c) 2001-2006 Python Software Foundation.
Licensed under the Python Software Foundation License Version 2 (PSF-2.0).
"""

import pytest
from pathlib import Path
from fileaudit.xml_check import validate_xml, FileValidationError


XML_VALIDATION_DIR = Path(__file__).parent / "validationfiles" / "xml"


@pytest.mark.parametrize(
    "filename",
    [
        "xmlbomb.xml",
        "xmlbomb2.xml",
        "cyclic.xml",
        "external.xml",
        "expansion.xml",
        "xmlbomb3.xml",
    ],
)
def test_invalid_xml_files(filename):
    assert validate_xml(XML_VALIDATION_DIR / filename) is False


# def test_xml_bomb_check():
#     """for remote files - only https is allowed"""
#     current_file_directory = Path(__file__).parent
#     validation_file = current_file_directory / "validationfiles" / "xml" / "xmlbomb.xml"
#     result = validate_xml(validation_file)    
#     assert result is False

# def test_xml_bomb_check2():
#     """for remote files - only https is allowed"""
#     current_file_directory = Path(__file__).parent
#     validation_file = current_file_directory / "validationfiles" / "xml" / "xmlbomb2.xml"
#     result = validate_xml(validation_file)    
#     assert result is False

# def test_xml_cyclic_check():
#     """for remote files - only https is allowed"""
#     current_file_directory = Path(__file__).parent
#     validation_file = current_file_directory / "validationfiles" / "xml" / "cyclic.xml"
#     result = validate_xml(validation_file)    
#     assert result is False

# def test_xml_external_doctype_check():
#     """for remote files - only https is allowed"""
#     current_file_directory = Path(__file__).parent
#     validation_file = current_file_directory / "validationfiles" / "xml" / "external.xml"
#     result = validate_xml(validation_file)    
#     assert result is False

# def test_xml_external_exapansion():
#     """for remote files - only https is allowed"""
#     current_file_directory = Path(__file__).parent
#     validation_file = current_file_directory / "validationfiles" / "xml" / "expansion.xml"
#     result = validate_xml(validation_file)    
#     assert result is False

# def test_xml_external_bomb3():
#     """for remote files - only https is allowed"""
#     current_file_directory = Path(__file__).parent
#     validation_file = current_file_directory / "validationfiles" / "xml" / "xmlbomb3.xml"
#     result = validate_xml(validation_file)    
#     assert result is False