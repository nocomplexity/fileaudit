# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0

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
    with pytest.raises(FileValidationError) as exc_info:
        validate_xml(XML_VALIDATION_DIR / filename)
