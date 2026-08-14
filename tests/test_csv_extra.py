# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

# test_validate_csv.py

import pytest
from pathlib import Path

from fileaudit.csv_check import (
    CsvValidationError,
    _classify_input,
)



class TestInputClassification:
    """Test CSV source classification."""

    def test_https_url(self):
        source_type, source = _classify_input(
            "https://example.com/data.csv"
        )

        assert source_type == "https"
        assert source == "https://example.com/data.csv"

    def test_http_url_rejected(self):
        with pytest.raises(CsvValidationError, match="only HTTPS"):
            _classify_input(
                "http://example.com/data.csv"
            )

    def test_ftp_url_rejected(self):
        with pytest.raises(CsvValidationError, match="only HTTPS"):
            _classify_input(
                "ftp://example.com/data.csv"
            )

    def test_file_url_rejected(self):
        with pytest.raises(CsvValidationError, match="only HTTPS"):
            _classify_input(
                "file:///tmp/data.csv"
            )

    def test_local_relative_path(self):
        source_type, source = _classify_input("data.csv")

        assert source_type == "local"
        assert source == Path("data.csv")

    def test_local_absolute_path(self):
        source_type, source = _classify_input("/tmp/data.csv")

        assert source_type == "local"
        assert source == Path("/tmp/data.csv")

    def test_local_path_object(self):
        path = Path("/tmp/data.csv")

        source_type, source = _classify_input(path)

        assert source_type == "local"
        assert source == path

    #Edge cases

    def test_empty_url_rejected(self):
        with pytest.raises(CsvValidationError, match="cannot be empty"):
            _classify_input("")


    def test_invalid_https_url_rejected(self):
        with pytest.raises(CsvValidationError, match="Invalid HTTPS URL"):
            _classify_input("https:///data.csv")


    def test_https_url_with_credentials_rejected(self):
        with pytest.raises(
            CsvValidationError,
            match="username/password credentials",
        ):
            _classify_input(
                "https://user:password@example.com/data.csv"
            )
    #MS Windows should be better tested -)
    def test_windows_local_path(self):
        source_type, source = _classify_input(
            r"C:\data\file.csv"
        )

        assert source_type == "local"
        assert source == Path(r"C:\data\file.csv")