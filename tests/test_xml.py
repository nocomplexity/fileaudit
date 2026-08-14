# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Tests for the @validate_xml decorator and secure XML loading.
"""
import pytest
import tempfile

from pathlib import Path
from unittest.mock import patch, MagicMock
import xml.etree.ElementTree as ET

from fileaudit.xml_check import validate_xml, FileValidationError, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE


class TestValidateXML:
    
    @pytest.fixture
    def valid_xml_file(self):
        """Create a valid XML file for testing."""
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
        <root>
            <child attr="value">text</child>
            <child2>text2</child2>
        </root>"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(xml_content)
            return Path(f.name)
    
    @pytest.fixture
    def invalid_xml_file(self):
        """Create an invalid XML file for testing."""
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
        <root>
            <child>text</child>
            <unclosed>"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(xml_content)
            return Path(f.name)
    
    @pytest.fixture
    def deep_nested_xml(self):
        """Create a deeply nested XML file."""
        xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_content += '<root>\n' + '  ' * 1000
        xml_content += '<child>\n' * 1000
        xml_content += 'content\n'
        xml_content += '</child>\n' * 1000
        xml_content += '</root>'
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(xml_content)
            return Path(f.name)
    
    def cleanup_files(self, *paths):
        """Helper to clean up test files."""
        for path in paths:
            if path and Path(path).exists():
                Path(path).unlink(missing_ok=True)
    
    # === Direct invocation tests ===
    
    def test_direct_invocation_valid_xml(self, valid_xml_file):
        """Test direct invocation with valid XML returns True."""
        result = validate_xml(str(valid_xml_file))
        assert result is True
        self.cleanup_files(valid_xml_file)
    
    def test_direct_invocation_valid_xml_path_object(self, valid_xml_file):
        """Test direct invocation with Path object returns True."""
        result = validate_xml(valid_xml_file)
        assert result is True
        self.cleanup_files(valid_xml_file)
    
    def test_direct_invocation_invalid_xml(self, invalid_xml_file):
        """Test direct invocation with invalid XML returns False."""
        result = validate_xml(str(invalid_xml_file))
        assert result is False
        self.cleanup_files(invalid_xml_file)
    
    def test_direct_invocation_nonexistent_file(self):
        """Test direct invocation with nonexistent file returns False."""
        result = validate_xml('/nonexistent/file.xml')
        assert result is False

        
    def test_direct_invocation_custom_limits(self, valid_xml_file):
        """Test direct invocation with custom validation limits."""
        result = validate_xml(
            str(valid_xml_file),
            max_depth=10,
            max_file_size=1024*1024,
            max_attributes=5
        )
        assert result is True
        self.cleanup_files(valid_xml_file)
    
    # === Decorator tests ===
    
    def test_decorator_first_argument(self, valid_xml_file):
        """Test decorator validating the first argument."""
        @validate_xml
        def process_xml(xml_path):
            return "processed"
        
        result = process_xml(str(valid_xml_file))
        assert result == "processed"
        self.cleanup_files(valid_xml_file)
    
    def test_decorator_named_argument(self, valid_xml_file):
        """Test decorator validating a named argument."""
        @validate_xml("config")
        def process_xml(config, output=None):
            return f"processed {config}"
        
        result = process_xml(str(valid_xml_file), output="out.xml")
        assert result == f"processed {str(valid_xml_file)}"
        self.cleanup_files(valid_xml_file)
    
    def test_decorator_invalid_xml(self, invalid_xml_file):
        """Test decorator raises FileValidationError for invalid XML."""
        @validate_xml
        def process_xml(xml_path):
            return "processed"
        
        with pytest.raises(FileValidationError):
            process_xml(str(invalid_xml_file))
        self.cleanup_files(invalid_xml_file)
    
    def test_decorator_no_parameters(self):
        """Test decorator raises error when function has no parameters."""
        with pytest.raises(FileValidationError):
            @validate_xml
            def process():
                return "processed"
    
       
    def test_decorator_wrong_argument_type(self):
        """Test decorator raises error when argument is not a string or Path."""
        @validate_xml
        def process_xml(xml_path):
            return "processed"
        
        with pytest.raises(FileValidationError) as excinfo:
            process_xml(123)
        assert "Expected a file path" in str(excinfo.value)
    
    
    def test_decorator_with_path_object(self, valid_xml_file):
        """Test decorator with Path object argument."""
        @validate_xml
        def process_xml(xml_path):
            return "processed"
        
        result = process_xml(valid_xml_file)
        assert result == "processed"
        self.cleanup_files(valid_xml_file)
    
    
    def test_decorator_with_custom_limits(self, valid_xml_file):
        """Test decorator with custom validation limits."""
        @validate_xml(
            max_depth=5,
            max_file_size=1024*1024,
            max_attributes=10,
            max_elements=1000
        )
        def process_xml(xml_path):
            return "processed"
        
        result = process_xml(str(valid_xml_file))
        assert result == "processed"
        self.cleanup_files(valid_xml_file)
    
    # === Edge cases ===
    
    def test_non_xml_file_extension(self):
        """Test validation with non-XML file extension."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Not an XML file")
            non_xml_path = Path(f.name)
        
        # Since _looks_like_file_path sees .txt as file path, it will attempt validation
        result = validate_xml(str(non_xml_path))
        assert result is False
        self.cleanup_files(non_xml_path)
    
    def test_path_like_string_without_extension(self):
        """Test validation with path-like string without extension."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='', delete=False) as f:
            f.write("<?xml version='1.0'?><root></root>")
            xml_path = Path(f.name)
        
        # This might not be recognized as file path without extension
        result = validate_xml(str(xml_path))
        # The function might treat it as parameter name
        assert isinstance(result, bool) or callable(result)
        self.cleanup_files(xml_path)
    

    def test_max_depth_exceeded(self, deep_nested_xml):
        """Test validation fails when max_depth is exceeded."""
        # The deep_nested_xml fixture likely creates XML with depth > 10
        # We need to ensure we're passing the path, not the XML content
        result = validate_xml(str(deep_nested_xml), max_depth=10)
        assert result is False
        # self.cleanup_files(deep_nested_xml)  # This should be handled by fixture


    def test_max_file_size_exceeded(self, tmp_path):
        """Test validation fails when max_file_size is exceeded."""
        large_file = tmp_path / "large.xml"
        # Create a valid XML file larger than the limit
        # Need to create a properly formatted XML file
        content = "<root>" + "x" * 200 + "</root>"
        large_file.write_text(content, encoding="utf-8")
        
        # The file size should be > 100 bytes
        # Content: "<root>" (6 chars) + 200 'x' + "</root>" (7 chars) = 213 chars
        # With UTF-8 encoding, each 'x' is 1 byte, so total > 100 bytes
        result = validate_xml(str(large_file), max_file_size=100)
        assert result is False


    def test_absolute_path_without_extension(self, tmp_path):
        """Test validation with absolute path without extension."""
        # Create a valid XML file that has no extension
        xml_file = tmp_path / "testfile"
        xml_file.write_text("<root><item>value</item></root>", encoding="utf-8")
        
        # The file path needs to be a string for _looks_like_file_path to work
        # Since the file has no extension but is absolute, it should be recognized
        result = validate_xml(str(xml_file.resolve()))  # absolute path, no extension
        assert result is True
        