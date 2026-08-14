# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Minimum pytest tests for GZip file validation function.
"""

import pytest
import os
import gzip
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import the function and exceptions
from fileaudit.gz_check import _validate_gz_file, GzValidationError, GZ_READ_CHUNK_SIZE


class TestValidateGzFile:
    """Test suite for _validate_gz_file function."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = Path(self.temp_dir) / "test.gz"
        
        # Default limits for testing - increased ratios to handle well-compressed test data
        self.max_file_size = 1024 * 1024  # 1 MB
        self.max_uncompressed_ratio = 200.0  # Increased to handle well-compressed data
        self.max_uncompressed_size = 5 * 1024 * 1024  # 5 MB
    
    def teardown_method(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir)
    
    def create_gz_file(self, content, filename=None):
        """Helper to create a GZip file with content."""
        if filename is None:
            filename = self.test_file
        
        with gzip.open(filename, 'wt') as f:
            f.write(content)
        return filename
    
    # ========================================================================
    # Happy Path Tests - CORRECTED
    # ========================================================================
    
    def test_valid_gz_file(self):
        """Test validation of a valid GZip file."""
        # Use content that doesn't compress extremely well
        content = "Hello, World! " * 100  # 1400 bytes of varied content
        self.create_gz_file(content)
        
        # Should not raise any exception with higher ratio limit
        _validate_gz_file(
            self.test_file,
            max_file_size=self.max_file_size,
            max_uncompressed_ratio=self.max_uncompressed_ratio,
            max_uncompressed_size=self.max_uncompressed_size
        )
    
    def test_valid_gz_file_with_low_ratio_limit(self):
        """Test validation with a very low ratio limit (should fail)."""
        content = "A" * 10000  # Highly compressible content
        self.create_gz_file(content)
        
        # This should fail with a low ratio limit
        with pytest.raises(GzValidationError) as exc_info:
            _validate_gz_file(
                self.test_file,
                max_file_size=self.max_file_size,
                max_uncompressed_ratio=1.5,  # Very low ratio limit
                max_uncompressed_size=10 * 1024 * 1024
            )
        
        assert "Decompression ratio" in str(exc_info.value)
        assert "exceeds maximum" in str(exc_info.value)
    
    def test_valid_gz_file_large_content(self):
        """Test validation of a large valid GZip file."""
        # Use varied content that doesn't compress extremely well
        content = "".join([f"Line {i}: Some text with numbers {i}\n" for i in range(500)])
        self.create_gz_file(content)
        
        # Should handle larger content within limits
        _validate_gz_file(
            self.test_file,
            max_file_size=1024 * 1024,  # 1MB
            max_uncompressed_ratio=200.0,  # Higher ratio for test
            max_uncompressed_size=5 * 1024 * 1024  # 5MB
        )
    
    def test_valid_gz_file_with_highly_compressible_data(self):
        """Test validation with highly compressible data but high ratio limit."""
        content = "A" * 10000  # Highly compressible
        self.create_gz_file(content)
        
        # Should pass with high ratio limit
        _validate_gz_file(
            self.test_file,
            max_file_size=self.max_file_size,
            max_uncompressed_ratio=200.0,  # High enough for the test data
            max_uncompressed_size=10 * 1024 * 1024
        )
    
    def test_valid_gz_file_without_extension(self):
        """Test validation of a valid GZip file without .gz extension."""
        filepath = Path(self.temp_dir) / "test_data"
        self.create_gz_file("Some content", filename=filepath)
        
        # Should work regardless of extension
        _validate_gz_file(
            filepath,
            max_file_size=self.max_file_size,
            max_uncompressed_ratio=self.max_uncompressed_ratio,
            max_uncompressed_size=self.max_uncompressed_size
        )
    
    def test_valid_gz_file_multiple_members(self):
        """Test validation of a GZip file with multiple concatenated members."""
        filepath = self.test_file
        
        # Create multiple GZip members
        with open(filepath, 'wb') as f:
            # First member
            gz1 = gzip.GzipFile(fileobj=f, mode='wb')
            gz1.write(b"First member content")
            gz1.close()
            
            # Second member (concatenated)
            gz2 = gzip.GzipFile(fileobj=f, mode='wb')
            gz2.write(b"Second member content")
            gz2.close()
        
        # Should handle concatenated members
        _validate_gz_file(
            filepath,
            max_file_size=self.max_file_size,
            max_uncompressed_ratio=self.max_uncompressed_ratio,
            max_uncompressed_size=self.max_uncompressed_size
        )
    
    # ========================================================================
    # File Existence and Access Tests - CORRECTED
    # ========================================================================
    
    def test_file_does_not_exist(self):
        """Test validation fails when file does not exist."""
        non_existent = Path(self.temp_dir) / "nonexistent.gz"
        
        with pytest.raises(GzValidationError) as exc_info:
            _validate_gz_file(
                non_existent,
                max_file_size=self.max_file_size,
                max_uncompressed_ratio=self.max_uncompressed_ratio,
                max_uncompressed_size=self.max_uncompressed_size
            )
        
        # Check for the actual error message
        assert "File not found" in str(exc_info.value)
        assert str(non_existent) in str(exc_info.value)
    
    def test_file_is_directory(self):
        """Test validation fails when path is a directory."""
        dirpath = Path(self.temp_dir) / "test_dir"
        dirpath.mkdir()
        
        with pytest.raises(GzValidationError) as exc_info:
            _validate_gz_file(
                dirpath,
                max_file_size=self.max_file_size,
                max_uncompressed_ratio=self.max_uncompressed_ratio,
                max_uncompressed_size=self.max_uncompressed_size
            )
        
        assert "not a regular file" in str(exc_info.value)
    
    def test_empty_file(self):
        """Test validation fails on empty file."""
        # Create empty file
        self.test_file.touch()
        
        with pytest.raises(GzValidationError) as exc_info:
            _validate_gz_file(
                self.test_file,
                max_file_size=self.max_file_size,
                max_uncompressed_ratio=self.max_uncompressed_ratio,
                max_uncompressed_size=self.max_uncompressed_size
            )
        
        assert "GZip file is empty" in str(exc_info.value)
    
    # ========================================================================
    # Symbolic Link Tests
    # ========================================================================
    
    @pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), 
                        reason="O_NOFOLLOW not supported on this platform")
    def test_symbolic_link_with_o_no_follow(self):
        """Test symbolic links are rejected when O_NOFOLLOW is supported."""
        # Create a real file and a symlink to it
        real_file = Path(self.temp_dir) / "real_file.gz"
        self.create_gz_file("content", filename=real_file)
        
        symlink = Path(self.temp_dir) / "link.gz"
        symlink.symlink_to(real_file)
        
        # On platforms with O_NOFOLLOW, the open will fail
        with pytest.raises(GzValidationError) as exc_info:
            _validate_gz_file(
                symlink,
                max_file_size=self.max_file_size,
                max_uncompressed_ratio=self.max_uncompressed_ratio,
                max_uncompressed_size=self.max_uncompressed_size
            )
        
        # The error should mention the O_NOFOLLOW failure
        error_msg = str(exc_info.value)
        assert "O_NOFOLLOW" in error_msg or "symbolic" in error_msg.lower()
    
    @pytest.mark.skipif(hasattr(os, "O_NOFOLLOW"), 
                        reason="O_NOFOLLOW is supported, test requires unsupported platform")
    def test_symbolic_link_without_o_no_follow(self):
        """Test symbolic links are explicitly rejected when O_NOFOLLOW not supported."""
        # Create a real file and a symlink to it
        real_file = Path(self.temp_dir) / "real_file.gz"
        self.create_gz_file("content", filename=real_file)
        
        symlink = Path(self.temp_dir) / "link.gz"
        symlink.symlink_to(real_file)
        
        # Should explicitly reject symlinks
        with pytest.raises(GzValidationError) as exc_info:
            _validate_gz_file(
                symlink,
                max_file_size=self.max_file_size,
                max_uncompressed_ratio=self.max_uncompressed_ratio,
                max_uncompressed_size=self.max_uncompressed_size
            )
        
        assert "Symbolic links are not allowed" in str(exc_info.value)
    
    # ========================================================================
    # Size Limit Tests
    # ========================================================================
    
    def test_compressed_file_size_exceeds_limit(self):
        """Test validation fails when compressed file size exceeds limit."""
        content = "X" * 1000
        self.create_gz_file(content)
        
        # Set a very small max file size
        with pytest.raises(GzValidationError) as exc_info:
            _validate_gz_file(
                self.test_file,
                max_file_size=1,  # 1 byte limit
                max_uncompressed_ratio=self.max_uncompressed_ratio,
                max_uncompressed_size=self.max_uncompressed_size
            )
        
        assert "exceeds maximum" in str(exc_info.value)
    
    def test_uncompressed_size_exceeds_limit(self):
        """Test validation fails when uncompressed size exceeds limit."""
        content = "A" * 10000
        self.create_gz_file(content)
        
        # Set a small max uncompressed size
        with pytest.raises(GzValidationError) as exc_info:
            _validate_gz_file(
                self.test_file,
                max_file_size=self.max_file_size,
                max_uncompressed_ratio=200.0,
                max_uncompressed_size=100  # 100 bytes limit
            )
        
        assert "Uncompressed size" in str(exc_info.value)
        assert "exceeds maximum" in str(exc_info.value)
    
    def test_uncompressed_ratio_exceeds_limit(self):
        """Test validation fails when decompression ratio exceeds limit."""
        # Create content that compresses very well (high ratio)
        content = "A" * 10000
        self.create_gz_file(content)
        
        # Set a very low ratio limit
        with pytest.raises(GzValidationError) as exc_info:
            _validate_gz_file(
                self.test_file,
                max_file_size=self.max_file_size,
                max_uncompressed_ratio=1.1,  # Very low ratio limit
                max_uncompressed_size=10 * 1024 * 1024
            )
        
        assert "Decompression ratio" in str(exc_info.value)
        assert "exceeds maximum" in str(exc_info.value)
    
    # ========================================================================
    # Invalid GZip Format Tests - CORRECTED
    # ========================================================================
    
    def test_invalid_gzip_format(self):
        """Test validation fails on invalid GZip format."""
        # Write plain text (not GZip compressed)
        with open(self.test_file, 'w') as f:
            f.write("This is not a GZip file")
        
        with pytest.raises(GzValidationError) as exc_info:
            _validate_gz_file(
                self.test_file,
                max_file_size=self.max_file_size,
                max_uncompressed_ratio=self.max_uncompressed_ratio,
                max_uncompressed_size=self.max_uncompressed_size
            )
        
        assert "Invalid GZip format" in str(exc_info.value)
    
    def test_corrupted_gzip_file(self):
        """Test validation fails on corrupted GZip file."""
        # Create a GZip file then corrupt it
        self.create_gz_file("Some content")
        
        # Corrupt the file by writing garbage at the end
        with open(self.test_file, 'ab') as f:
            f.write(b"Corrupted data at the end")
        
        with pytest.raises(GzValidationError) as exc_info:
            _validate_gz_file(
                self.test_file,
                max_file_size=self.max_file_size,
                max_uncompressed_ratio=self.max_uncompressed_ratio,
                max_uncompressed_size=self.max_uncompressed_size
            )
        
        error_msg = str(exc_info.value)
        # The actual error might be "Invalid GZip format" or contain CRC error
        assert "Invalid GZip format" in error_msg or "CRC" in error_msg
    
    def test_file_modification_detection_simple(self):
        """Test detection of file modification during validation."""
        # Create a real GZip file
        content = "Some test content for validation" * 100
        self.create_gz_file(content)
        
        # Get the actual file size
        actual_size = self.test_file.stat().st_size
        
        # Create a mock for _open_gz_file to return controlled values
        with patch('fileaudit.gz_check._open_gz_file') as mock_open_gz:
            # Create mock file object
            mock_file = MagicMock()
            mock_file.fileno.return_value = 123
            mock_file.close = MagicMock()
            
            # First stat: initial size
            initial_stat = MagicMock()
            initial_stat.st_size = actual_size
            
            # Return the mock file and initial stat from _open_gz_file
            mock_open_gz.return_value = (mock_file, initial_stat)
            
            # Now mock os.fstat to simulate file change during validation
            with patch('os.fstat') as mock_fstat:
                # Second stat: modified size (different from initial)
                modified_stat = MagicMock()
                modified_stat.st_size = actual_size + 1000
                mock_fstat.return_value = modified_stat
                
                # Mock gzip.GzipFile to simulate reading data
                with patch('gzip.GzipFile') as mock_gzip:
                    mock_gzip_instance = MagicMock()
                    # Simulate reading some data
                    mock_gzip_instance.read.side_effect = [
                        b"Some test data" * 100,  # Enough data to be meaningful
                        b""  # End of file
                    ]
                    mock_gzip.return_value.__enter__.return_value = mock_gzip_instance
                    
                    # The validation should detect the file size change
                    with pytest.raises(GzValidationError) as exc_info:
                        _validate_gz_file(
                            self.test_file,
                            max_file_size=1024 * 1024,
                            max_uncompressed_ratio=200.0,
                            max_uncompressed_size=5 * 1024 * 1024
                        )
                    
                    # Check for the file modification error
                    error_msg = str(exc_info.value)
                    assert "File changed while being validated" in error_msg

        
    # ========================================================================
    # Edge Cases and Special Scenarios
    # ========================================================================
    
    def test_unicode_filename(self):
        """Test validation with Unicode filename."""
        unicode_file = Path(self.temp_dir) / "测试文件.gz"
        self.create_gz_file("Some content", filename=unicode_file)
        
        # Should handle Unicode filenames
        _validate_gz_file(
            unicode_file,
            max_file_size=self.max_file_size,
            max_uncompressed_ratio=self.max_uncompressed_ratio,
            max_uncompressed_size=self.max_uncompressed_size
        )
    
    def test_file_with_spaces_in_name(self):
        """Test validation with filename containing spaces."""
        spaced_file = Path(self.temp_dir) / "test file with spaces.gz"
        self.create_gz_file("Some content", filename=spaced_file)
        
        # Should handle spaces in filenames
        _validate_gz_file(
            spaced_file,
            max_file_size=self.max_file_size,
            max_uncompressed_ratio=self.max_uncompressed_ratio,
            max_uncompressed_size=self.max_uncompressed_size
        )
    
    def test_empty_content(self):
        """Test validation of GZip file with empty content."""
        self.create_gz_file("")  # Empty content
        
        # Should handle empty content (valid GZip)
        _validate_gz_file(
            self.test_file,
            max_file_size=self.max_file_size,
            max_uncompressed_ratio=self.max_uncompressed_ratio,
            max_uncompressed_size=self.max_uncompressed_size
        )
    
    def test_maximum_allowed_size(self):
        """Test validation with exactly the maximum allowed size."""
        # Use varied content that doesn't compress too well
        content = "".join([f"Line {i}: Some varied content with numbers {i}\n" for i in range(100)])
        self.create_gz_file(content)
        
        # Get the file size and set limits accordingly
        file_size = self.test_file.stat().st_size
        
        # Calculate expected uncompressed size (roughly the content size)
        uncompressed_size = len(content)
        
        # Set limits that will pass
        _validate_gz_file(
            self.test_file,
            max_file_size=file_size + 100,  # Slightly larger than file
            max_uncompressed_ratio=200.0,  # High ratio limit
            max_uncompressed_size=uncompressed_size + 100  # Slightly larger
        )
    
    def test_absolute_path(self):
        """Test validation with absolute path."""
        abs_path = self.test_file.absolute()
        self.create_gz_file("Some content")
        
        # Should handle absolute paths
        _validate_gz_file(
            abs_path,
            max_file_size=self.max_file_size,
            max_uncompressed_ratio=self.max_uncompressed_ratio,
            max_uncompressed_size=self.max_uncompressed_size
        )


class TestValidateGzFileExceptions:
    """Test exception handling in _validate_gz_file."""
    
    def test_re_raise_gz_validation_error(self):
        """Test that GzValidationError is re-raised properly."""
        with tempfile.NamedTemporaryFile(suffix='.gz', delete=False) as f:
            f.write(b"Invalid GZip data")
            filepath = f.name
        
        try:
            with pytest.raises(GzValidationError) as exc_info:
                _validate_gz_file(
                    filepath,
                    max_file_size=1024*1024,
                    max_uncompressed_ratio=200.0,
                    max_uncompressed_size=5*1024*1024
                )
            
            # The error should be about invalid GZip format
            assert "Invalid GZip format" in str(exc_info.value)
        finally:
            os.unlink(filepath)
    def test_oserror_handling(self):
        """Test that OSError is caught and converted to GzValidationError."""
        # Patch all the preliminary checks to pass
        with patch('os.path.exists', return_value=True):
            with patch('os.path.islink', return_value=False):
                with patch('os.path.isfile', return_value=True):
                    # Patch both possible open calls (os.open for O_NOFOLLOW and builtins.open)
                    with patch('os.open') as mock_os_open:
                        mock_os_open.side_effect = PermissionError("Permission denied")
                        
                        # Also patch builtins.open as a fallback
                        with patch('builtins.open') as mock_builtin_open:
                            mock_builtin_open.side_effect = PermissionError("Permission denied")
                            
                            with pytest.raises(GzValidationError) as exc_info:
                                _validate_gz_file(
                                    Path("/path/to/file.gz"),
                                    max_file_size=1024*1024,
                                    max_uncompressed_ratio=200.0,
                                    max_uncompressed_size=5*1024*1024
                                )
                            
                            # Check that the error message contains the expected text
                            error_msg = str(exc_info.value)
                            # The actual error message format is "Permission denied: /path/to/file.gz"
                            # or "Failed to open ... Permission denied"
                            assert "Permission denied" in error_msg
                            assert "/path/to/file.gz" in error_msg
                            