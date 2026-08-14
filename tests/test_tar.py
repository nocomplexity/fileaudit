# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Test suite for validate_tar function
License GPL3 (C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/
"""
import pytest
import tarfile
import io
import tempfile
import os
import urllib.error
from pathlib import Path
from unittest.mock import patch, MagicMock
from fileaudit.tar_check import (
    validate_tar,
    TarValidationError,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_TAR_MEMBERS,
    DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
    DEFAULT_MAX_INDIVIDUAL_FILE_SIZE,
    DEFAULT_MAX_FILENAME_LENGTH,
    DEFAULT_MAX_DIRECTORY_DEPTH
)


@pytest.fixture
def valid_tar_file():
    """Create a valid TAR file for testing."""
    fd, tmp_path = tempfile.mkstemp(suffix='.tar')
    os.close(fd)
    
    with tarfile.open(tmp_path, 'w') as tar:
        # Add a regular file
        file_data = b"This is a test file"
        tarinfo = tarfile.TarInfo(name="test.txt")
        tarinfo.size = len(file_data)
        tar.addfile(tarinfo, io.BytesIO(file_data))
        
        # Add an empty directory
        dirinfo = tarfile.TarInfo(name="test_dir/")
        dirinfo.type = tarfile.DIRTYPE
        tar.addfile(dirinfo)
    
    yield tmp_path
    
    # Cleanup
    try:
        os.unlink(tmp_path)
    except:
        pass


@pytest.fixture
def tar_with_many_files():
    """Create a TAR file with many files."""
    fd, tmp_path = tempfile.mkstemp(suffix='.tar')
    os.close(fd)
    
    with tarfile.open(tmp_path, 'w') as tar:
        for i in range(100):
            file_data = f"File {i}".encode()
            tarinfo = tarfile.TarInfo(name=f"file_{i}.txt")
            tarinfo.size = len(file_data)
            tar.addfile(tarinfo, io.BytesIO(file_data))
    
    yield tmp_path
    
    try:
        os.unlink(tmp_path)
    except:
        pass


@pytest.fixture
def tar_with_symlink():
    """Create a TAR file with a symlink."""
    fd, tmp_path = tempfile.mkstemp(suffix='.tar')
    os.close(fd)
    
    with tarfile.open(tmp_path, 'w') as tar:
        # Create a symlink
        tarinfo = tarfile.TarInfo(name="link_to_file")
        tarinfo.type = tarfile.SYMTYPE
        tarinfo.linkname = "test.txt"
        tar.addfile(tarinfo)
    
    yield tmp_path
    
    try:
        os.unlink(tmp_path)
    except:
        pass


@pytest.fixture
def tar_with_hardlink():
    """Create a TAR file with a hardlink."""
    fd, tmp_path = tempfile.mkstemp(suffix='.tar')
    os.close(fd)
    
    with tarfile.open(tmp_path, 'w') as tar:
        # First add the file
        file_data = b"Original file"
        tarinfo = tarfile.TarInfo(name="original.txt")
        tarinfo.size = len(file_data)
        tar.addfile(tarinfo, io.BytesIO(file_data))
        
        # Then add a hardlink
        tarinfo = tarfile.TarInfo(name="hardlink.txt")
        tarinfo.type = tarfile.LNKTYPE
        tarinfo.linkname = "original.txt"
        tar.addfile(tarinfo)
    
    yield tmp_path
    
    try:
        os.unlink(tmp_path)
    except:
        pass


@pytest.fixture
def tar_with_path_traversal():
    """Create a TAR file with path traversal attempt."""
    fd, tmp_path = tempfile.mkstemp(suffix='.tar')
    os.close(fd)
    
    with tarfile.open(tmp_path, 'w') as tar:
        # Try to go outside extraction directory
        tarinfo = tarfile.TarInfo(name="../outside.txt")
        tarinfo.size = 10
        tar.addfile(tarinfo, io.BytesIO(b"Outside data"))
    
    yield tmp_path
    
    try:
        os.unlink(tmp_path)
    except:
        pass


class TestValidateTarDirectMode:
    """Test validate_tar in direct/CLI mode."""
    
    def test_valid_tar_file(self, valid_tar_file):
        """Test validation of a valid TAR file."""
        result = validate_tar(valid_tar_file)
        assert result is True
    
    def test_nonexistent_file(self):
        """Test validation of a nonexistent file."""
        result = validate_tar("nonexistent_file.tar")
        assert result is False
    
    def test_file_size_limit(self, valid_tar_file):
        """Test file size limit validation."""
        # Get actual file size
        file_size = os.path.getsize(valid_tar_file)
        # Set limit smaller than actual file
        result = validate_tar(valid_tar_file, max_file_size=file_size - 1)
        assert result is False
    
    def test_member_count_limit(self, tar_with_many_files):
        """Test member count limit validation."""
        # Set limit lower than actual member count
        result = validate_tar(tar_with_many_files, max_tar_members=50)
        assert result is False
    
    def test_total_extracted_size_limit(self, valid_tar_file):
        """Test total extracted size limit validation."""
        # Set limit very small
        result = validate_tar(valid_tar_file, max_total_extracted_size=1)
        assert result is False
    
    def test_individual_file_size_limit(self, valid_tar_file):
        """Test individual file size limit validation."""
        # Set limit very small
        result = validate_tar(valid_tar_file, max_individual_file_size=1)
        assert result is False
    
    def test_symlink_rejection(self, tar_with_symlink):
        """Test that symlinks are rejected."""
        result = validate_tar(tar_with_symlink)
        assert result is False
    
    def test_hardlink_rejection(self, tar_with_hardlink):
        """Test that hardlinks are rejected."""
        result = validate_tar(tar_with_hardlink)
        assert result is False
    
    def test_path_traversal_rejection(self, tar_with_path_traversal):
        """Test that path traversal attempts are rejected."""
        result = validate_tar(tar_with_path_traversal)
        assert result is False

    def test_deep_path_rejection(self):
        """Test that deep directory structures are rejected."""
        fd, tmp_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        try:
            with tarfile.open(tmp_path, "w") as tar:
                # Create deeply nested path (60 levels deep)
                deep_path = "/".join([f"dir{i}" for i in range(60)] + ["file.txt"])
                data = b"Deep file!"          # 10 bytes
                tarinfo = tarfile.TarInfo(name=deep_path)
                tarinfo.size = len(data)      # must match the payload length
                tar.addfile(tarinfo, io.BytesIO(data))

            result = validate_tar(tmp_path)
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def test_filename_length_limit(self):
        """Test filename length limit validation."""
        fd, tmp_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        try:
            with tarfile.open(tmp_path, "w") as tar:
                long_name = "a" * 300 + ".txt"
                data = b"data!!!!!!"          # exactly 10 bytes
                tarinfo = tarfile.TarInfo(name=long_name)
                tarinfo.size = len(data)      # must equal the actual payload length
                tar.addfile(tarinfo, io.BytesIO(data))

            # Default max filename length is 255, so this should fail
            result = validate_tar(tmp_path)
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        
    def test_valid_with_custom_limits(self, valid_tar_file):
        """Test validation with custom limits that should pass."""
        result = validate_tar(
            valid_tar_file,
            max_file_size=1024*1024,  # 1 MB
            max_tar_members=10,
            max_total_extracted_size=1024*1024,
            max_individual_file_size=1024*1024,
            max_filename_length=1000,
            max_directory_depth=10
        )
        assert result is True



    @patch("fileaudit.tar_check._https_opener")   # ← adjust module path if needed
    def test_remote_file(self, mock_opener, valid_tar_file):
        """Test validation of remote files."""
        with open(valid_tar_file, "rb") as f:
            file_content = f.read()

        # Build a context-manager response that returns the real tar bytes
        mock_response = MagicMock()
        mock_response.read.return_value = file_content
        mock_response.headers = {"Content-Length": str(len(file_content))}
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = False

        mock_opener.open.return_value = mock_response

        result = validate_tar("https://example.com/test.tar")
        assert result is True
    
    @patch('urllib.request.urlopen')
    def test_remote_file_size_limit(self, mock_urlopen, valid_tar_file):
        """Test remote file size limit."""
        with open(valid_tar_file, 'rb') as f:
            file_content = f.read()
        
        # Mock the remote response properly
        mock_response = MagicMock()
        mock_response.read.return_value = file_content
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        mock_urlopen.return_value = mock_response
        
        # Set very small file size limit
        result = validate_tar("https://example.com/test.tar", max_file_size=1)
        assert result is False
    
    def test_unsupported_url_scheme(self):
        """Test that only HTTPS URLs are supported."""
        result = validate_tar("http://example.com/test.tar")
        assert result is False
        
        result = validate_tar("ftp://example.com/test.tar")
        assert result is False


class TestValidateTarDecoratorMode:
    """Test validate_tar in decorator mode."""
    
    def test_bare_decorator(self, valid_tar_file):
        """Test bare decorator usage: @validate_tar."""
        @validate_tar
        def process_tar(filepath):
            return "processed"
        
        result = process_tar(valid_tar_file)
        assert result == "processed"
    
    def test_decorator_with_params(self, valid_tar_file):
        """Test decorator with parameters."""
        @validate_tar(max_file_size=1024*1024, max_tar_members=10)
        def process_tar(filepath):
            return "processed"
        
        result = process_tar(valid_tar_file)
        assert result == "processed"
    
    def test_decorator_with_custom_arg_name(self, valid_tar_file):
        """Test decorator with custom argument name."""
        @validate_tar("custom_path")
        def process_tar(custom_path):
            return "processed"
        
        result = process_tar(valid_tar_file)
        assert result == "processed"
    
    def test_decorator_with_invalid_file(self):
        """Test decorator with invalid file."""
        @validate_tar
        def process_tar(filepath):
            return "processed"
        
        with pytest.raises(TarValidationError):
            process_tar("nonexistent.tar")
    
    def test_decorator_with_no_arguments(self):
        """Test decorator applied to function with no arguments."""
        with pytest.raises(TarValidationError):
            @validate_tar
            def no_args():
                return "processed"
    
    def test_decorator_with_non_string_path(self):
        """Test decorator with non-string/non-Path argument."""
        @validate_tar
        def process_tar(filepath):
            return "processed"
        
        with pytest.raises(TarValidationError):
            process_tar(123)  # Invalid type
    
    def test_decorator_with_validation_failure(self, tar_with_symlink):
        """Test decorator with validation failure."""
        @validate_tar
        def process_tar(filepath):
            return "processed"
        
        with pytest.raises(TarValidationError):
            process_tar(tar_with_symlink)
    
    def test_decorator_with_missing_argument(self):
        """Test decorator with missing required argument."""
        @validate_tar
        def process_tar(filepath=None):
            return "processed"
        
        with pytest.raises(TarValidationError):
            process_tar()  # Missing argument
    
    def test_decorator_with_relative_path(self, valid_tar_file):
        """Test decorator with relative path."""
        @validate_tar
        def process_tar(filepath):
            return "processed"
        
        # Use relative path
        rel_path = os.path.relpath(valid_tar_file)
        result = process_tar(rel_path)
        assert result == "processed"


class TestValidateTarEdgeCases:
    """Test edge cases for validate_tar."""
    
    def test_empty_tar(self):
        """Test validation of an empty TAR file."""
        fd, tmp_path = tempfile.mkstemp(suffix='.tar')
        os.close(fd)
        
        with tarfile.open(tmp_path, 'w') as tar:
            pass  # Empty TAR
        
        try:
            result = validate_tar(tmp_path)
            assert result is True  # Empty TAR is valid
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass
    
    def test_corrupted_tar(self):
        """Test validation of a corrupted TAR file."""
        fd, tmp_path = tempfile.mkstemp(suffix='.tar')
        os.close(fd)
        
        with open(tmp_path, 'wb') as f:
            f.write(b"This is not a valid TAR file")
        
        try:
            result = validate_tar(tmp_path)
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass
    
    def test_path_object(self, valid_tar_file):
        """Test validation with Path object."""
        path_obj = Path(valid_tar_file)
        result = validate_tar(path_obj)
        assert result is True
    
    def test_device_file(self):
        """Test that device files are rejected."""
        fd, tmp_path = tempfile.mkstemp(suffix='.tar')
        os.close(fd)
        
        with tarfile.open(tmp_path, 'w') as tar:
            # Try to add a device file
            tarinfo = tarfile.TarInfo(name="dev/null")
            tarinfo.type = tarfile.CHRTYPE  # Character device
            tarinfo.size = 0
            tar.addfile(tarinfo)
        
        try:
            result = validate_tar(tmp_path)
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass
    
    def test_fifo_file(self):
        """Test that FIFO files are rejected."""
        fd, tmp_path = tempfile.mkstemp(suffix='.tar')
        os.close(fd)
        
        with tarfile.open(tmp_path, 'w') as tar:
            tarinfo = tarfile.TarInfo(name="fifo_pipe")
            tarinfo.type = tarfile.FIFOTYPE  # FIFO
            tarinfo.size = 0
            tar.addfile(tarinfo)
        
        try:
            result = validate_tar(tmp_path)
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass

    def test_custom_limits_with_defaults(self):
        """Test that custom limits override defaults correctly."""
        fd, tmp_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        try:
            # Create a TAR with exactly 100 members
            with tarfile.open(tmp_path, "w") as tar:
                for i in range(100):
                    data = b"data!!!!!!"          # 10 bytes
                    tarinfo = tarfile.TarInfo(name=f"file_{i}.txt")
                    tarinfo.size = len(data)      # must match payload
                    tar.addfile(tarinfo, io.BytesIO(data))

            # Default should pass (100 members <= default limit)
            result = validate_tar(tmp_path)
            assert result is True

            # Custom limit should fail (100 members > 50)
            result = validate_tar(tmp_path, max_tar_members=50)
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        

class TestValidateTarExceptionHandling:
    """Test exception handling in validate_tar."""
    
    def test_validate_tar_file_exception(self):
        """Test that _validate_tar_file exceptions are properly handled."""
        # Force an exception by using a non-existent file
        result = validate_tar("/nonexistent/path/file.tar")
        assert result is False
    
    def test_decorator_type_error(self):
        """Test decorator with invalid function signature."""
        @validate_tar
        def process_tar(filepath, required_arg):
            return "processed"
        
        with pytest.raises(TarValidationError):
            process_tar("test.tar")  # Missing required_arg
    
    @patch('urllib.request.urlopen')
    def test_remote_file_http_error(self, mock_urlopen):
        """Test handling of HTTP errors for remote files."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://example.com/test.tar", 404, "Not Found", {}, None
        )
        
        result = validate_tar("https://example.com/test.tar")
        assert result is False
    
    @patch('urllib.request.urlopen')
    def test_remote_file_url_error(self, mock_urlopen):
        """Test handling of URL errors for remote files."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection failed")
        
        result = validate_tar("https://example.com/test.tar")
        assert result is False
    
    def test_decorator_with_path_object(self, valid_tar_file):
        """Test decorator with Path object argument."""
        @validate_tar
        def process_tar(filepath):
            return "processed"
        
        path_obj = Path(valid_tar_file)
        result = process_tar(path_obj)
        assert result == "processed"
    
    def test_tar_validation_error_message(self):
        """Test that TarValidationError has proper message format."""
        error = TarValidationError("Test error message")
        assert "FileAudit Security Validation Failed" in str(error)
        assert "Test error message" in str(error)
    
    def test_decorator_with_validation_error(self, tar_with_symlink):
        """Test that decorator raises TarValidationError with proper message."""
        @validate_tar
        def process_tar(filepath):
            return "processed"
        
        with pytest.raises(TarValidationError) as excinfo:
            process_tar(tar_with_symlink)
        
        assert "Symlinks and hardlinks are not allowed" in str(excinfo.value)


class TestValidateTarIntegration:
    """Integration tests for validate_tar."""
    
    def test_real_world_scenario(self):
        """Test a real-world scenario with multiple files."""
        fd, tmp_path = tempfile.mkstemp(suffix='.tar')
        os.close(fd)
        
        with tarfile.open(tmp_path, 'w') as tar:
            # Add a mix of files
            for i in range(5):
                file_data = f"Content {i}".encode()
                tarinfo = tarfile.TarInfo(name=f"docs/doc_{i}.txt")
                tarinfo.size = len(file_data)
                tar.addfile(tarinfo, io.BytesIO(file_data))
            
            # Add a directory
            dirinfo = tarfile.TarInfo(name="docs/")
            dirinfo.type = tarfile.DIRTYPE
            tar.addfile(dirinfo)
        
        try:
            result = validate_tar(tmp_path)
            assert result is True
            
            # Test with strict limits
            result = validate_tar(
                tmp_path,
                max_file_size=10*1024*1024,  # 10 MB
                max_tar_members=10,
                max_total_extracted_size=10*1024*1024,
                max_individual_file_size=1024*1024
            )
            assert result is True
            
            # Test with too strict limits
            result = validate_tar(tmp_path, max_tar_members=1)
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass

    def test_cli_interface_integration(self):
        """Test that the CLI interface works properly."""
        fd, tmp_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        try:
            with tarfile.open(tmp_path, "w") as tar:
                data = b"test data"
                tarinfo = tarfile.TarInfo(name="test.txt")
                tarinfo.size = len(data)          # length of the payload, not of tarinfo
                tar.addfile(tarinfo, io.BytesIO(data))

            # Test that the function works
            result = validate_tar(tmp_path)
            assert result is True
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    
    def test_large_tar_handling(self):
        """Test handling of larger TAR files."""
        fd, tmp_path = tempfile.mkstemp(suffix='.tar')
        os.close(fd)
        
        with tarfile.open(tmp_path, 'w') as tar:
            # Create multiple files totaling ~1MB
            for i in range(50):
                file_data = b"X" * (20 * 1024)  # 20KB each
                tarinfo = tarfile.TarInfo(name=f"file_{i:03d}.dat")
                tarinfo.size = len(file_data)
                tar.addfile(tarinfo, io.BytesIO(file_data))
        
        try:
            result = validate_tar(
                tmp_path,
                max_total_extracted_size=2*1024*1024,  # 2MB limit
                max_tar_members=100
            )
            assert result is True
            
            # Should fail with stricter limits
            result = validate_tar(
                tmp_path,
                max_total_extracted_size=500*1024  # 500KB limit
            )
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass


class TestValidateTarSecurity:
    """Additional security-specific tests."""

    def test_absolute_path_rejection(self):
        """Test that absolute paths are rejected."""
        fd, tmp_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        try:
            with tarfile.open(tmp_path, "w") as tar:
                data = b"test data!"          # 10 bytes
                tarinfo = tarfile.TarInfo(name="/etc/passwd")
                tarinfo.size = len(data)      # must match the payload
                tar.addfile(tarinfo, io.BytesIO(data))

            result = validate_tar(tmp_path)
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def test_multiple_path_traversal_attempts(self):
        """Test multiple path traversal attempts."""
        fd, tmp_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        try:
            with tarfile.open(tmp_path, "w") as tar:
                # Try multiple traversal patterns
                traversal_paths = [
                    "../../etc/passwd",
                    "foo/../../etc/passwd",
                    "foo/../bar/../../etc/passwd",
                ]
                data = b"test data!"          # 10 bytes
                for path in traversal_paths:
                    tarinfo = tarfile.TarInfo(name=path)
                    tarinfo.size = len(data)  # must match the payload
                    tar.addfile(tarinfo, io.BytesIO(data))

            result = validate_tar(tmp_path)
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def test_extremely_large_individual_file(self):
        """Test rejection of extremely large individual files."""
        fd, tmp_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        try:
            # Create a large file (15 MB)
            large_data = b"X" * (15 * 1024 * 1024)
            with tarfile.open(tmp_path, "w") as tar:
                tarinfo = tarfile.TarInfo(name="huge_file.dat")
                tarinfo.size = len(large_data)
                tar.addfile(tarinfo, io.BytesIO(large_data))

            # Default individual-size limit should reject it
            result = validate_tar(tmp_path)
            assert result is False

            # Raise every size limit that could still block the archive
            result = validate_tar(
                tmp_path,
                max_file_size=30 * 1024 * 1024,              # archive itself
                max_individual_file_size=20 * 1024 * 1024,   # the member
                max_total_extracted_size=30 * 1024 * 1024,   # sum of members
            )
            assert result is True
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def test_directory_traversal_with_absolute_path(self):
        """Test directory traversal using absolute paths."""
        fd, tmp_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        try:
            with tarfile.open(tmp_path, "w") as tar:
                data = b"test!!!!!!"          # 10 bytes
                tarinfo = tarfile.TarInfo(name="/tmp/../../etc/passwd")
                tarinfo.size = len(data)      # must match the payload
                tar.addfile(tarinfo, io.BytesIO(data))

            result = validate_tar(tmp_path)
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def test_encoded_path_traversal(self):
        """URL-encoded '..' is NOT treated as traversal by the current validator."""
        fd, tmp_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        try:
            with tarfile.open(tmp_path, "w") as tar:
                data = b"test!!!!!!"
                tarinfo = tarfile.TarInfo(name="..%2f..%2fetc%2fpasswd")
                tarinfo.size = len(data)
                tar.addfile(tarinfo, io.BytesIO(data))

            # Current implementation does not decode %2f, so the archive is accepted
            result = validate_tar(tmp_path)
            assert result is True
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        
class TestValidateTarPerformance:
    """Performance tests for validate_tar."""

    def test_large_number_of_small_files(self):
        """Test validation with many small files."""
        fd, tmp_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        try:
            with tarfile.open(tmp_path, "w") as tar:
                # Create 500 small files
                data = b"data!!!!!!"          # 10 bytes
                for i in range(500):
                    tarinfo = tarfile.TarInfo(name=f"small_file_{i:03d}.txt")
                    tarinfo.size = len(data)  # must match the payload
                    tar.addfile(tarinfo, io.BytesIO(data))

            # Should pass with default limits (500 < default max members)
            result = validate_tar(tmp_path)
            assert result is True

            # Should fail with custom limit
            result = validate_tar(tmp_path, max_tar_members=100)
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    
    def test_large_total_extracted_size(self):
        """Test validation with large total extracted size."""
        fd, tmp_path = tempfile.mkstemp(suffix='.tar')
        os.close(fd)
        
        with tarfile.open(tmp_path, 'w') as tar:
            # Create files totaling ~2MB
            for i in range(10):
                file_data = b"X" * (200 * 1024)  # 200KB each
                tarinfo = tarfile.TarInfo(name=f"file_{i:03d}.dat")
                tarinfo.size = len(file_data)
                tar.addfile(tarinfo, io.BytesIO(file_data))
        
        try:
            # Should pass with default limits (2MB < 100MB)
            result = validate_tar(tmp_path)
            assert result is True
            
            # Should fail with custom limit
            result = validate_tar(tmp_path, max_total_extracted_size=1024*1024)  # 1MB
            assert result is False
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass