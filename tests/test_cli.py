# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Pytest tests for FileAudit CLI main() entry point.
Tests the sys.argv manipulation and command routing logic.
"""
import sys
from unittest.mock import patch, MagicMock
import pytest

# Import the module under test
# Adjust the import path based on your project structure
from fileaudit.cli import main, FileAudit


class TestMainCLIActivation:
    """Test suite for main() CLI command activation logic."""

    def test_main_no_args_shows_help(self):
        """Test that main() with no arguments displays help and exits."""
        with patch.object(sys, 'argv', ['fileaudit']):
            with patch.object(FileAudit, 'help') as mock_help:
                result = main()

                mock_help.assert_called_once()
                assert result is None  # help() returns None implicitly

    def test_main_with_file_path_inserts_check_command(self):
        """Test that a file path argument auto-inserts 'check' command."""
        with patch.object(sys, 'argv', ['fileaudit', 'app.py']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                # Verify 'check' was inserted at position 1
                assert sys.argv[1] == 'check'
                assert sys.argv[2] == 'app.py'
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_url_inserts_check_command(self):
        """Test that a URL argument auto-inserts 'check' command."""
        test_url = 'https://example.com/file.zip'
        with patch.object(sys, 'argv', ['fileaudit', test_url]):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == test_url
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_http_url_inserts_check_command(self):
        """Test that an HTTP URL argument auto-inserts 'check' command."""
        test_url = 'http://example.com/data.json'
        with patch.object(sys, 'argv', ['fileaudit', test_url]):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == test_url
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_explicit_check_command_no_insertion(self):
        """Test that explicit 'check' command does not trigger insertion."""
        with patch.object(sys, 'argv', ['fileaudit', 'check', 'app.py']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                # Should remain unchanged
                assert sys.argv == ['fileaudit', 'check', 'app.py']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_version_command(self):
        """Test that 'version' command is passed through to Fire."""
        with patch.object(sys, 'argv', ['fileaudit', 'version']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                # Should not insert 'check' since 'version' has no dot and doesn't start with http
                assert sys.argv == ['fileaudit', 'version']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_help_command(self):
        """Test that 'help' command is passed through to Fire."""
        with patch.object(sys, 'argv', ['fileaudit', 'help']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv == ['fileaudit', 'help']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_flag_argument_no_insertion(self):
        """Test that flag arguments (starting with -) don't trigger check insertion."""
        with patch.object(sys, 'argv', ['fileaudit', '--help']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv == ['fileaudit', '--help']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_json_file_extension(self):
        """Test auto-insertion with .json file extension."""
        with patch.object(sys, 'argv', ['fileaudit', 'config.json']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == 'config.json'
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_tar_gz_file_extension(self):
        """Test auto-insertion with .tar.gz file extension."""
        with patch.object(sys, 'argv', ['fileaudit', 'archive.tar.gz']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == 'archive.tar.gz'
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_tgz_file_extension(self):
        """Test auto-insertion with .tgz file extension."""
        with patch.object(sys, 'argv', ['fileaudit', 'backup.tgz']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == 'backup.tgz'
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_csv_file_extension(self):
        """Test auto-insertion with .csv file extension."""
        with patch.object(sys, 'argv', ['fileaudit', 'data.csv']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == 'data.csv'
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_xml_file_extension(self):
        """Test auto-insertion with .xml file extension."""
        with patch.object(sys, 'argv', ['fileaudit', 'data.xml']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == 'data.xml'
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_zip_file_extension(self):
        """Test auto-insertion with .zip file extension."""
        with patch.object(sys, 'argv', ['fileaudit', 'files.zip']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == 'files.zip'
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_tar_file_extension(self):
        """Test auto-insertion with .tar file extension."""
        with patch.object(sys, 'argv', ['fileaudit', 'archive.tar']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == 'archive.tar'
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_gz_file_extension(self):
        """Test auto-insertion with .gz file extension."""
        with patch.object(sys, 'argv', ['fileaudit', 'file.gz']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == 'file.gz'
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_url_containing_query_params(self):
        """Test auto-insertion with URL containing query parameters."""
        test_url = 'https://example.com/file.zip?token=abc123'
        with patch.object(sys, 'argv', ['fileaudit', test_url]):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == test_url
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_file_path_with_multiple_dots(self):
        """Test auto-insertion with file path containing multiple dots."""
        with patch.object(sys, 'argv', ['fileaudit', 'some.file.name.py']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == 'some.file.name.py'
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_fire_invocation_with_correct_class(self):
        """Test that fire.Fire is called with FileAudit class and correct name."""
        with patch.object(sys, 'argv', ['fileaudit', 'test.py']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                args, kwargs = mock_fire.call_args
                assert args[0] is FileAudit
                assert kwargs['name'] == 'fileaudit'

    def test_main_no_args_does_not_call_fire(self):
        """Test that main() with no args does not call fire.Fire (shows help instead)."""
        with patch.object(sys, 'argv', ['fileaudit']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                with patch.object(FileAudit, 'help'):
                    main()

                    mock_fire.assert_not_called()

    def test_main_with_path_without_extension_no_insertion(self):
        """Test that paths without extensions don't trigger check insertion."""
        with patch.object(sys, 'argv', ['fileaudit', 'Makefile']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                # No dot in 'Makefile', so no insertion
                assert sys.argv == ['fileaudit', 'Makefile']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_directory_path_no_insertion(self):
        """Test that directory paths don't trigger check insertion."""
        with patch.object(sys, 'argv', ['fileaudit', '/path/to/dir/']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                # Trailing slash, no typical file extension pattern
                assert sys.argv == ['fileaudit', '/path/to/dir/']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_argv_mutation_side_effect(self):
        """Test that main() correctly mutates sys.argv for Fire consumption."""
        original_argv = ['fileaudit', 'script.py']

        with patch.object(sys, 'argv', original_argv.copy()):
            with patch('fileaudit.cli.fire.Fire'):
                main()

                # After main(), sys.argv should be mutated
                assert sys.argv == ['fileaudit', 'check', 'script.py']


class TestMainEdgeCases:
    """Edge case tests for main() function."""

    def test_main_with_single_dot_argument(self):
        """Test handling of single dot argument (current directory)."""
        with patch.object(sys, 'argv', ['fileaudit', '.']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                # '.' has no extension after the dot
                assert sys.argv == ['fileaudit', '.']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_double_dot_argument(self):
        """Test handling of double dot argument (parent directory)."""
        with patch.object(sys, 'argv', ['fileaudit', '..']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv == ['fileaudit', '..']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_ftp_url_insertion(self):
        """Test that FTP URLs trigger check insertion (they contain file extensions)."""
        with patch.object(sys, 'argv', ['fileaudit', 'ftp://example.com/file.zip']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()
                
                # FTP URL has .zip extension, should insert 'check'
                assert sys.argv == ['fileaudit', 'check', 'ftp://example.com/file.zip']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_http_url_insertion(self):
        """Test that HTTP URLs trigger check insertion."""
        with patch.object(sys, 'argv', ['fileaudit', 'http://example.com/file.json']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()
                
                assert sys.argv == ['fileaudit', 'check', 'http://example.com/file.json']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_https_url_insertion(self):
        """Test that HTTPS URLs trigger check insertion."""
        with patch.object(sys, 'argv', ['fileaudit', 'https://example.com/file.xml']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()
                
                assert sys.argv == ['fileaudit', 'check', 'https://example.com/file.xml']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_ftp_url_no_extension(self):
        """Test that FTP URLs without file extensions don't trigger insertion."""
        with patch.object(sys, 'argv', ['fileaudit', 'ftp://example.com/download']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()
                
                # No file extension, so shouldn't insert 'check'
                assert sys.argv == ['fileaudit', 'ftp://example.com/download']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    
    def test_main_with_complex_url_path(self):
        """Test auto-insertion with complex URL path containing multiple dots."""
        test_url = 'https://example.com/api/v1.0/download/file.tar.gz'
        with patch.object(sys, 'argv', ['fileaudit', test_url]):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                assert sys.argv[1] == 'check'
                assert sys.argv[2] == test_url
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_with_file_starting_with_dash(self):
        """Test that files starting with dash don't get treated as flags."""
        # This is a pathological case: a file named '- unusual.txt'
        with patch.object(sys, 'argv', ['fileaudit', '-unusual.txt']):
            with patch('fileaudit.cli.fire.Fire') as mock_fire:
                main()

                # Starts with '-', so no insertion (treated as flag)
                assert sys.argv == ['fileaudit', '-unusual.txt']
                mock_fire.assert_called_once_with(FileAudit, name='fileaudit')

    def test_main_sys_argv_restore_after_test(self):
        """Verify that sys.argv mutations don't leak between tests."""
        # This test verifies our patching strategy works correctly
        original = sys.argv.copy()

        with patch.object(sys, 'argv', ['fileaudit', 'test.py']):
            with patch('fileaudit.cli.fire.Fire'):
                main()
                assert sys.argv == ['fileaudit', 'check', 'test.py']

        # After context exit, sys.argv should be restored
        assert sys.argv == original
