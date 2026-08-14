"""
License GPL3
(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/
FileAudit - File Security Checker
"""
import os
import sys
import tempfile
import urllib.request
import urllib.error
from urllib.parse import urlparse
import fire
from fileaudit.__about__ import __version__
from fileaudit.json_check import validate_json
from fileaudit.targz_check import validate_tar_gz
from fileaudit.xml_check import validate_xml
from fileaudit.tar_check import validate_tar
from fileaudit.zip_check import validate_zip
from fileaudit.gz_check import validate_gz
from fileaudit.csv_check import validate_csv
from fileaudit.python_check import validate_python

fileaudit_ascii_art = r"""
--------------------------------
 __             _             
|_  o  |  _    |_|    _| o _|_
|   |  | (/_   | ||_|(_| |  |_
--------------------------------
"""


# Mapping of file extensions to validation functions
VALIDATORS = {
    '.json': validate_json,
    '.xml': validate_xml,
    '.csv': validate_csv,
    '.py': validate_python,
    '.zip': validate_zip,
    '.tar': validate_tar,
    '.gz': validate_gz,
    '.tgz': validate_tar_gz,
    '.tar.gz': validate_tar_gz,
}

# Supported file types for help display
SUPPORTED_TYPES = {
    'json': 'JSON files',
    'xml': 'XML files',
    'csv': 'CSV files',    
    'py': 'Python source files',
    'zip': 'ZIP archives',
    'tar': 'TAR archives',
    'gz': 'GZIP files',
    'tar-gz': 'TAR.GZ archives',
    'tgz': 'TAR.GZ archives',
}

TYPE_MAP = {
    'json': validate_json,
    'xml': validate_xml,
    'csv': validate_csv,    
    'py': validate_python,
    'zip': validate_zip,
    'tar': validate_tar,
    'gz': validate_gz,
    'tar-gz': validate_tar_gz,
    'tgz': validate_tar_gz,
}


class FileAudit:
    """🔒 Python File Audit - Secure your Python Programs with one simple line!"""

    def __init__(self):
        self.version = __version__

    def check(self, filepath, type=None):
        """
        Validate a file for security issues.

        Args:
            filepath: Path to file or URL to audit
            type: Optional manual type specification (json, xml, csv, python, zip, tar, gz, tar-gz)
        """
        if not filepath:
            print("❌ Error: Please specify a file or URL to check")
            print("Usage: fileaudit check <FILE|URL> [--type TYPE]")
            return 1

        # Check if it's a URL or local file
        is_url = filepath.startswith(('http://', 'https://'))

        # If type is specified, map to validator
        if type:
            validator = TYPE_MAP.get(type.lower())
            if not validator:
                print(f"❌ Error: Unsupported file type '{type}'")
                print(f"Supported types: {', '.join(sorted(TYPE_MAP.keys()))}")
                return 1
        else:
            # Auto-detect
            validator = self._detect_file_type(filepath)
            if not validator:
                print(f"❌ Error: Could not detect file type for '{filepath}'")
                print("Please specify file type with --type option")
                print(f"Supported types: {', '.join(sorted(SUPPORTED_TYPES.keys()))}")
                return 1

        temp_path = None
        try:
            print(f"🔍 Auditing: {filepath}")

            if is_url:
                print("📡 Downloading from remote URL...")
                temp_path = self._download_url(filepath)
                local_path = temp_path
            else:
                print("📁 Local file detected")
                if not os.path.isfile(filepath):
                    print(f"❌ Error: Local file not found: {filepath}")
                    return 1
                local_path = filepath

            # Call the validator (on a real local file)
            result = validator(local_path)

            # Treat an explicit False return value as failure
            if result is False:
                print(f"❌ Security audit failed for {filepath}")
                return 1

            print(f"✅ Security audit passed for {filepath}")
            return 0

        except Exception as e:
            print(f"❌ Security audit failed: {e}")
            return 1
        finally:
            # Always attempt to clean up the temporary file.
            if temp_path:
                try:
                    os.unlink(temp_path)
                except FileNotFoundError:
                    # Already removed; nothing to do.
                    pass  #NOSEC let is pass
                except OSError as exc:
                    # Log this rather than silently ignoring a potentially
                    # security-relevant cleanup failure.
                    print("WARNING:Failed to remove temporary file: %s", exc)


    def _download_url(self, url, timeout=30):
        """
        Download a remote URL to a temporary file.
        Raises on network / HTTP errors so the caller can report failure.
        """
        # Preserve a sensible suffix so validators that look at the extension still work
        suffix = self._get_file_extension(url) or ''
        fd, temp_path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)

        try:
            request = urllib.request.Request(
                url,
                headers={'User-Agent': f'FileAudit/{__version__}'}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                if response.status >= 400:
                    raise urllib.error.HTTPError(
                        url, response.status, response.reason, response.headers, None
                    )
                with open(temp_path, 'wb') as out:
                    while True:
                        chunk = response.read(8192)
                        if not chunk:
                            break
                        out.write(chunk)
            return temp_path
        except Exception:
            # Clean up the empty/partial temp file on any failure
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

    def _detect_file_type(self, filepath):
        """Auto-detect file type from extension"""
        ext = self._get_file_extension(filepath)
        if ext in VALIDATORS:
            return VALIDATORS[ext]
        # If no extension found or unsupported, try to detect from URL path
        if filepath.startswith(('http://', 'https://')):
            parsed = urlparse(filepath)
            path = parsed.path
            ext = self._get_file_extension(path)
            if ext in VALIDATORS:
                return VALIDATORS[ext]
        return None

    def _get_file_extension(self, filename):
        """Extract file extension, handling special cases like .tar.gz"""
        if filename.endswith('.tar.gz'):
            return '.tar.gz'
        # Handle URLs with query parameters
        if '?' in filename:
            filename = filename.split('?')[0]
        ext = os.path.splitext(filename)[1].lower()
        return ext

    def version(self):
        """Display version information"""
        print(f"FileAudit version: {__version__}")

    def help(self):
        """Show detailed help for using FileAudit tool"""
        print(fileaudit_ascii_art)
        print("Python File Audit - Secure your programs with one simple command.")
        print("Usage:")
        print("  fileaudit <command> [options]\n")
        print("Commands:")
        print("  check <FILE|URL> [--type TYPE]  Run a security audit on a local file or HTTPS URL")
        print("  version                        Print version and exit")
        print("  help                           Show this help\n")
        print("Options for check:")
        print("  --type TYPE                    Force file type instead of auto-detection")
        print("Supported types (auto-detected from extension):")
        for ftype, description in sorted(SUPPORTED_TYPES.items()):
            print(f"  {ftype:<12} {description}")
        print("\nExamples:")
        print("  fileaudit check app.py")
        print("  fileaudit check data.json")
        print("  fileaudit check https://example.com/archive.zip")
        print("  fileaudit check unknown.dat --type json")
        print("\nCheck the Documentation: https://fileaudit.nocomplexity.com")


def main():
    """Entry point for the CLI application."""
    if len(sys.argv) == 1:
        FileAudit().help()
        return

    first_arg = sys.argv[1]

    # Check if it's a URL or an existing file path
    is_file_or_url = (
        first_arg.startswith(('http://', 'https://')) or
        (os.path.isfile(first_arg) and not first_arg.startswith('-'))
    )

    # Also handle if it looks like a file with extension
    if not is_file_or_url and '.' in first_arg and not first_arg.startswith('-'):
        # Make sure it's not just '.' or '..' or a directory
        last_part = os.path.basename(first_arg)
        if last_part not in ['.', '..'] and '.' in last_part[1:]:  # Not starting with dot
            # Check if there are characters after the last dot
            dot_index = last_part.rfind('.')
            if dot_index < len(last_part) - 1:
                is_file_or_url = True

    if is_file_or_url:
        sys.argv.insert(1, 'check')

    # Run Fire and turn an integer return value into a real process exit code
    result = fire.Fire(FileAudit, name='fileaudit')
    if isinstance(result, int):
        sys.exit(result)


if __name__ == "__main__":
    main()