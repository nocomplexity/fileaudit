# Change Log

All notable changes to this project will be documented in this file.

## Version 0.2.5

**Changed**

- CLI / Direct Call Exception Handling: Improved exception handling across all functions when called directly or via CLI. Exceptions are now propagated directly to the caller function rather than printed to stdout/stderr.

**Fixed**

- python_check Module: Removed print statements when `validate_python` encounters an exception, leaving exception handling entirely to the calling application. `validate_python` now returns True on success and raises an exception on failure.



## Version 0.2.4

**Added**

* Added AI/LLM policy in the "Contribute" section.

* Added validation and confirmed support for Python 3.15.

**Changed**

* Improved test scripts.

* Enhanced Python validation code.

* Made minor improvements to the output text displayed in the CLI.

**Fixed**

* Fixed GitHub Action workflow warning regarding Node.js 20 deprecation for automated documentation builds.

* Applied manual improvements and general fixes.

**Documentation**

* Improvements and updates




## Version 0.2.3

### Changed
- Relicensed the project from **GPLv3** to **Mozilla Public License version 2.0 (MPL-2.0)** with permission of all authors.
- Updated GitHub Actions CI workflows.


## Version 0.2.2

### Added
* Added `-v` or `--version` flag for CLI to display `fileaudit` version information.

### Changed

* Updated and added more comprehensive documentation across modules.
* Minor code improvements and updates for `xml_validator`.

### Fixed

* Corrected automatic documentation building script for GitHub Pages deployment.
* Test corrections and minor code improvements for `json_validator`.

### Documentation

* Expanded usage examples, API reference, and setup guides.



## Version 0.2.1


### Added
- Added Open Source Security Foundation (OpenSSF) Best Practices badge to `README.md`.

### Documentation
- Updated project manual.
- Applied text corrections and proofreading fixes to the manual.