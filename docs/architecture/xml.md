# XML Validation

This section outlines specific implementation details for the `validation_xml` functionality.


In the table below outlines how functionality implemented in `validate_xml` and its underlying functions (`_validate_xml_file`, `XMLSecurityValidator`, and `HTTPSOnlyRedirectHandler`) are created:


| Check | Description | Code Implementation |
| --- | --- | --- |
| **Max File Size** | Enforces maximum XML file size (bytes) | Checks local `st_size`, HTTP `Content-Length`, and caps standard/gzipped streaming reads at `max_file_size`. |
| **Max Nesting Depth** | Prevents deeply nested elements causing stack overflow | `XMLSecurityValidator._validate_tree` enforces `depth > self.max_depth` check on stack items. |
| **Max Elements** | Limits total element count to prevent DoS | Increments `self.element_count` during traversal and raises if it exceeds `self.max_elements`. |
| **Max Attributes** | Caps attributes per element | Checks `len(element.attrib) > self.max_attributes` inside `_validate_tree`. |
| **Max Text Length** | Limits text node and attribute value sizes | Checks `element.text`, `element.tail`, and `attribute value` string lengths against `self.max_text_length`. |
| **Max Name Length** | Limits element and attribute name lengths | Validates both `element.tag` and attribute keys against `self.max_name_length`. |
| **DOCTYPE Rejection** | Blocks DTD declarations (XXE, entity expansion) | `_reject_doctype` uses regex `_DOCTYPE_RE` (`<!DOCTYPE`) to reject any document with DTD declarations. |
| **GZip Support** | Handles compressed XML with size limits | Checks for magic header `b"\x1f\x8b"` or `gzip` content-encoding and safely streams via `_read_gzip_stream` using `max_file_size`. |
| **UTF-8 Validation** | Rejects files with invalid UTF-8 encoding | Decodes with `errors="strict"` and explicitly catches `UnicodeDecodeError`. |
| **Remote File Restriction** | Strictly restricts remote access to HTTPS only | `_validate_url_scheme` and `HTTPSOnlyRedirectHandler` block non-HTTPS schemes and HTTP downgrades. |
| **Parser Hardening** | Uses defusedxml-style protections against known XML attacks | Combines custom tree traversal depth/size limits with strict DOCTYPE rejection, preventing XXE, quadratic blowup, and Billion Laughs entity expansion. |