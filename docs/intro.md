# Introduction

[![PythonCodeAudit Badge](https://img.shields.io/badge/Python%20Code%20Audit-Security%20Verified-FF0000?style=flat-square)](https://github.com/nocomplexity/codeaudit)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14110/badge)](https://www.bestpractices.dev/projects/14110)
[![PyPI - Version](https://img.shields.io/pypi/v/fileaudit.svg)](https://pypi.org/project/fileaudit)
[![Documentation](https://img.shields.io/badge/Python%20File%20Audit%20Manual-Available-blue)](https://nocomplexity.github.io/fileaudit/intro.html)
[![License](https://img.shields.io/badge/License-GPLv3-FFD700)](https://github.com/nocomplexity/fileaudit/blob/main/docs/license.md)


**Python File Audit**: Build secure Python applications by default. Validate files before you use them.


```{image} images/ca_logo.png
:alt: logo
:width: 200px
:align: center
```

::::{grid} 2
:class-container: text-center
:gutter: 3

:::{grid-item-card}
{octicon}`light-bulb;4em;caption-text` **Getting Started**
^^^
In the Getting Started section you can find installation instructions and a high-level overview of the main concepts.
+++
```{button-ref} installation
:color: danger
Quick Start Guide
```
:::

:::{grid-item-card}
{octicon}`book;4em;caption-text` **User Guide**
^^^
Check out the User Guides for in-depth information.
+++
```{button-ref} general_use
:color: danger
User Guide
```
:::

::::
%end grid

::::{grid} 2
:class-container: text-center
:gutter: 3

:::{grid-item-card}
{octicon}`package-dependencies;4em;caption-text` **API Reference**
^^^
The API reference guide contains detailed information on all methods and checks possible. All possible with a simple decorator method `@validate_..()` or API call `validate..()`

+++
```{button-ref} reference/modules
:color: danger
API Reference
```
:::

:::{grid-item-card}
{octicon}`person-add;4em;caption-text` **Contributor's Guide**
^^^
Want to improve the documentation? Want to add a validation for another file extension? Found a bug? Improve existing functionalities?
The contributing guidelines will guide you!

+++
```{button-ref} CONTRIBUTE
:color: danger
Contribute and Join the team!
```
:::

::::
%end grid


:::{admonition} Python programs are not immune to cybersecurity threats.
:class: danger
File validation shouldn't be a **security afterthought**. Make it effortless, make it default.
:::



**Python File Audit** offers a powerful yet straightforward security solution:

* **Ease of Use**: Simple to operate for quick audits.

* **Extensibility**: Easy to customize and adapt for diverse use cases.

* **Impactful Analysis**: Powerful detection of security weaknesses that have the potential to become critical vulnerabilities.

Enjoying **Python File Audit** Support us with a [GitHub star](https://github.com/nocomplexity/fileaudit)! It’s a simple way to help others find us and contributes to a more secure Python ecosystem. ⭐️



## Features

:::{admonition} **Python File Audit** protects you from using insecure files and file-based attacks with a comprehensive set of safety checks
:class: tip

- **File size limit** – Prevents oversized files from being processed
- **GZip decompression ratio** – Guards against decompression bombs
- **Tar member count** – Limits the number of entries inside tar archives
- **Total extracted size** – Caps the overall size of extracted content
- **Individual file size** – Enforces a maximum size per extracted file
- **Path traversal protection** – Blocks `../` and absolute path tricks
- **Reject symlinks** – Disallows symbolic links
- **Reject hardlinks** – Disallows hard links
- **Reject device files** – Blocks device nodes
- **Reject FIFOs** – Blocks named pipes
- **Filename length** – Enforces a maximum filename length
- **Directory depth** – Limits how deeply nested directories can be

These checks work can be used by a simple API or adding a decorator function without changing your current code!
:::



## Background

The availability of well-maintained, open source simple file validation tools for Python code is very limited. 


:::{note}
This `Python File Audit` tool is built to be fast, lightweight, and easy to use.

:::

:::{admonition} Donate
:class: hint
Our mission is to make cybersecurity simpler and more robust. Join us in building a better open-source solution—your support makes it possible. All donations will be used strictly to fund the development and maintenance of Python Code Audit.

```{button-link} https://buy.stripe.com/5kQ6oH3dm4RO1ujaOUgbm02
:color: danger
Make A Donation
```
If you are unable to make a small donation, that’s fine. Just enjoy this tool and [spread the word](share-label)!
:::
