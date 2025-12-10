# csaf-vex

[![Tests](https://github.com/RedHatProductSecurity/csaf-vex/actions/workflows/tests.yml/badge.svg)](https://github.com/RedHatProductSecurity/csaf-vex/actions/workflows/tests.yml)
[![Lint](https://github.com/RedHatProductSecurity/csaf-vex/actions/workflows/lint.yml/badge.svg)](https://github.com/RedHatProductSecurity/csaf-vex/actions/workflows/lint.yml)

A Python library for generating, parsing, and validating CSAF VEX files.

## Installation

```bash
pip install csaf-vex
```

For development:

```bash
git clone https://github.com/RedHatProductSecurity/csaf-vex.git
cd csaf-vex
uv sync --group dev --group test
```

## Usage

### CLI

Read and parse a CSAF VEX file (with verification):

```bash
csaf-vex read tests/test_files/sample-vex.json
```

Read with verbose verification output:

```bash
csaf-vex read -v tests/test_files/sample-vex.json
```

Disable verification:

```bash
csaf-vex read --no-verify tests/test_files/minimal-vex.json
```

Verify a CSAF VEX file:

```bash
# Run all verification tests
csaf-vex verify tests/test_files/sample-vex.json

# Run only CSAF compliance tests (Test Set 1)
csaf-vex verify tests/test_files/sample-vex.json --test-set csaf

# Run only data type checks (Test Set 2)
csaf-vex verify tests/test_files/sample-vex.json --test-set data

# Run specific tests by ID
csaf-vex verify tests/test_files/sample-vex.json -t 1.1 -t 2.5
```

Validate with plugins:

```bash
csaf-vex validate tests/test_files/sample-vex.json
```

See docs/plugins.md for authoring and how the plugin system works.

### Python API

```python
from csaf_vex.models import CSAFVEX

# Load from file
csafvex = CSAFVEX.from_file("path/to/document.json")

# Or load from dictionary
import json
with open("vex-file.json") as f:
    data = json.load(f)
csafvex = CSAFVEX.from_dict(data)

# Access document metadata
print(csafvex.document.title)
print(csafvex.document.publisher.name)
print(csafvex.document.tracking.id)

# Access vulnerabilities
for vuln in csafvex.vulnerabilities:
    print(f"CVE: {vuln.cve}")
    if vuln.cwe:
        print(f"  CWE: {vuln.cwe.id}")

# Access product tree
if csafvex.product_tree:
    for branch in csafvex.product_tree.branches:
        print(f"Branch: {branch.name}")

# Serialize back to dictionary
data = csafvex.to_dict()
```

### Validation (Plugins) - Python API

```python
import logging
from csaf_vex.models import CSAFVEX
from csaf_vex.validation.validator import Validator

csafvex = CSAFVEX.from_file("path/to/document.json")

# Create validator; default log level is WARNING
validator = Validator(csafvex, log_level=logging.INFO)

# Run all installed validation plugins
report = validator.run_all()
print(f"Plugins: total={report.total}, passed={report.passed_count}, failed={report.failed_count}")
for r in report.results:
    if not r.success:
        print(f"[{r.validator_name}]")
        for e in r.errors:
            print(f"  - {e.message}")

# Run a subset of plugins by name
subset = validator.run_plugins(["<PLUGIN-NAME>"])
print(f"Subset failed: {subset.failed_count}")

# List available plugin names
from csaf_vex.validation.validator import Validator
print(Validator.get_available_plugins())
```

For detailed API documentation including working with CVSS scores, PURLs, and more examples, see [docs/csafvex-usage.md](docs/csafvex-usage.md).

## Verification

The library provides comprehensive verification of CSAF VEX documents through two test sets:

- **Test Set 1 (CSAF Compliance)**: 14 tests verifying VEX Profile conformance and CSAF mandatory requirements
- **Test Set 2 (Data Type Checks)**: 16 tests verifying data format compliance, patterns, and schema constraints

### Using the Verifier

```python
from csaf_vex.verification import Verifier

# Create verifier from a file
verifier = Verifier.from_file("path/to/vex.json")

# Run all verification tests
report = verifier.run_all()

# Check results
if report.passed:
    print("All verification tests passed!")
else:
    print(f"Failed: {report.failed_count}/{report.total_tests}")
    for failure in report.failures:
        print(f"  {failure.test_id}: {failure.message}")

# Run specific test sets
csaf_report = verifier.run_csaf_compliance()   # Test Set 1 only
data_report = verifier.run_data_type_checks()  # Test Set 2 only

# Run individual tests
result = verifier.run_test("1.1")  # VEX Profile Conformance
result = verifier.run_test("2.5")  # CVE ID Format

# Get available tests
tests = Verifier.get_available_tests()
for test_id, test_name in tests.items():
    print(f"{test_id}: {test_name}")
```

### Verification Test Reference

| ID | Test Name | Description |
|----|-----------|-------------|
| 1.1 | VEX Profile Conformance | Document must have csaf_vex category and required sections |
| 1.2 | Base Mandatory Fields | Required tracking, publisher, and title fields |
| 1.3 | VEX Product Status Existence | Each vulnerability must have a product status |
| 1.4 | Vulnerability ID Existence | Each vulnerability must have CVE or IDs |
| 1.5 | Vulnerability Notes Existence | Each vulnerability must have notes |
| 1.6 | Product ID Definition (Missing) | All referenced product_ids must be defined |
| 1.7 | Product ID Definition (Multiple) | No duplicate product_id definitions |
| 1.8 | Circular Reference Check | No circular dependencies in relationships |
| 1.9 | Contradicting Product Status | Products cannot have conflicting statuses |
| 1.10 | Action Statement Requirement | known_affected products need remediations |
| 1.11 | Impact Statement Requirement | known_not_affected products need justification |
| 1.12 | Remediation Product Reference | Remediations must reference products |
| 1.13 | Flag Product Reference | Flags must reference products |
| 1.14 | Unique VEX Justification | Products can only have one VEX justification |
| 2.1 | JSON Schema Validation | Validates against CSAF 2.0 JSON schema |
| 2.2 | PURL Format | Package URL format validation |
| 2.3 | CPE Format | CPE 2.2 and 2.3 format validation |
| 2.4 | Date-Time Format | ISO 8601/RFC 3339 format validation |
| 2.5 | CVE ID Format | CVE identifier format validation |
| 2.6 | CWE ID Format | CWE identifier format validation |
| 2.7 | Language Code Format | BCP 47/RFC 5646 language code validation |
| 2.8 | Version Range Prohibition | No version ranges in product_version names |
| 2.9 | Mixed Versioning Prohibition | Consistent versioning scheme |
| 2.10 | CVSS Syntax | CVSS object schema validation |
| 2.11 | CVSS Calculation | CVSS score range validation |
| 2.12 | CVSS Vector Consistency | CVSS properties must match vectorString |
| 2.13 | File Size Soft Limit | Document should not exceed 15 MB |
| 2.14 | Array Length Soft Limit | Arrays should not exceed 100,000 items |
| 2.15 | String Length Soft Limit | Strings should not exceed field-specific limits |
| 2.16 | Initial Date Consistency | initial_release_date must match first revision |

## Development

### Installation for Development

```bash
git clone https://github.com/RedHatProductSecurity/csaf-vex.git
cd csaf-vex
uv sync --group dev --group test
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run tests with verbose output
uv run pytest -v

# Run tests with coverage report
uv run pytest --cov=csaf_vex --cov-report=term-missing

# Run specific test file
uv run pytest tests/test_csaf_compliance.py
uv run pytest tests/test_data_type_checks.py

# Run specific test class or function
uv run pytest tests/test_csaf_compliance.py::TestVEXProfileConformance
uv run pytest tests/test_csaf_compliance.py::TestVEXProfileConformance::test_valid_vex_profile
```

### Running Linter and Formatter

```bash
# Check linting issues
uv run ruff check .

# Auto-fix linting issues
uv run ruff check --fix .

# Format code
uv run ruff format .

# Check formatting without applying changes
uv run ruff format --check .
```

### Project Structure

- `src/csaf_vex/cli.py` - CLI entrypoint
- `src/csaf_vex/models/` - Internal representation models
  - `csafvex.py` - Root CSAFVEX document model
  - `document.py` - Document section models
  - `product_tree.py` - Product tree models
  - `vulnerability.py` - Vulnerability models
  - `common.py` - Shared models (Note, Reference, etc.)
- `src/csaf_vex/validation/` - Validation logic (semantic validation against external data)
- `src/csaf_vex/verification/` - Verification logic (structural and format validation)
  - `result.py` - VerificationResult and VerificationReport classes
  - `csaf_compliance.py` - Test Set 1: CSAF Standard Compliance tests
  - `data_type_checks.py` - Test Set 2: Data Type Checking tests
  - `verifier.py` - Main Verifier orchestration class
  - `schemas/` - CSAF and CVSS JSON schemas
- `tests/` - Pytest tests
  - `conftest.py` - Shared test fixtures
  - `test_csaf_compliance.py` - Tests for Test Set 1
  - `test_data_type_checks.py` - Tests for Test Set 2
  - `test_models.py` - Tests for internal representation models
  - `test_files/` - Sample CSAF VEX files for testing

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Authors

- Jakub Frejlach (jfrejlac@redhat.com)
- Juan Perez de Algaba (jperezde@redhat.com)
- George Vauter (gvauter@redhat.com)

Developed by Red Hat Product Security.
