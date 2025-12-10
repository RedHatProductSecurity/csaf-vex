"""Tests for Test Set 2: Data Type Checking.

This module tests the data type checking verification functions (2.1-2.16).
"""

import json

from csaf_vex.verification import VerificationStatus, Verifier
from csaf_vex.verification.data_type_checks import (
    verify_cpe_format,
    verify_cve_id_format,
    verify_cvss_calculation,
    verify_cvss_syntax,
    verify_cvss_vector_consistency,
    verify_cwe_id_format,
    verify_datetime_format,
    verify_initial_date_consistency,
    verify_json_schema,
    verify_language_code_format,
    verify_mixed_versioning_prohibition,
    verify_purl_format,
    verify_soft_limit_array_length,
    verify_soft_limit_file_size,
    verify_soft_limit_string_length,
    verify_version_range_prohibition,
)


class TestJSONSchemaValidation:
    """Test 2.1: JSON Schema Validation."""

    def test_valid_document_passes_schema(self, valid_vex_document):
        """Test that a valid document passes JSON schema validation."""
        result = verify_json_schema(valid_vex_document)
        # May skip if jsonschema not installed
        assert result.status in (VerificationStatus.PASS, VerificationStatus.SKIP)
        assert result.test_id == "2.1"

    def test_invalid_document_fails_schema(self):
        """Test that an invalid document fails JSON schema validation."""
        # Document with wrong type for title (should be string)
        doc = {
            "document": {
                "category": "csaf_vex",
                "title": 12345,  # Should be string
            }
        }
        result = verify_json_schema(doc)
        # May skip if jsonschema not installed, otherwise should fail
        assert result.status in (VerificationStatus.FAIL, VerificationStatus.SKIP)


class TestPURLFormat:
    """Test 2.2: PURL Format Validation."""

    def test_valid_purl(self, document_with_purl_and_cpe):
        """Test that valid PURL passes."""
        result = verify_purl_format(document_with_purl_and_cpe)
        assert result.passed
        assert result.test_id == "2.2"

    def test_invalid_purl(self):
        """Test that invalid PURL fails."""
        doc = {
            "product_tree": {
                "full_product_names": [
                    {
                        "name": "Test",
                        "product_id": "TEST-001",
                        "product_identification_helper": {
                            "purl": "invalid-purl-format",  # Missing pkg: prefix
                        },
                    }
                ]
            }
        }
        result = verify_purl_format(doc)
        assert result.failed
        assert "invalid-purl-format" in result.details["invalid_purls"]

    def test_no_purls_skips(self):
        """Test that document without PURLs skips."""
        doc = {"product_tree": {}}
        result = verify_purl_format(doc)
        assert result.status == VerificationStatus.SKIP

    def test_various_valid_purls(self):
        """Test various valid PURL formats."""
        valid_purls = [
            "pkg:npm/example@1.0.0",
            "pkg:maven/org.example/artifact@1.0.0",
            "pkg:pypi/requests@2.28.0",
            "pkg:golang/github.com/example/repo@v1.0.0",
            "pkg:rpm/redhat/openssl@1.1.1k-6.el8",
        ]
        for purl in valid_purls:
            doc = {
                "product_tree": {
                    "full_product_names": [
                        {
                            "name": "Test",
                            "product_id": "TEST",
                            "product_identification_helper": {"purl": purl},
                        }
                    ]
                }
            }
            result = verify_purl_format(doc)
            assert result.passed, f"PURL '{purl}' should be valid"


class TestCPEFormat:
    """Test 2.3: CPE Format Validation."""

    def test_valid_cpe(self, document_with_purl_and_cpe):
        """Test that valid CPE passes."""
        result = verify_cpe_format(document_with_purl_and_cpe)
        assert result.passed
        assert result.test_id == "2.3"

    def test_invalid_cpe(self):
        """Test that invalid CPE fails."""
        doc = {
            "product_tree": {
                "full_product_names": [
                    {
                        "name": "Test",
                        "product_id": "TEST-001",
                        "product_identification_helper": {
                            "cpe": "invalid-cpe",
                        },
                    }
                ]
            }
        }
        result = verify_cpe_format(doc)
        assert result.failed

    def test_no_cpes_skips(self):
        """Test that document without CPEs skips."""
        doc = {"product_tree": {}}
        result = verify_cpe_format(doc)
        assert result.status == VerificationStatus.SKIP

    def test_various_valid_cpe_23_formats(self):
        """Test various valid CPE 2.3 (Formatted String Binding) formats."""
        valid_cpe_23 = [
            "cpe:2.3:a:example:package:1.0.0:*:*:*:*:*:*:*",
            "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",
            "cpe:2.3:h:cisco:router:1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            "cpe:2.3:a:vendor:product:1.0:update1:*:*:*:*:*:*",
            "cpe:2.3:a:redhat:openssl:1.1.1k:*:*:*:*:*:*:*",
            "cpe:2.3:*:vendor:product:*:*:*:*:*:*:*:*",
            "cpe:2.3:-:vendor:product:1.0:*:*:*:*:*:*:*",
        ]
        for cpe in valid_cpe_23:
            doc = {
                "product_tree": {
                    "full_product_names": [
                        {
                            "name": "Test",
                            "product_id": "TEST",
                            "product_identification_helper": {"cpe": cpe},
                        }
                    ]
                }
            }
            result = verify_cpe_format(doc)
            assert result.passed, f"CPE 2.3 '{cpe}' should be valid"

    def test_various_valid_cpe_22_formats(self):
        """Test various valid CPE 2.2 (URI Binding) formats."""
        valid_cpe_22 = [
            "cpe:/a:apache:http_server:2.4.49",
            "cpe:/o:microsoft:windows:10",
            "cpe:/h:cisco:router",
            "cpe:/a:vendor:product:1.0:update",
            "cpe:/a:redhat:openssl:1.1.1k",
            "cpe:/a:example:package:1.0.0",
            "cpe:/o:linux:linux_kernel:5.10",
            # Case-insensitive prefix per CSAF 2.0 schema
            "CPE:/a:vendor:product:1.0",
            "Cpe:/o:microsoft:windows:11",
        ]
        for cpe in valid_cpe_22:
            doc = {
                "product_tree": {
                    "full_product_names": [
                        {
                            "name": "Test",
                            "product_id": "TEST",
                            "product_identification_helper": {"cpe": cpe},
                        }
                    ]
                }
            }
            result = verify_cpe_format(doc)
            assert result.passed, f"CPE 2.2 '{cpe}' should be valid"

    def test_invalid_cpe_formats(self):
        """Test that invalid CPE formats fail validation."""
        invalid_cpes = [
            "cpe:2.2:a:vendor:product:1.0:*:*:*:*:*:*:*",  # Wrong version prefix
            "invalid-cpe-string",  # Not a CPE at all
            "cpe:a:vendor:product",  # Missing version prefix
            "cpe://a:vendor:product",  # Wrong separator (double slash)
            "cpe:2.3:x:vendor:product:1.0:*:*:*:*:*:*:*",  # Invalid part type 'x'
            "cpe:2.3:a:vendor",  # Too few components for CPE 2.3
            "",  # Empty string
        ]
        for cpe in invalid_cpes:
            doc = {
                "product_tree": {
                    "full_product_names": [
                        {
                            "name": "Test",
                            "product_id": "TEST",
                            "product_identification_helper": {"cpe": cpe},
                        }
                    ]
                }
            }
            result = verify_cpe_format(doc)
            assert result.failed, f"CPE '{cpe}' should be invalid"

    def test_mixed_valid_cpe_formats(self):
        """Test document with both CPE 2.2 and CPE 2.3 formats passes."""
        doc = {
            "product_tree": {
                "full_product_names": [
                    {
                        "name": "Product with CPE 2.3",
                        "product_id": "PROD-23",
                        "product_identification_helper": {
                            "cpe": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
                        },
                    },
                    {
                        "name": "Product with CPE 2.2",
                        "product_id": "PROD-22",
                        "product_identification_helper": {"cpe": "cpe:/a:vendor:product:2.0"},
                    },
                ]
            }
        }
        result = verify_cpe_format(doc)
        assert result.passed, "Document with both CPE 2.2 and 2.3 should pass"

    def test_cpe_format_detection_in_summary(self):
        """Test that CPE format detection is included in the verification summary."""
        # Test with only CPE 2.3
        doc_23 = {
            "product_tree": {
                "full_product_names": [
                    {
                        "name": "Product 1",
                        "product_id": "PROD-1",
                        "product_identification_helper": {
                            "cpe": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
                        },
                    },
                ]
            }
        }
        result_23 = verify_cpe_format(doc_23)
        assert result_23.passed
        assert "CPE 2.3: 1" in result_23.message
        assert result_23.details["cpe_23_count"] == 1
        assert result_23.details["cpe_22_count"] == 0

        # Test with only CPE 2.2
        doc_22 = {
            "product_tree": {
                "full_product_names": [
                    {
                        "name": "Product 1",
                        "product_id": "PROD-1",
                        "product_identification_helper": {"cpe": "cpe:/a:vendor:product:1.0"},
                    },
                ]
            }
        }
        result_22 = verify_cpe_format(doc_22)
        assert result_22.passed
        assert "CPE 2.2: 1" in result_22.message
        assert result_22.details["cpe_23_count"] == 0
        assert result_22.details["cpe_22_count"] == 1

        # Test with mixed formats
        doc_mixed = {
            "product_tree": {
                "full_product_names": [
                    {
                        "name": "Product 2.3",
                        "product_id": "PROD-23",
                        "product_identification_helper": {
                            "cpe": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
                        },
                    },
                    {
                        "name": "Product 2.2",
                        "product_id": "PROD-22",
                        "product_identification_helper": {"cpe": "cpe:/a:vendor:product:2.0"},
                    },
                ]
            }
        }
        result_mixed = verify_cpe_format(doc_mixed)
        assert result_mixed.passed
        assert "CPE 2.3: 1" in result_mixed.message
        assert "CPE 2.2: 1" in result_mixed.message
        assert result_mixed.details["cpe_23_count"] == 1
        assert result_mixed.details["cpe_22_count"] == 1
        assert len(result_mixed.details["cpe_23_values"]) == 1
        assert len(result_mixed.details["cpe_22_values"]) == 1


class TestDateTimeFormat:
    """Test 2.4: Date-Time Format Validation."""

    def test_valid_datetime(self, valid_vex_document):
        """Test that valid date-time passes."""
        result = verify_datetime_format(valid_vex_document)
        assert result.passed
        assert result.test_id == "2.4"

    def test_invalid_datetime(self):
        """Test that invalid date-time fails."""
        doc = {
            "document": {
                "tracking": {
                    "initial_release_date": "2025/01/01",  # Wrong format
                    "current_release_date": "2025-01-01T00:00:00.000Z",
                }
            }
        }
        result = verify_datetime_format(doc)
        assert result.failed

    def test_various_valid_datetimes(self):
        """Test various valid ISO 8601 formats."""
        valid_datetimes = [
            "2025-01-01T00:00:00Z",
            "2025-01-01T00:00:00.000Z",
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T12:30:45.123Z",
            "2025-12-31T23:59:59-05:00",
        ]
        for dt in valid_datetimes:
            doc = {"document": {"tracking": {"initial_release_date": dt}}}
            result = verify_datetime_format(doc)
            assert result.passed, f"Date-time '{dt}' should be valid"


class TestCVEIDFormat:
    """Test 2.5: CVE ID Format."""

    def test_valid_cve_id(self, valid_vex_document):
        """Test that valid CVE ID passes."""
        result = verify_cve_id_format(valid_vex_document)
        assert result.passed
        assert result.test_id == "2.5"

    def test_invalid_cve_id(self):
        """Test that invalid CVE ID fails."""
        doc = {"vulnerabilities": [{"cve": "CVE-INVALID"}]}
        result = verify_cve_id_format(doc)
        assert result.failed

    def test_various_valid_cve_ids(self):
        """Test various valid CVE ID formats."""
        valid_cves = [
            "CVE-2024-0001",
            "CVE-2025-12345",
            "CVE-1999-99999",
            "CVE-2024-1234567",
        ]
        for cve in valid_cves:
            doc = {"vulnerabilities": [{"cve": cve}]}
            result = verify_cve_id_format(doc)
            assert result.passed, f"CVE ID '{cve}' should be valid"

    def test_no_cves_skips(self):
        """Test that document without CVEs skips."""
        doc = {"vulnerabilities": []}
        result = verify_cve_id_format(doc)
        assert result.status == VerificationStatus.SKIP


class TestCWEIDFormat:
    """Test 2.6: CWE ID Format."""

    def test_valid_cwe_id(self):
        """Test that valid CWE ID passes."""
        doc = {"vulnerabilities": [{"cwe": {"id": "CWE-79", "name": "XSS"}}]}
        result = verify_cwe_id_format(doc)
        assert result.passed
        assert result.test_id == "2.6"

    def test_invalid_cwe_id(self):
        """Test that invalid CWE ID fails."""
        doc = {"vulnerabilities": [{"cwe": {"id": "CWE-INVALID", "name": "Invalid"}}]}
        result = verify_cwe_id_format(doc)
        assert result.failed

    def test_various_valid_cwe_ids(self):
        """Test various valid CWE ID formats."""
        valid_cwes = ["CWE-1", "CWE-79", "CWE-123", "CWE-12345"]
        for cwe in valid_cwes:
            doc = {"vulnerabilities": [{"cwe": {"id": cwe}}]}
            result = verify_cwe_id_format(doc)
            assert result.passed, f"CWE ID '{cwe}' should be valid"

    def test_no_cwes_skips(self):
        """Test that document without CWEs skips."""
        doc = {"vulnerabilities": []}
        result = verify_cwe_id_format(doc)
        assert result.status == VerificationStatus.SKIP


class TestLanguageCodeFormat:
    """Test 2.7: Language Code Format."""

    def test_valid_language_code(self):
        """Test that valid language code passes."""
        doc = {"document": {"lang": "en"}}
        result = verify_language_code_format(doc)
        assert result.passed
        assert result.test_id == "2.7"

    def test_invalid_language_code(self):
        """Test that invalid language code fails."""
        doc = {"document": {"lang": "123"}}
        result = verify_language_code_format(doc)
        assert result.failed

    def test_various_valid_language_codes(self):
        """Test various valid language codes."""
        valid_codes = ["en", "en-US", "de-DE", "zh-Hans", "pt-BR"]
        for code in valid_codes:
            doc = {"document": {"lang": code}}
            result = verify_language_code_format(doc)
            assert result.passed, f"Language code '{code}' should be valid"

    def test_no_language_codes_skips(self):
        """Test that document without language codes skips."""
        doc = {"document": {}}
        result = verify_language_code_format(doc)
        assert result.status == VerificationStatus.SKIP


class TestVersionRangeProhibition:
    """Test 2.8: Version Range Prohibition."""

    def test_valid_version(self, valid_vex_document):
        """Test that valid version without range passes."""
        result = verify_version_range_prohibition(valid_vex_document)
        assert result.status in (VerificationStatus.PASS, VerificationStatus.SKIP)
        assert result.test_id == "2.8"

    def test_version_with_range(self):
        """Test that version with range fails."""
        doc = {
            "product_tree": {
                "branches": [
                    {
                        "category": "product_version",
                        "name": ">= 1.0.0",  # Contains range indicator
                        "product": {"name": "Test", "product_id": "TEST"},
                    }
                ]
            }
        }
        result = verify_version_range_prohibition(doc)
        assert result.failed

    def test_various_range_indicators(self):
        """Test that various range indicators are detected."""
        range_indicators = ["< 2.0", "<= 1.5", "> 1.0", "before 2.0", "after 1.0", "1.0 or later"]
        for version in range_indicators:
            doc = {
                "product_tree": {
                    "branches": [
                        {
                            "category": "product_version",
                            "name": version,
                            "product": {"name": "Test", "product_id": "TEST"},
                        }
                    ]
                }
            }
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"Version '{version}' should be rejected"

    def test_word_boundary_no_false_positives(self):
        """Test that package names with range words are not rejected.

        Package names like 'ipsec-tools', 'nodejs-through', etc. should NOT be
        flagged even when they contain words that could indicate version ranges.
        """
        valid_package_names = [
            # Words as substrings
            "ipsec-tools-0:0.2.5-0.4.ia64",  # Contains 'to' in 'tools'
            "ipsec-tools-debuginfo-0:0.2.5-0.4.x86_64",
            "priority-queue-1.0.0",  # Contains 'prior' in 'priority'
            "sincerity-lib-1.0",  # Contains 'since' in 'sincerity'
            "tomcat-9.0.50",  # 'to' in 'tomcat'
            # Words as standalone parts of package names (not version ranges)
            "nodejs-through-0:2.3.4-4.el7aos",  # npm package 'through'
            "nodejs-after-0:0.8.2-1.el7aos",  # npm package 'after'
            "glibc-langpack-to",  # 'to' is a language code (Tonga)
            "glibc-langpack-th",  # Similar language code suffix
            "goto-statement-1.0",  # 'to' in 'goto'
            "aftermath-0.5.0",  # 'after' in 'aftermath'
            "beforehand-utils-2.0",  # 'before' in 'beforehand'
            "libthrough-2.3.1",  # 'through' in package name
            "pass-through-proxy-1.0",  # 'through' in package name
            "since-when-lib-0.1",  # 'since' in package name
            "until-done-0.2.3",  # 'until' in package name
        ]
        for version in valid_package_names:
            doc = {
                "product_tree": {
                    "branches": [
                        {
                            "category": "product_version",
                            "name": version,
                            "product": {"name": "Test", "product_id": "TEST"},
                        }
                    ]
                }
            }
            result = verify_version_range_prohibition(doc)
            assert result.passed, f"Version '{version}' should NOT be rejected (false positive)"

    def test_word_boundary_detects_actual_ranges(self):
        """Test that actual version ranges are still detected."""
        actual_range_versions = [
            # Versions with 'to' in range context
            "1.0 to 2.0",  # 'to' between versions
            "v1 to v5",  # 'to' between version identifiers
            "prior to 3.0",  # 'prior to' phrase
            "up to 3.0",  # 'up to' phrase
            # Versions with range words followed by version numbers
            "since 1.5",  # 'since' followed by version
            "until 2.0",  # 'until' followed by version
            "before 3.0",  # 'before' followed by version
            "after 1.0",  # 'after' followed by version
            # Version ranges with 'through'/'thru'
            "1.0 through 2.0",  # 'through' between versions
            "v1.0 thru v2.0",  # 'thru' between versions
            # Multi-word phrases
            "1.0 and later",
            "2.0 or earlier",
            "3.0 or above",
        ]
        for version in actual_range_versions:
            doc = {
                "product_tree": {
                    "branches": [
                        {
                            "category": "product_version",
                            "name": version,
                            "product": {"name": "Test", "product_id": "TEST"},
                        }
                    ]
                }
            }
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"Version '{version}' should be rejected as a range"

    # === Operator detection tests ===

    def test_operator_less_than(self):
        """Test detection of less-than operator."""
        invalid_versions = ["< 1.0", "<1.0", "version < 2.0", "pkg<3.0"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains '<')"
            assert result.details["invalid_versions"][0]["indicator"] == "<"

    def test_operator_greater_than(self):
        """Test detection of greater-than operator."""
        invalid_versions = ["> 1.0", ">1.0", "version > 2.0", "pkg>3.0"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains '>')"
            assert result.details["invalid_versions"][0]["indicator"] == ">"

    def test_operator_less_than_or_equal(self):
        """Test detection of less-than-or-equal operator."""
        invalid_versions = ["<= 1.0", "<=1.0", "version <= 2.0"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains '<=')"
            assert result.details["invalid_versions"][0]["indicator"] == "<="

    def test_operator_greater_than_or_equal(self):
        """Test detection of greater-than-or-equal operator."""
        invalid_versions = [">= 1.0", ">=1.0", "version >= 2.0"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains '>=')"
            assert result.details["invalid_versions"][0]["indicator"] == ">="

    def test_operator_not_equal(self):
        """Test detection of not-equal operator."""
        invalid_versions = ["!= 1.0", "!=1.0", "version != 2.0"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains '!=')"
            assert result.details["invalid_versions"][0]["indicator"] == "!="

    def test_operator_double_equal(self):
        """Test detection of double-equal operator."""
        invalid_versions = ["== 1.0", "==1.0", "version == 2.0"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains '==')"
            assert result.details["invalid_versions"][0]["indicator"] == "=="

    # === Multi-word phrase detection tests ===

    def test_phrase_and_later(self):
        """Test detection of 'and later' phrase."""
        invalid_versions = ["1.0 and later", "version 2.0 and later", "v3 and later"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'and later')"
            assert result.details["invalid_versions"][0]["indicator"] == "and later"

    def test_phrase_and_earlier(self):
        """Test detection of 'and earlier' phrase."""
        invalid_versions = ["2.0 and earlier", "version 3.0 and earlier"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'and earlier')"
            assert result.details["invalid_versions"][0]["indicator"] == "and earlier"

    def test_phrase_or_later(self):
        """Test detection of 'or later' phrase."""
        invalid_versions = ["1.0 or later", "version 2.0 or later"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'or later')"
            assert result.details["invalid_versions"][0]["indicator"] == "or later"

    def test_phrase_or_earlier(self):
        """Test detection of 'or earlier' phrase."""
        invalid_versions = ["2.0 or earlier", "version 3.0 or earlier"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'or earlier')"
            assert result.details["invalid_versions"][0]["indicator"] == "or earlier"

    def test_phrase_or_above(self):
        """Test detection of 'or above' phrase."""
        invalid_versions = ["1.0 or above", "version 2.0 or above"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'or above')"
            assert result.details["invalid_versions"][0]["indicator"] == "or above"

    def test_phrase_or_below(self):
        """Test detection of 'or below' phrase."""
        invalid_versions = ["2.0 or below", "version 3.0 or below"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'or below')"
            assert result.details["invalid_versions"][0]["indicator"] == "or below"

    # === Context-aware single word detection tests ===

    def test_word_to_in_version_range_context(self):
        """Test 'to' is detected when between version-like strings."""
        invalid_versions = [
            "1.0 to 2.0",
            "v1 to v2",
            "1.0.0 to 2.0.0",
            "version1 to version2",
            "0 to 10",
        ]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'to' range)"
            assert result.details["invalid_versions"][0]["indicator"] == "to"

    def test_word_to_not_in_range_context(self):
        """Test 'to' is NOT detected when not in version range context."""
        valid_versions = [
            "glibc-langpack-to",  # Language code
            "convert-to-json-1.0",  # Part of package name
            "go-to-sleep-0.1",  # Part of package name
            "how-to-guide-2.0",  # Part of package name
            "point-to-point-1.5",  # Part of package name
        ]
        for version in valid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.passed, f"'{version}' should NOT be rejected"

    def test_word_prior_to_phrase(self):
        """Test 'prior to' phrase is detected."""
        invalid_versions = ["prior to 1.0", "prior to 2.0.0", "prior to v3"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'prior to')"
            assert result.details["invalid_versions"][0]["indicator"] == "prior"

    def test_word_prior_not_in_phrase(self):
        """Test 'prior' alone in package name is NOT detected."""
        valid_versions = [
            "priority-queue-1.0",
            "a-priori-lib-2.0",
            "prior-art-checker-0.5",
        ]
        for version in valid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.passed, f"'{version}' should NOT be rejected"

    def test_word_up_to_phrase(self):
        """Test 'up to' phrase is detected."""
        invalid_versions = ["up to 1.0", "up to 2.0.0", "up to v3"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'up to')"
            assert result.details["invalid_versions"][0]["indicator"] == "to"

    def test_word_through_in_version_range_context(self):
        """Test 'through' is detected when between version-like strings."""
        invalid_versions = [
            "1.0 through 2.0",
            "v1 through v5",
            "1.0.0 through 2.0.0",
            "version1 through version3",
        ]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'through' range)"
            assert result.details["invalid_versions"][0]["indicator"] == "through"

    def test_word_through_not_in_range_context(self):
        """Test 'through' is NOT detected when not in version range context."""
        valid_versions = [
            "nodejs-through-0:2.3.4-4.el7aos",  # npm package
            "pass-through-1.0",  # Part of package name
            "walk-through-lib-2.0",  # Part of package name
            "see-through-0.5",  # Part of package name
            "breakthrough-3.0",  # Part of word
        ]
        for version in valid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.passed, f"'{version}' should NOT be rejected"

    def test_word_thru_in_version_range_context(self):
        """Test 'thru' is detected when between version-like strings."""
        invalid_versions = ["1.0 thru 2.0", "v1 thru v5", "1.0.0 thru 2.0.0"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'thru' range)"
            assert result.details["invalid_versions"][0]["indicator"] == "thru"

    def test_word_after_with_version(self):
        """Test 'after' is detected when followed by version-like string."""
        invalid_versions = ["after 1.0", "after v2", "after 1.0.0", "after version3"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'after' range)"
            assert result.details["invalid_versions"][0]["indicator"] == "after"

    def test_word_after_not_with_version(self):
        """Test 'after' is NOT detected when not followed by version."""
        valid_versions = [
            "nodejs-after-0:0.8.2-1.el7aos",  # npm package
            "aftermath-0.5.0",  # Part of word
            "afterthought-lib-1.0",  # Part of word
            "day-after-tomorrow-2.0",  # Part of package name
        ]
        for version in valid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.passed, f"'{version}' should NOT be rejected"

    def test_word_before_with_version(self):
        """Test 'before' is detected when followed by version-like string."""
        invalid_versions = ["before 1.0", "before v2", "before 1.0.0"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'before' range)"
            assert result.details["invalid_versions"][0]["indicator"] == "before"

    def test_word_before_not_with_version(self):
        """Test 'before' is NOT detected when not followed by version."""
        valid_versions = [
            "beforehand-utils-2.0",  # Part of word
            "the-day-before-1.0",  # Part of package name
            "before-sunrise-lib-0.5",  # Part of package name
        ]
        for version in valid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.passed, f"'{version}' should NOT be rejected"

    def test_word_since_with_version(self):
        """Test 'since' is detected when followed by version-like string."""
        invalid_versions = ["since 1.0", "since v2", "since 1.0.0"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'since' range)"
            assert result.details["invalid_versions"][0]["indicator"] == "since"

    def test_word_since_not_with_version(self):
        """Test 'since' is NOT detected when not followed by version."""
        valid_versions = [
            "sincerity-lib-1.0",  # Part of word
            "since-when-0.5",  # Part of package name (no digit after)
            "ever-since-lib-2.0",  # Part of package name
        ]
        for version in valid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.passed, f"'{version}' should NOT be rejected"

    def test_word_until_with_version(self):
        """Test 'until' is detected when followed by version-like string."""
        invalid_versions = ["until 1.0", "until v2", "until 1.0.0"]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (contains 'until' range)"
            assert result.details["invalid_versions"][0]["indicator"] == "until"

    def test_word_until_not_with_version(self):
        """Test 'until' is NOT detected when not followed by version."""
        valid_versions = [
            "until-done-0.2.3",  # Part of package name (no digit right after 'until')
            "wait-until-lib-1.0",  # Part of package name
        ]
        for version in valid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.passed, f"'{version}' should NOT be rejected"

    # === Real-world Red Hat VEX package names ===

    def test_redhat_vex_ipsec_tools(self):
        """Test Red Hat VEX package names from cve-2004-0164.json."""
        valid_versions = [
            "ipsec-tools-0:0.2.5-0.4.ia64",
            "ipsec-tools-debuginfo-0:0.2.5-0.4.ia64",
            "ipsec-tools-0:0.2.5-0.4.ppc",
            "ipsec-tools-0:0.2.5-0.4.s390",
            "ipsec-tools-0:0.2.5-0.4.s390x",
            "ipsec-tools-0:0.2.5-0.4.src",
            "ipsec-tools-0:0.2.5-0.4.x86_64",
        ]
        for version in valid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.passed, f"Red Hat package '{version}' should NOT be rejected"

    def test_redhat_vex_glibc_langpack(self):
        """Test Red Hat VEX package names from cve-2005-3590.json."""
        valid_versions = [
            "glibc-langpack-to",
            "glibc-langpack-th",
            "glibc-langpack-tr",
            "glibc-common",
            "glibc-headers",
            "glibc-static",
            "glibc-utils",
            "glibc-devel",
        ]
        for version in valid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.passed, f"Red Hat package '{version}' should NOT be rejected"

    def test_redhat_vex_nodejs_packages(self):
        """Test Red Hat VEX package names from cve-2015-1807.json."""
        valid_versions = [
            "nodejs-through-0:2.3.4-4.el7aos",
            "nodejs-after-0:0.8.2-1.el7aos",
            "nodejs-timed-out-0:2.0.0-3.el7aos",
            "nodejs-touch-0:1.0.0-2.el7aos",
            "nodejs-undefsafe-0:0.0.3-1.el7aos",
            "nodejs-uuid-0:2.0.1-1.el7aos",
            "jenkins-0:1.609.1-1.el6op.noarch",
        ]
        for version in valid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.passed, f"Red Hat package '{version}' should NOT be rejected"

    # === Edge cases ===

    def test_case_insensitive_detection(self):
        """Test that detection is case-insensitive."""
        invalid_versions = [
            "1.0 TO 2.0",  # Uppercase 'TO'
            "BEFORE 1.0",  # Uppercase 'BEFORE'
            "1.0 And Later",  # Mixed case
            "1.0 OR ABOVE",  # Uppercase phrase
        ]
        for version in invalid_versions:
            doc = self._make_product_version_doc(version)
            result = verify_version_range_prohibition(doc)
            assert result.failed, f"'{version}' should be rejected (case-insensitive)"

    def test_no_product_version_branches_skips(self):
        """Test that documents without product_version branches skip the check."""
        doc = {
            "product_tree": {
                "branches": [
                    {
                        "category": "product_name",  # Not product_version
                        "name": "1.0 to 2.0",  # Would be invalid if it were product_version
                        "product": {"name": "Test", "product_id": "TEST"},
                    }
                ]
            }
        }
        result = verify_version_range_prohibition(doc)
        assert result.status == VerificationStatus.SKIP

    def test_empty_branches_skips(self):
        """Test that documents with empty branches skip the check."""
        doc = {"product_tree": {"branches": []}}
        result = verify_version_range_prohibition(doc)
        assert result.status == VerificationStatus.SKIP

    def test_no_product_tree_skips(self):
        """Test that documents without product_tree skip the check."""
        doc = {"document": {"title": "Test"}}
        result = verify_version_range_prohibition(doc)
        assert result.status == VerificationStatus.SKIP

    def test_nested_product_version_branches(self):
        """Test that nested product_version branches are checked."""
        doc = {
            "product_tree": {
                "branches": [
                    {
                        "category": "vendor",
                        "name": "Red Hat",
                        "branches": [
                            {
                                "category": "product_version",
                                "name": "1.0 to 2.0",  # Invalid nested branch
                                "product": {"name": "Test", "product_id": "TEST"},
                            }
                        ],
                    }
                ]
            }
        }
        result = verify_version_range_prohibition(doc)
        assert result.failed, "Nested product_version with range should be rejected"

    def test_multiple_invalid_versions_reported(self):
        """Test that multiple invalid versions are all reported."""
        doc = {
            "product_tree": {
                "branches": [
                    {
                        "category": "product_version",
                        "name": ">= 1.0",
                        "product": {"name": "Test1", "product_id": "TEST1"},
                    },
                    {
                        "category": "product_version",
                        "name": "1.0 and later",
                        "product": {"name": "Test2", "product_id": "TEST2"},
                    },
                ]
            }
        }
        result = verify_version_range_prohibition(doc)
        assert result.failed
        assert len(result.details["invalid_versions"]) == 2

    # === Helper method ===

    def _make_product_version_doc(self, version_name: str) -> dict:
        """Create a minimal document with a product_version branch."""
        return {
            "product_tree": {
                "branches": [
                    {
                        "category": "product_version",
                        "name": version_name,
                        "product": {"name": "Test", "product_id": "TEST"},
                    }
                ]
            }
        }


class TestMixedVersioningProhibition:
    """Test 2.9: Mixed Versioning Prohibition."""

    def test_integer_versioning(self):
        """Test that homogeneous integer versioning passes."""
        doc = {
            "document": {
                "tracking": {
                    "version": "1",
                    "revision_history": [
                        {"number": "1", "date": "2025-01-01T00:00:00Z"},
                    ],
                }
            }
        }
        result = verify_mixed_versioning_prohibition(doc)
        assert result.passed
        assert result.test_id == "2.9"

    def test_semantic_versioning(self):
        """Test that homogeneous semantic versioning passes."""
        doc = {
            "document": {
                "tracking": {
                    "version": "1.0.0",
                    "revision_history": [
                        {"number": "1.0.0", "date": "2025-01-01T00:00:00Z"},
                    ],
                }
            }
        }
        result = verify_mixed_versioning_prohibition(doc)
        assert result.passed

    def test_mixed_versioning(self):
        """Test that mixed versioning fails."""
        doc = {
            "document": {
                "tracking": {
                    "version": "2",  # Integer
                    "revision_history": [
                        {"number": "1.0.0", "date": "2025-01-01T00:00:00Z"},  # Semver
                        {"number": "2", "date": "2025-01-02T00:00:00Z"},  # Integer
                    ],
                }
            }
        }
        result = verify_mixed_versioning_prohibition(doc)
        assert result.failed


class TestCVSSSyntax:
    """Test 2.10: CVSS Syntax Validation."""

    def test_valid_cvss(self, document_with_cvss):
        """Test that valid CVSS passes."""
        result = verify_cvss_syntax(document_with_cvss)
        # May skip if jsonschema not installed
        assert result.status in (VerificationStatus.PASS, VerificationStatus.SKIP)
        assert result.test_id == "2.10"

    def test_invalid_cvss_syntax(self):
        """Test that invalid CVSS vector string fails validation."""
        doc = {
            "vulnerabilities": [
                {
                    "scores": [
                        {
                            "products": ["TEST"],
                            "cvss_v3": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/INVALID/VECTOR/STRING",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        }
                    ]
                }
            ]
        }
        result = verify_cvss_syntax(doc)
        assert result.status == VerificationStatus.FAIL
        assert "errors" in result.details

    def test_no_cvss_skips(self, valid_vex_document):
        """Test that document without CVSS skips."""
        result = verify_cvss_syntax(valid_vex_document)
        assert result.status == VerificationStatus.SKIP


class TestCVSSCalculation:
    """Test 2.11: CVSS Calculation Validation."""

    def test_valid_cvss_calculation(self, document_with_cvss):
        """Test that valid CVSS calculation passes."""
        result = verify_cvss_calculation(document_with_cvss)
        assert result.passed
        assert result.test_id == "2.11"

    def test_score_mismatch_fails(self):
        """Test that score mismatch between document and computed value fails."""
        doc = {
            "vulnerabilities": [
                {
                    "scores": [
                        {
                            "products": ["TEST"],
                            "cvss_v3": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 5.0,  # Incorrect: should be 9.8
                            },
                        }
                    ]
                }
            ]
        }
        result = verify_cvss_calculation(doc)
        assert result.status == VerificationStatus.FAIL
        assert "score_mismatches" in result.details

    def test_no_cvss_skips(self):
        """Test that document without CVSS skips."""
        doc = {"vulnerabilities": []}
        result = verify_cvss_calculation(doc)
        assert result.status == VerificationStatus.SKIP


class TestCVSSVectorConsistency:
    """Test 2.12: CVSS Vector Consistency."""

    def test_consistent_cvss(self, document_with_cvss):
        """Test that consistent CVSS passes."""
        result = verify_cvss_vector_consistency(document_with_cvss)
        assert result.passed
        assert result.test_id == "2.12"

    def test_inconsistent_cvss(self):
        """Test that inconsistent CVSS properties fail."""
        doc = {
            "vulnerabilities": [
                {
                    "scores": [
                        {
                            "products": ["TEST"],
                            "cvss_v3": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "attackVector": "LOCAL",  # Contradicts AV:N in vector
                            },
                        }
                    ]
                }
            ]
        }
        result = verify_cvss_vector_consistency(doc)
        assert result.failed

    def test_no_cvss_skips(self):
        """Test that document without CVSS v3 skips."""
        doc = {"vulnerabilities": []}
        result = verify_cvss_vector_consistency(doc)
        assert result.status == VerificationStatus.SKIP


class TestSoftLimitFileSize:
    """Test 2.13: Soft Limits Check: File Size."""

    def test_small_file_passes(self, valid_vex_document):
        """Test that small file passes."""
        result = verify_soft_limit_file_size(valid_vex_document)
        assert result.passed
        assert result.test_id == "2.13"

    def test_large_file_warns(self):
        """Test that large file warns."""
        # Create a document that exceeds 15MB
        large_content = "x" * (16 * 1024 * 1024)  # 16MB
        doc = {"data": large_content}
        result = verify_soft_limit_file_size(doc, large_content)
        assert result.status == VerificationStatus.WARN


class TestSoftLimitArrayLength:
    """Test 2.14: Soft Limits Check: Array Length."""

    def test_normal_arrays_pass(self, valid_vex_document):
        """Test that normal-sized arrays pass."""
        result = verify_soft_limit_array_length(valid_vex_document)
        assert result.passed
        assert result.test_id == "2.14"

    def test_large_vulnerabilities_array_warns(self):
        """Test that oversized vulnerabilities array warns."""
        doc = {"vulnerabilities": [{"cve": f"CVE-2025-{i:04d}"} for i in range(100001)]}
        result = verify_soft_limit_array_length(doc)
        assert result.status == VerificationStatus.WARN


class TestSoftLimitStringLength:
    """Test 2.15: Soft Limits Check: String Length."""

    def test_normal_strings_pass(self, valid_vex_document):
        """Test that normal-sized strings pass."""
        result = verify_soft_limit_string_length(valid_vex_document)
        assert result.passed
        assert result.test_id == "2.15"

    def test_long_product_id_warns(self):
        """Test that oversized product_id warns."""
        doc = {
            "product_tree": {
                "full_product_names": [
                    {"name": "Test", "product_id": "x" * 1001}  # Exceeds 1000 limit
                ]
            }
        }
        result = verify_soft_limit_string_length(doc)
        assert result.status == VerificationStatus.WARN


class TestInitialDateConsistency:
    """Test 2.16: Initial Date Consistency."""

    def test_consistent_dates(self, valid_vex_document):
        """Test that consistent dates pass."""
        result = verify_initial_date_consistency(valid_vex_document)
        assert result.passed
        assert result.test_id == "2.16"

    def test_inconsistent_dates(self):
        """Test that inconsistent dates fail."""
        doc = {
            "document": {
                "tracking": {
                    "initial_release_date": "2025-01-01T00:00:00.000Z",
                    "revision_history": [
                        {
                            "number": "1",
                            "date": "2025-01-02T00:00:00.000Z",  # Different from initial
                            "summary": "First version",
                        }
                    ],
                }
            }
        }
        result = verify_initial_date_consistency(doc)
        assert result.failed

    def test_no_initial_date_skips(self):
        """Test that missing initial_release_date skips."""
        doc = {"document": {"tracking": {}}}
        result = verify_initial_date_consistency(doc)
        assert result.status == VerificationStatus.SKIP

    def test_no_revision_history_skips(self):
        """Test that missing revision_history skips."""
        doc = {
            "document": {
                "tracking": {
                    "initial_release_date": "2025-01-01T00:00:00.000Z",
                }
            }
        }
        result = verify_initial_date_consistency(doc)
        assert result.status == VerificationStatus.SKIP


class TestVerifierDataTypeChecks:
    """Integration tests for the Verifier class with data type checks."""

    def test_run_data_type_checks_on_valid_document(self, valid_vex_document):
        """Test running all data type checks on a valid document."""
        verifier = Verifier(valid_vex_document)
        report = verifier.run_data_type_checks()

        assert report.total_tests == 16
        # Check that all data type tests ran
        test_ids = {r.test_id for r in report.results}
        expected_ids = {f"2.{i}" for i in range(1, 17)}
        assert test_ids == expected_ids

    def test_run_all_on_valid_document(self, valid_vex_document):
        """Test running all tests on a valid document."""
        verifier = Verifier(valid_vex_document)
        report = verifier.run_all()

        assert report.total_tests == 30  # 14 CSAF + 16 data type
        assert report.document_id == "TEST-VEX-001"

    def test_from_json_string(self, valid_vex_document):
        """Test creating Verifier from JSON string."""
        json_str = json.dumps(valid_vex_document)
        verifier = Verifier.from_json(json_str)

        assert verifier.document_id == "TEST-VEX-001"
        report = verifier.run_all()
        assert report.total_tests == 30

    def test_from_file(self, test_files_dir):
        """Test creating Verifier from file."""
        verifier = Verifier.from_file(test_files_dir / "2022-evd-uc-05-001.json")

        assert verifier.document_id == "2022-EVD-UC-05-001"
        report = verifier.run_all()
        assert report.total_tests == 30

    def test_run_specific_tests(self, valid_vex_document):
        """Test running specific tests by ID."""
        verifier = Verifier(valid_vex_document)
        report = verifier.run_tests(["1.1", "2.5", "2.16"])

        assert report.total_tests == 3
        test_ids = {r.test_id for r in report.results}
        assert test_ids == {"1.1", "2.5", "2.16"}

    def test_report_to_dict(self, valid_vex_document):
        """Test converting report to dictionary."""
        verifier = Verifier(valid_vex_document)
        report = verifier.run_all()

        report_dict = report.to_dict()
        assert "summary" in report_dict
        assert "results" in report_dict
        assert report_dict["summary"]["total"] == 30
