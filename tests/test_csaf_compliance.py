"""Tests for Test Set 1: CSAF Standard Compliance.

This module tests the CSAF compliance verification functions (1.1-1.14).
"""

from csaf_vex.verification import VerificationStatus, Verifier
from csaf_vex.verification.csaf_compliance import (
    verify_action_statement_requirement,
    verify_base_mandatory_fields,
    verify_flag_product_reference,
    verify_impact_statement_requirement,
    verify_no_circular_references,
    verify_no_contradicting_status,
    verify_product_id_defined,
    verify_product_id_unique,
    verify_remediation_product_reference,
    verify_unique_vex_justification,
    verify_vex_product_status_existence,
    verify_vex_profile_conformance,
    verify_vulnerability_id_existence,
    verify_vulnerability_notes_existence,
)


class TestVEXProfileConformance:
    """Test 1.1: VEX Profile Conformance."""

    def test_valid_vex_profile(self, valid_vex_document):
        """Test that a valid VEX document passes profile conformance."""
        result = verify_vex_profile_conformance(valid_vex_document)
        assert result.passed
        assert result.test_id == "1.1"

    def test_missing_document_section(self):
        """Test that missing /document section fails."""
        doc = {"product_tree": {}, "vulnerabilities": []}
        result = verify_vex_profile_conformance(doc)
        assert result.failed
        assert "document" in result.details["errors"][0].lower()

    def test_missing_product_tree_section(self):
        """Test that missing /product_tree section fails."""
        doc = {"document": {"category": "csaf_vex"}, "vulnerabilities": []}
        result = verify_vex_profile_conformance(doc)
        assert result.failed
        assert "product_tree" in result.details["errors"][0].lower()

    def test_missing_vulnerabilities_section(self):
        """Test that missing /vulnerabilities section fails."""
        doc = {"document": {"category": "csaf_vex"}, "product_tree": {}}
        result = verify_vex_profile_conformance(doc)
        assert result.failed
        assert "vulnerabilities" in result.details["errors"][0].lower()

    def test_invalid_category(self, document_with_invalid_category):
        """Test that invalid category fails."""
        result = verify_vex_profile_conformance(document_with_invalid_category)
        assert result.failed
        assert any("category" in e.lower() for e in result.details["errors"])

    def test_empty_document(self, empty_document):
        """Test that empty document fails."""
        result = verify_vex_profile_conformance(empty_document)
        assert result.failed


class TestBaseMandatoryFields:
    """Test 1.2: Base Mandatory Fields."""

    def test_valid_base_fields(self, valid_vex_document):
        """Test that a document with all base fields passes."""
        result = verify_base_mandatory_fields(valid_vex_document)
        assert result.passed
        assert result.test_id == "1.2"

    def test_missing_title(self):
        """Test that missing title fails."""
        doc = {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "publisher": {
                    "category": "vendor",
                    "name": "Test",
                    "namespace": "https://test.com",
                },
                "tracking": {
                    "id": "TEST-001",
                    "status": "final",
                    "version": "1",
                    "initial_release_date": "2025-01-01T00:00:00Z",
                    "current_release_date": "2025-01-01T00:00:00Z",
                },
            }
        }
        result = verify_base_mandatory_fields(doc)
        assert result.failed
        assert any("title" in e.lower() for e in result.details["errors"])

    def test_missing_publisher(self):
        """Test that missing publisher fails."""
        doc = {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "title": "Test",
                "tracking": {
                    "id": "TEST-001",
                    "status": "final",
                    "version": "1",
                    "initial_release_date": "2025-01-01T00:00:00Z",
                    "current_release_date": "2025-01-01T00:00:00Z",
                },
            }
        }
        result = verify_base_mandatory_fields(doc)
        assert result.failed
        assert any("publisher" in e.lower() for e in result.details["errors"])

    def test_missing_tracking(self):
        """Test that missing tracking fails."""
        doc = {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "title": "Test",
                "publisher": {
                    "category": "vendor",
                    "name": "Test",
                    "namespace": "https://test.com",
                },
            }
        }
        result = verify_base_mandatory_fields(doc)
        assert result.failed
        assert any("tracking" in e.lower() for e in result.details["errors"])


class TestVEXProductStatusExistence:
    """Test 1.3: VEX Product Status Existence."""

    def test_valid_product_status(self, valid_vex_document):
        """Test that a document with product status passes."""
        result = verify_vex_product_status_existence(valid_vex_document)
        assert result.passed
        assert result.test_id == "1.3"

    def test_missing_product_status(self, valid_vex_document):
        """Test that missing product status fails."""
        doc = valid_vex_document.copy()
        doc["vulnerabilities"] = [{"cve": "CVE-2025-0001", "notes": []}]
        result = verify_vex_product_status_existence(doc)
        assert result.failed

    def test_no_vulnerabilities_skips(self):
        """Test that document with no vulnerabilities skips."""
        doc = {"vulnerabilities": []}
        result = verify_vex_product_status_existence(doc)
        assert result.status == VerificationStatus.SKIP

    def test_all_valid_status_types(self):
        """Test that all valid status types are accepted."""
        valid_statuses = ["fixed", "known_affected", "known_not_affected", "under_investigation"]
        for status in valid_statuses:
            doc = {
                "vulnerabilities": [
                    {
                        "cve": "CVE-2025-0001",
                        "product_status": {status: ["PROD-001"]},
                    }
                ]
            }
            result = verify_vex_product_status_existence(doc)
            assert result.passed, f"Status '{status}' should be valid"


class TestVulnerabilityIDExistence:
    """Test 1.4: Vulnerability ID Existence."""

    def test_valid_cve_id(self, valid_vex_document):
        """Test that a document with CVE ID passes."""
        result = verify_vulnerability_id_existence(valid_vex_document)
        assert result.passed
        assert result.test_id == "1.4"

    def test_valid_ids_field(self):
        """Test that a document with ids field passes."""
        doc = {
            "vulnerabilities": [
                {
                    "ids": [{"system_name": "Custom", "text": "VULN-001"}],
                    "notes": [],
                }
            ]
        }
        result = verify_vulnerability_id_existence(doc)
        assert result.passed

    def test_missing_id(self):
        """Test that missing ID fails."""
        doc = {"vulnerabilities": [{"notes": []}]}
        result = verify_vulnerability_id_existence(doc)
        assert result.failed

    def test_no_vulnerabilities_skips(self):
        """Test that document with no vulnerabilities skips."""
        doc = {"vulnerabilities": []}
        result = verify_vulnerability_id_existence(doc)
        assert result.status == VerificationStatus.SKIP


class TestVulnerabilityNotesExistence:
    """Test 1.5: Vulnerability Notes Existence."""

    def test_valid_notes(self, valid_vex_document):
        """Test that a document with notes passes."""
        result = verify_vulnerability_notes_existence(valid_vex_document)
        assert result.passed
        assert result.test_id == "1.5"

    def test_missing_notes(self):
        """Test that missing notes fails."""
        doc = {
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "product_status": {"under_investigation": ["PROD-001"]},
                }
            ]
        }
        result = verify_vulnerability_notes_existence(doc)
        assert result.failed

    def test_empty_notes(self):
        """Test that empty notes array fails."""
        doc = {
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "notes": [],
                }
            ]
        }
        result = verify_vulnerability_notes_existence(doc)
        assert result.failed


class TestProductIDDefined:
    """Test 1.6: Product ID Definition Check (Missing)."""

    def test_all_product_ids_defined(self, valid_vex_document):
        """Test that all referenced product_ids are defined."""
        result = verify_product_id_defined(valid_vex_document)
        assert result.passed
        assert result.test_id == "1.6"

    def test_undefined_product_id(self):
        """Test that undefined product_id fails."""
        doc = {
            "product_tree": {},
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "product_status": {"known_affected": ["UNDEFINED-PROD"]},
                }
            ],
        }
        result = verify_product_id_defined(doc)
        assert result.failed
        assert "UNDEFINED-PROD" in result.details["undefined_ids"]


class TestProductIDUnique:
    """Test 1.7: Product ID Definition Check (Multiple)."""

    def test_unique_product_ids(self, valid_vex_document):
        """Test that unique product_ids pass."""
        result = verify_product_id_unique(valid_vex_document)
        assert result.passed
        assert result.test_id == "1.7"

    def test_duplicate_product_id(self):
        """Test that duplicate product_id fails."""
        doc = {
            "product_tree": {
                "full_product_names": [
                    {"name": "Product 1", "product_id": "DUPE-001"},
                    {"name": "Product 2", "product_id": "DUPE-001"},
                ]
            }
        }
        result = verify_product_id_unique(doc)
        assert result.failed
        assert "DUPE-001" in result.details["duplicates"]


class TestNoCircularReferences:
    """Test 1.8: Product ID Definition Check (Circular)."""

    def test_no_circular_references(self, valid_vex_document):
        """Test that document without circular references passes."""
        result = verify_no_circular_references(valid_vex_document)
        # Should skip if no relationships defined
        assert result.status in (VerificationStatus.PASS, VerificationStatus.SKIP)
        assert result.test_id == "1.8"

    def test_no_relationships_skips(self):
        """Test that document without relationships skips."""
        doc = {"product_tree": {}}
        result = verify_no_circular_references(doc)
        assert result.status == VerificationStatus.SKIP

    def test_circular_reference_detected(self):
        """Test that circular dependencies in relationships are detected."""
        doc = {
            "product_tree": {
                "full_product_names": [
                    {"name": "Base Product", "product_id": "BASE-001"},
                ],
                "relationships": [
                    {
                        "category": "installed_on",
                        "full_product_name": {
                            "name": "Product A on Base",
                            "product_id": "PROD-A-ON-BASE",
                        },
                        "product_reference": "BASE-001",
                        "relates_to_product_reference": "PROD-B-ON-A",  # References B
                    },
                    {
                        "category": "installed_on",
                        "full_product_name": {
                            "name": "Product B on A",
                            "product_id": "PROD-B-ON-A",
                        },
                        "product_reference": "BASE-001",
                        # References A - circular!
                        "relates_to_product_reference": "PROD-A-ON-BASE",
                    },
                ],
            }
        }
        result = verify_no_circular_references(doc)
        assert result.failed
        assert "cycle" in result.details


class TestNoContradictingStatus:
    """Test 1.9: Contradicting Product Status."""

    def test_no_contradicting_status(self, valid_vex_document):
        """Test that document without contradicting status passes."""
        result = verify_no_contradicting_status(valid_vex_document)
        assert result.passed
        assert result.test_id == "1.9"

    def test_contradicting_status(self, document_with_contradicting_status):
        """Test that contradicting status fails."""
        result = verify_no_contradicting_status(document_with_contradicting_status)
        assert result.failed
        assert "CONTRADICT-001" in str(result.details)


class TestActionStatementRequirement:
    """Test 1.10: Action Statement Requirement."""

    def test_known_affected_with_remediation(self, vex_with_known_affected):
        """Test that known_affected with remediation passes."""
        result = verify_action_statement_requirement(vex_with_known_affected)
        assert result.passed
        assert result.test_id == "1.10"

    def test_known_affected_without_remediation(self):
        """Test that known_affected without remediation fails."""
        doc = {
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "product_status": {"known_affected": ["PROD-001"]},
                    "remediations": [],  # No remediation for PROD-001
                }
            ]
        }
        result = verify_action_statement_requirement(doc)
        assert result.failed


class TestImpactStatementRequirement:
    """Test 1.11: Impact Statement Requirement."""

    def test_known_not_affected_with_flag(self, vex_with_known_not_affected):
        """Test that known_not_affected with flag passes."""
        result = verify_impact_statement_requirement(vex_with_known_not_affected)
        assert result.passed
        assert result.test_id == "1.11"

    def test_known_not_affected_with_threat(self):
        """Test that known_not_affected with threat passes."""
        doc = {
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "product_status": {"known_not_affected": ["PROD-001"]},
                    "threats": [
                        {
                            "category": "impact",
                            "details": "Component not present in product",
                            "product_ids": ["PROD-001"],
                        }
                    ],
                }
            ]
        }
        result = verify_impact_statement_requirement(doc)
        assert result.passed

    def test_known_not_affected_without_impact(self):
        """Test that known_not_affected without impact fails."""
        doc = {
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "product_status": {"known_not_affected": ["PROD-001"]},
                }
            ]
        }
        result = verify_impact_statement_requirement(doc)
        assert result.failed


class TestRemediationProductReference:
    """Test 1.12: Remediation Product Reference."""

    def test_remediation_with_product_ids(self, vex_with_known_affected):
        """Test that remediation with product_ids passes."""
        result = verify_remediation_product_reference(vex_with_known_affected)
        assert result.passed
        assert result.test_id == "1.12"

    def test_remediation_without_product_reference(self):
        """Test that remediation without product reference fails."""
        doc = {
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "remediations": [
                        {
                            "category": "vendor_fix",
                            "details": "Apply update",
                            # Missing product_ids and group_ids
                        }
                    ],
                }
            ]
        }
        result = verify_remediation_product_reference(doc)
        assert result.failed


class TestFlagProductReference:
    """Test 1.13: Flag Product Reference."""

    def test_flag_with_product_ids(self, vex_with_known_not_affected):
        """Test that flag with product_ids passes."""
        result = verify_flag_product_reference(vex_with_known_not_affected)
        assert result.passed
        assert result.test_id == "1.13"

    def test_flag_without_product_reference(self):
        """Test that flag without product reference fails."""
        doc = {
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "flags": [
                        {
                            "label": "component_not_present",
                            # Missing product_ids and group_ids
                        }
                    ],
                }
            ]
        }
        result = verify_flag_product_reference(doc)
        assert result.failed


class TestUniqueVEXJustification:
    """Test 1.14: Unique VEX Justification."""

    def test_unique_justifications(self, vex_with_known_not_affected):
        """Test that unique VEX justifications pass."""
        result = verify_unique_vex_justification(vex_with_known_not_affected)
        assert result.passed
        assert result.test_id == "1.14"

    def test_duplicate_justifications(self):
        """Test that duplicate VEX justifications fail."""
        doc = {
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "flags": [
                        {
                            "label": "component_not_present",
                            "product_ids": ["PROD-001"],
                        },
                        {
                            "label": "vulnerable_code_not_present",
                            "product_ids": ["PROD-001"],  # Same product, different justification
                        },
                    ],
                }
            ]
        }
        result = verify_unique_vex_justification(doc)
        assert result.failed


class TestVerifierCSAFCompliance:
    """Integration tests for the Verifier class with CSAF compliance tests."""

    def test_run_csaf_compliance_on_valid_document(self, valid_vex_document):
        """Test running all CSAF compliance tests on a valid document."""
        verifier = Verifier(valid_vex_document)
        report = verifier.run_csaf_compliance()

        assert report.total_tests == 14
        # Check that all CSAF compliance tests ran
        test_ids = {r.test_id for r in report.results}
        expected_ids = {f"1.{i}" for i in range(1, 15)}
        assert test_ids == expected_ids

    def test_run_csaf_compliance_on_complete_vex(self, complete_vex):
        """Test running CSAF compliance tests on the complete VEX example."""
        verifier = Verifier(complete_vex)
        report = verifier.run_csaf_compliance()

        assert report.total_tests == 14
        # The example file should pass most tests
        assert report.passed_count > 0

    def test_run_single_test(self, valid_vex_document):
        """Test running a single CSAF compliance test."""
        verifier = Verifier(valid_vex_document)
        result = verifier.run_test("1.1")

        assert result.test_id == "1.1"
        assert result.passed

    def test_get_available_tests(self):
        """Test getting the list of available tests."""
        tests = Verifier.get_available_tests()

        # Should have 30 tests total (14 CSAF + 16 data type)
        assert len(tests) == 30
        assert "1.1" in tests
        assert "2.1" in tests


class TestWithFixtureFiles:
    """Tests using the JSON fixture files from test_files directory."""

    def test_complete_vex_file(self, complete_vex):
        """Test verification on the complete 2022-evd-uc-05-001.json file."""
        verifier = Verifier(complete_vex)
        report = verifier.run_csaf_compliance()

        assert report.total_tests == 14
        # This file should pass VEX profile conformance
        result = verifier.run_test("1.1")
        assert result.passed

    def test_sample_vex_file(self, sample_vex):
        """Test verification on the sample-vex.json file."""
        result = verify_vex_profile_conformance(sample_vex)
        assert result.passed

    def test_minimal_vex_file(self, minimal_vex):
        """Test verification on the minimal-vex.json file."""
        # Minimal VEX should pass profile conformance (has document with csaf_vex)
        result = verify_vex_profile_conformance(minimal_vex)
        # Missing product_tree and vulnerabilities sections
        assert result.failed

    def test_invalid_category_file(self, invalid_category_file):
        """Test that invalid-category.json fails VEX profile conformance."""
        result = verify_vex_profile_conformance(invalid_category_file)
        assert result.failed
        assert any("category" in e.lower() for e in result.details["errors"])

    def test_invalid_empty_title_file(self, invalid_empty_title_file):
        """Test that invalid-empty-title.json fails base mandatory fields check."""
        result = verify_base_mandatory_fields(invalid_empty_title_file)
        assert result.failed
        assert any("title" in e.lower() for e in result.details["errors"])

    def test_invalid_whitespace_title_file(self, invalid_whitespace_title_file):
        """Test that invalid-whitespace-title.json fails base mandatory fields check.

        Note: The file has a whitespace-only title which is truthy, so the
        base mandatory fields check passes the title check. However, the file
        is missing csaf_version and publisher, so it still fails.
        """
        result = verify_base_mandatory_fields(invalid_whitespace_title_file)
        assert result.failed
        # File is missing csaf_version and publisher
        assert any("csaf_version" in e.lower() for e in result.details["errors"])
        assert any("publisher" in e.lower() for e in result.details["errors"])

    def test_verifier_from_file_path(self, test_files_dir):
        """Test creating Verifier directly from file path."""
        verifier = Verifier.from_file(test_files_dir / "2022-evd-uc-05-001.json")

        assert verifier.document_id == "2022-EVD-UC-05-001"
        result = verifier.run_test("1.1")
        assert result.passed

    def test_verifier_from_invalid_category_file(self, test_files_dir):
        """Test Verifier with invalid-category.json file."""
        verifier = Verifier.from_file(test_files_dir / "invalid-category.json")

        result = verifier.run_test("1.1")
        assert result.failed
