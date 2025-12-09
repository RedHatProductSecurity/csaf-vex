"""Shared pytest fixtures for VEX verification tests."""

import json
from pathlib import Path

import pytest

# Path to test fixture files
TEST_FILES_DIR = Path(__file__).parent / "test_files"


@pytest.fixture
def test_files_dir() -> Path:
    """Return the path to the test files directory."""
    return TEST_FILES_DIR


@pytest.fixture
def minimal_vex() -> dict:
    """Load the minimal VEX document fixture."""
    with open(TEST_FILES_DIR / "minimal-vex.json") as f:
        return json.load(f)


@pytest.fixture
def sample_vex() -> dict:
    """Load the sample VEX document fixture."""
    with open(TEST_FILES_DIR / "sample-vex.json") as f:
        return json.load(f)


@pytest.fixture
def complete_vex() -> dict:
    """Load a complete VEX document fixture (2022-evd-uc-05-001.json)."""
    with open(TEST_FILES_DIR / "2022-evd-uc-05-001.json") as f:
        return json.load(f)


@pytest.fixture
def invalid_category_file() -> dict:
    """Load the invalid-category.json fixture."""
    with open(TEST_FILES_DIR / "invalid-category.json") as f:
        return json.load(f)


@pytest.fixture
def invalid_empty_title_file() -> dict:
    """Load the invalid-empty-title.json fixture."""
    with open(TEST_FILES_DIR / "invalid-empty-title.json") as f:
        return json.load(f)


@pytest.fixture
def invalid_whitespace_title_file() -> dict:
    """Load the invalid-whitespace-title.json fixture."""
    with open(TEST_FILES_DIR / "invalid-whitespace-title.json") as f:
        return json.load(f)


@pytest.fixture
def valid_vex_document() -> dict:
    """A valid VEX document with all required fields."""
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "Test VEX Document",
            "publisher": {
                "category": "vendor",
                "name": "Test Vendor",
                "namespace": "https://test.example.com",
            },
            "tracking": {
                "id": "TEST-VEX-001",
                "status": "final",
                "version": "1",
                "initial_release_date": "2025-01-01T00:00:00.000Z",
                "current_release_date": "2025-01-01T00:00:00.000Z",
                "revision_history": [
                    {
                        "date": "2025-01-01T00:00:00.000Z",
                        "number": "1",
                        "summary": "Initial version",
                    }
                ],
            },
        },
        "product_tree": {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Test Vendor",
                    "branches": [
                        {
                            "category": "product_name",
                            "name": "Test Product",
                            "branches": [
                                {
                                    "category": "product_version",
                                    "name": "1.0.0",
                                    "product": {
                                        "name": "Test Product 1.0.0",
                                        "product_id": "TESTPROD-001",
                                    },
                                }
                            ],
                        }
                    ],
                }
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2025-0001",
                "notes": [
                    {
                        "category": "description",
                        "text": "Test vulnerability description",
                        "title": "Description",
                    }
                ],
                "product_status": {"under_investigation": ["TESTPROD-001"]},
            }
        ],
    }


@pytest.fixture
def vex_with_known_affected() -> dict:
    """A VEX document with known_affected products requiring remediations."""
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "Test VEX with Known Affected",
            "publisher": {
                "category": "vendor",
                "name": "Test Vendor",
                "namespace": "https://test.example.com",
            },
            "tracking": {
                "id": "TEST-VEX-002",
                "status": "final",
                "version": "1",
                "initial_release_date": "2025-01-01T00:00:00.000Z",
                "current_release_date": "2025-01-01T00:00:00.000Z",
            },
        },
        "product_tree": {
            "full_product_names": [
                {"name": "Affected Product", "product_id": "AFFECTED-001"},
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2025-0002",
                "notes": [{"category": "description", "text": "Test vulnerability"}],
                "product_status": {"known_affected": ["AFFECTED-001"]},
                "remediations": [
                    {
                        "category": "vendor_fix",
                        "details": "Apply the security update",
                        "product_ids": ["AFFECTED-001"],
                    }
                ],
            }
        ],
    }


@pytest.fixture
def vex_with_known_not_affected() -> dict:
    """A VEX document with known_not_affected products requiring impact statements."""
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "Test VEX with Known Not Affected",
            "publisher": {
                "category": "vendor",
                "name": "Test Vendor",
                "namespace": "https://test.example.com",
            },
            "tracking": {
                "id": "TEST-VEX-003",
                "status": "final",
                "version": "1",
                "initial_release_date": "2025-01-01T00:00:00.000Z",
                "current_release_date": "2025-01-01T00:00:00.000Z",
            },
        },
        "product_tree": {
            "full_product_names": [
                {"name": "Not Affected Product", "product_id": "NOTAFFECTED-001"},
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2025-0003",
                "notes": [{"category": "description", "text": "Test vulnerability"}],
                "product_status": {"known_not_affected": ["NOTAFFECTED-001"]},
                "flags": [
                    {
                        "label": "component_not_present",
                        "product_ids": ["NOTAFFECTED-001"],
                    }
                ],
            }
        ],
    }


@pytest.fixture
def empty_document() -> dict:
    """An empty document for testing missing fields."""
    return {}


@pytest.fixture
def document_with_invalid_category() -> dict:
    """A document with an invalid category."""
    return {
        "document": {
            "category": "invalid_category",
            "title": "Invalid Category Test",
        },
        "product_tree": {},
        "vulnerabilities": [],
    }


@pytest.fixture
def document_with_cvss() -> dict:
    """A document with CVSS scoring information."""
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "Test VEX with CVSS",
            "publisher": {
                "category": "vendor",
                "name": "Test Vendor",
                "namespace": "https://test.example.com",
            },
            "tracking": {
                "id": "TEST-VEX-CVSS",
                "status": "final",
                "version": "1",
                "initial_release_date": "2025-01-01T00:00:00.000Z",
                "current_release_date": "2025-01-01T00:00:00.000Z",
            },
        },
        "product_tree": {
            "full_product_names": [
                {"name": "Test Product", "product_id": "CVSS-TEST-001"},
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2025-0004",
                "notes": [{"category": "description", "text": "Test vulnerability"}],
                "product_status": {"known_affected": ["CVSS-TEST-001"]},
                "scores": [
                    {
                        "products": ["CVSS-TEST-001"],
                        "cvss_v3": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "availabilityImpact": "HIGH",
                        },
                    }
                ],
                "remediations": [
                    {
                        "category": "vendor_fix",
                        "details": "Update to latest version",
                        "product_ids": ["CVSS-TEST-001"],
                    }
                ],
            }
        ],
    }


@pytest.fixture
def document_with_purl_and_cpe() -> dict:
    """A document with PURL and CPE identifiers."""
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "Test VEX with PURL and CPE",
            "publisher": {
                "category": "vendor",
                "name": "Test Vendor",
                "namespace": "https://test.example.com",
            },
            "tracking": {
                "id": "TEST-VEX-PURL-CPE",
                "status": "final",
                "version": "1",
                "initial_release_date": "2025-01-01T00:00:00.000Z",
                "current_release_date": "2025-01-01T00:00:00.000Z",
            },
        },
        "product_tree": {
            "full_product_names": [
                {
                    "name": "Test Product",
                    "product_id": "PURL-CPE-001",
                    "product_identification_helper": {
                        "purl": "pkg:npm/example-package@1.0.0",
                        "cpe": "cpe:2.3:a:example:package:1.0.0:*:*:*:*:*:*:*",
                    },
                },
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2025-0005",
                "notes": [{"category": "description", "text": "Test vulnerability"}],
                "product_status": {"under_investigation": ["PURL-CPE-001"]},
            }
        ],
    }


@pytest.fixture
def document_with_circular_reference() -> dict:
    """A document with circular product references (invalid)."""
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "Test VEX with Circular Reference",
            "publisher": {
                "category": "vendor",
                "name": "Test Vendor",
                "namespace": "https://test.example.com",
            },
            "tracking": {
                "id": "TEST-VEX-CIRCULAR",
                "status": "final",
                "version": "1",
                "initial_release_date": "2025-01-01T00:00:00.000Z",
                "current_release_date": "2025-01-01T00:00:00.000Z",
            },
        },
        "product_tree": {
            "full_product_names": [
                {"name": "Product A", "product_id": "PROD-A"},
                {"name": "Product B", "product_id": "PROD-B"},
            ],
            "relationships": [
                {
                    "category": "installed_on",
                    "full_product_name": {
                        "name": "A on B",
                        "product_id": "PROD-A-ON-B",
                    },
                    "product_reference": "PROD-A",
                    "relates_to_product_reference": "PROD-B",
                },
                {
                    "category": "installed_on",
                    "full_product_name": {
                        "name": "B on A-on-B",
                        "product_id": "PROD-B-ON-A-ON-B",
                    },
                    "product_reference": "PROD-B",
                    "relates_to_product_reference": "PROD-A-ON-B",
                },
            ],
        },
        "vulnerabilities": [],
    }


@pytest.fixture
def document_with_contradicting_status() -> dict:
    """A document where a product has contradicting status (invalid)."""
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "Test VEX with Contradicting Status",
            "publisher": {
                "category": "vendor",
                "name": "Test Vendor",
                "namespace": "https://test.example.com",
            },
            "tracking": {
                "id": "TEST-VEX-CONTRADICT",
                "status": "final",
                "version": "1",
                "initial_release_date": "2025-01-01T00:00:00.000Z",
                "current_release_date": "2025-01-01T00:00:00.000Z",
            },
        },
        "product_tree": {
            "full_product_names": [
                {"name": "Contradicting Product", "product_id": "CONTRADICT-001"},
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2025-0006",
                "notes": [{"category": "description", "text": "Test vulnerability"}],
                "product_status": {
                    "known_affected": ["CONTRADICT-001"],
                    "known_not_affected": ["CONTRADICT-001"],  # Contradiction!
                },
            }
        ],
    }


@pytest.fixture
def cve_2023_20593() -> dict:
    """Load the cve-2023-20593.json fixture."""
    with open(TEST_FILES_DIR / "cve-2023-20593.json") as f:
        return json.load(f)
