"""Tests for CSAF VEX model serialization and deserialization."""

from deepdiff import DeepDiff

from csaf_vex.models import CSAFVEX


class TestModelRoundTrip:
    """Test round-trip serialization: dict -> model -> dict."""

    def test_minimal_vex_roundtrip(self, minimal_vex):
        """Test round-trip with minimal VEX document."""
        csafvex = CSAFVEX.from_dict(minimal_vex)

        assert csafvex.document is not None
        assert csafvex.document.category == "csaf_vex"

        result = csafvex.to_dict()

        assert result["document"]["category"] == minimal_vex["document"]["category"]
        assert result["document"]["title"] == minimal_vex["document"]["title"]

    def test_sample_vex_roundtrip(self, sample_vex):
        """Test round-trip with sample VEX document."""
        csafvex = CSAFVEX.from_dict(sample_vex)

        assert csafvex.document is not None

        result = csafvex.to_dict()

        assert result["document"]["category"] == sample_vex["document"]["category"]

        if sample_vex.get("product_tree"):
            assert "product_tree" in result or csafvex.product_tree is None

        if csafvex.vulnerabilities:
            assert "vulnerabilities" in result
            assert len(result["vulnerabilities"]) == len(csafvex.vulnerabilities)

    def test_cve_2023_20593_roundtrip(self, cve_2023_20593):
        """Test round-trip with real-world CVE document using DeepDiff."""
        csafvex = CSAFVEX.from_dict(cve_2023_20593)
        result = csafvex.to_dict()

        diff = DeepDiff(
            cve_2023_20593, result, ignore_order=False, exclude_regex_paths=[r".*date.*"]
        )

        assert not diff, f"Diff should be empty: {diff}"


class TestEmptyListFiltering:
    """Test that empty lists are filtered out during serialization."""

    def test_empty_product_status_lists_omitted(self):
        """Test that empty product_status lists are omitted."""
        data = {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "title": "Test",
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
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "product_status": {
                        "known_affected": ["PROD-001"],
                        "fixed": [],  # This should be omitted
                        "under_investigation": [],  # This should be omitted
                    },
                }
            ],
        }

        csafvex = CSAFVEX.from_dict(data)
        result = csafvex.to_dict()

        product_status = result["vulnerabilities"][0]["product_status"]
        assert "known_affected" in product_status
        assert "fixed" not in product_status
        assert "under_investigation" not in product_status

    def test_empty_vulnerabilities_omitted(self):
        """Test that empty vulnerabilities list is omitted."""
        data = {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "title": "Test",
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
            },
            "vulnerabilities": [],
        }

        csafvex = CSAFVEX.from_dict(data)
        result = csafvex.to_dict()

        assert "vulnerabilities" not in result
