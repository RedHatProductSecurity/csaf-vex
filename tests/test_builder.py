"""Tests for CSAF VEX builder."""

from csaf_vex.builder import CSAFVEXBuilder


class TestBuilderEmptyValues:
    """Test that builder correctly handles empty values."""

    def test_builder_handles_empty_product_status(self):
        """Builder should accept empty product_status dict without treating it as falsy."""
        vex = CSAFVEXBuilder.build(
            cve_id="CVE-2025-0001",
            title="Test Advisory",
            document_data={
                "publisher": {"name": "Test", "namespace": "https://test.com"},
                "initial_release_date": "2025-01-01T00:00:00Z",
            },
            vulnerability_data={"product_status": {}},
        )
        assert vex.vulnerabilities[0].product_status is not None

    def test_builder_handles_empty_references_list(self):
        """Builder should accept empty references list."""
        vex = CSAFVEXBuilder.build(
            cve_id="CVE-2025-0001",
            title="Test Advisory",
            document_data={
                "publisher": {"name": "Test", "namespace": "https://test.com"},
                "initial_release_date": "2025-01-01T00:00:00Z",
            },
            vulnerability_data={"references": []},
        )
        assert vex.vulnerabilities[0].references == []

    def test_builder_handles_empty_products_list(self):
        """Builder should handle empty products list in product_tree_data."""
        vex = CSAFVEXBuilder.build(
            cve_id="CVE-2025-0001",
            title="Test Advisory",
            document_data={
                "publisher": {"name": "Test", "namespace": "https://test.com"},
                "initial_release_date": "2025-01-01T00:00:00Z",
            },
            product_tree_data={
                "name": "Test Vendor",
                "components": [],
                "streams": [],
                "products": [],
            },
        )
        assert vex.product_tree is not None
