"""Builder for constructing CSAF VEX documents."""

from datetime import datetime, timezone
from typing import Any

from csaf_vex import __version__
from csaf_vex.models.csafvex import CSAFVEX
from csaf_vex.models.document import Document
from csaf_vex.models.product_tree import (
    Branch,
    FullProductName,
    ProductIdentificationHelper,
    ProductTree,
    Relationship,
)
from csaf_vex.models.vulnerability import (
    Vulnerability,
)

# Default values for CSAF VEX documents
DEFAULT_CATEGORY = "csaf_vex"
DEFAULT_CSAF_VERSION = "2.0"
DEFAULT_LANG = "en"
DEFAULT_SOURCE_LANG = "en"
DEFAULT_PUBLISHER_CATEGORY = "vendor"
DEFAULT_TLP_LABEL = "WHITE"
DEFAULT_TLP_URL = "https://www.first.org/tlp/"
DEFAULT_TRACKING_STATUS = "final"
DEFAULT_TRACKING_VERSION = "1"
DEFAULT_GENERATOR_ENGINE_NAME = "csaf-vex"
DEFAULT_REVISION_NUMBER = "1"
DEFAULT_REVISION_SUMMARY = "Initial version"


class CSAFVEXBuilder:
    """Builder for constructing CSAF VEX documents.

    The CVE ID is passed once as a top-level parameter and automatically injected
    into the document tracking ID.

    Example:
        vex = CSAFVEXBuilder.build(
            cve_id="CVE-2025-66293",
            title="example: Security Advisory",
            document_data={
                "publisher": {"name": "Red Hat Product Security", "namespace": "https://redhat.com"},
                "initial_release_date": "2025-01-01T00:00:00Z",
            },
            product_tree_data={
                "name": "Red Hat",
                "components": [{"name": "component1", "purl": "pkg:..."}],
                "streams": [{"name": "stream1", "cpe": "cpe:/..."}],
                "products": [
                    {
                        "name": "Product 1",
                        "component": "component1",
                        "stream": "stream1",
                        "purl": "pkg:..."
                    }
                ],
            },
        )
    """

    @classmethod
    def build(
        cls,
        cve_id: str,
        title: str,
        document_data: dict[str, Any],
        vulnerability_data: dict[str, Any] | None = None,
        product_tree_data: dict[str, Any] | None = None,
    ) -> CSAFVEX:
        """Build a CSAF VEX document.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2025-66293"). This is automatically
                   injected into document.tracking.id and vulnerability.cve
            title: Document and vulnerability title. This is automatically
                   injected into document.title and vulnerability.title
            document_data: Document metadata. No need to include CVE ID or title here.
                The following defaults are automatically set if not provided:
                - category: "csaf_vex"
                - csaf_version: "2.0"
                - lang: "en"
                - source_lang: "en"
                - publisher.category: "vendor"
                - distribution.tlp: {"label": "WHITE", "url": "https://www.first.org/tlp/"}
                - tracking.status: "final"
                - tracking.version: "1"
                - tracking.generator.engine.name: "csaf-vex"
                - tracking.generator.engine.version: Current library version
                - tracking.generator.date: Current UTC timestamp
                - tracking.initial_release_date: Copied from document initial_release_date
                - tracking.current_release_date: Current UTC timestamp if not provided
                - tracking.revision_history: Single entry with initial version

                Expected keys:
                - publisher: Publisher info dict with name, namespace, contact_details,
                issuing_authority
                - initial_release_date: Optional initial release date (ISO format)
                - current_release_date: Optional current release date (defaults to now)
                - aggregate_severity: Optional severity dict with text and namespace
                - distribution: Optional distribution dict with text and tlp
                - tracking: Optional tracking dict (id will be overwritten with cve_id)
            vulnerability_data: Vulnerability data. No need to include CVE ID or title here.
            Expected keys:
                - cwe_id: Optional CWE dict with id and name keys
                - discovery_date: Optional discovery date (ISO format string or datetime)
                - product_status: Dict mapping status to product IDs
                - score: Optional CVSS score dict with vector
                - remediation: Optional remediation text
                - references: List of reference dicts with category, url, summary
                - flags: Optional list of flag dicts with label and product_ids
                - notes: Optional list of note dicts with category, text, and title
            product_tree_data: Product tree data. Expected keys:
                - name: Vendor name (e.g., "Red Hat")
                - components: List of component dicts with name and purl
                - streams: List of stream dicts with name and cpe
                - products (or records): List of full product dicts with name, component, stream,
                purl

        Returns:
            Complete CSAFVEX object
        """
        # Preprocess document data with defaults, title, and CVE ID
        document_data = cls._preprocess_document_data(document_data, cve_id, title)

        # Build Document directly from data
        document = Document.from_dict(document_data)

        # Transform product tree data
        product_tree = None
        if product_tree_data:
            product_tree = cls._build_product_tree(product_tree_data)

        # Transform vulnerability data
        vulnerabilities = []
        if vulnerability_data:
            vulnerability = cls._build_vulnerability(
                vulnerability_data, product_tree_data, cve_id, title
            )
            vulnerabilities = [vulnerability]

        return CSAFVEX(
            document=document,
            product_tree=product_tree,
            vulnerabilities=vulnerabilities,
        )

    @staticmethod
    def _preprocess_document_data(
        document_data: dict[str, Any], cve_id: str, title: str
    ) -> dict[str, Any]:
        """Preprocess document data by setting title, adding defaults, and injecting CVE ID.

        Mutates document_data and ensures:
        - title is set from parameter
        - Standard CSAF VEX defaults are set if not provided
        - tracking.id is set to cve_id

        Args:
            document_data: Document data to mutate
            cve_id: CVE identifier to inject
            title: Document title to set

        Returns:
            The same document_data dict (mutated)
        """
        # Set required fields
        document_data["title"] = title

        # Set defaults if not provided
        document_data.setdefault("category", DEFAULT_CATEGORY)
        document_data.setdefault("csaf_version", DEFAULT_CSAF_VERSION)
        document_data.setdefault("lang", DEFAULT_LANG)
        document_data.setdefault("source_lang", DEFAULT_SOURCE_LANG)

        # Handle publisher with defaults
        if "publisher" in document_data:
            document_data["publisher"].setdefault("category", DEFAULT_PUBLISHER_CATEGORY)

        # Handle distribution with TLP defaults
        if "distribution" not in document_data:
            document_data["distribution"] = {}
        document_data["distribution"].setdefault(
            "tlp", {"label": DEFAULT_TLP_LABEL, "url": DEFAULT_TLP_URL}
        )

        # Get current timestamp for defaults
        now = datetime.now(timezone.utc).isoformat()

        # Ensure tracking exists and set defaults
        if "tracking" not in document_data:
            document_data["tracking"] = {}

        tracking = document_data["tracking"]

        # Set tracking.id and status
        tracking["id"] = cve_id
        tracking.setdefault("status", DEFAULT_TRACKING_STATUS)
        tracking.setdefault("version", DEFAULT_TRACKING_VERSION)

        # Set up generator with defaults
        if "generator" not in tracking:
            tracking["generator"] = {}

        generator = tracking["generator"]
        generator.setdefault("date", now)

        if "engine" not in generator:
            generator["engine"] = {}

        generator["engine"].setdefault("name", DEFAULT_GENERATOR_ENGINE_NAME)
        generator["engine"].setdefault("version", __version__)

        # Set up initial and current release dates in tracking
        # Copy from document level if provided, otherwise use defaults
        if "initial_release_date" in document_data:
            tracking.setdefault("initial_release_date", document_data["initial_release_date"])

        if "current_release_date" in document_data:
            tracking.setdefault("current_release_date", document_data["current_release_date"])
        else:
            tracking.setdefault("current_release_date", now)

        # Set up default revision history if not provided
        if "revision_history" not in tracking:
            initial_date = document_data.get("initial_release_date")
            if initial_date:
                tracking["revision_history"] = [
                    {
                        "number": DEFAULT_REVISION_NUMBER,
                        "date": initial_date,
                        "summary": DEFAULT_REVISION_SUMMARY,
                    }
                ]

        return document_data

    @staticmethod
    def _create_stream_branch(name: str, cpe: str) -> Branch:
        """Create a branch for a stream product."""
        product = FullProductName(
            name=name,
            product_id=name,
            product_identification_helper=ProductIdentificationHelper(cpe=cpe),
        )
        return Branch(category="product_name", name=name, product=product)

    @staticmethod
    def _create_component_branch(name: str, purl: str) -> Branch:
        """Create a branch for a component product."""
        product = FullProductName(
            name=name,
            product_id=name,
            product_identification_helper=ProductIdentificationHelper(purl=purl),
        )
        return Branch(category="product_version", name=name, product=product)

    @staticmethod
    def _create_relationship(component: str, stream: str) -> Relationship:
        """Create a relationship between component and stream."""
        full_product = FullProductName(
            name=f"{component} as a component of {stream}",
            product_id=f"{stream}:{component}",
        )
        return Relationship(
            category="default_component_of",
            full_product_name=full_product,
            product_reference=component,
            relates_to_product_reference=stream,
        )

    @staticmethod
    def _build_product_tree(data: dict[str, Any]) -> ProductTree:
        """Transform raw product tree data into ProductTree model.

        Args:
            data: Dict with keys:
                - name: Vendor name
                - components: List of dicts with name, purl
                - streams: List of dicts with name, cpe
                - products: List of full product dicts with name, component, stream, purl
        """
        vendor_name = data.get("name", "Vendor")
        products_data = data.get("products", [])
        components_data = data.get("components", [])
        streams_data = data.get("streams", [])

        branches = []
        for stream in streams_data:
            branches.append(
                CSAFVEXBuilder._create_stream_branch(stream.get("name"), stream.get("cpe"))
            )

        for component in components_data:
            branches.append(
                CSAFVEXBuilder._create_component_branch(
                    component.get("name"), component.get("purl")
                )
            )

        # TODO: handle product_family, architecture
        vendor_branch = Branch(category="vendor", name=vendor_name, branches=branches)

        relationships = []
        for record in products_data:
            relationships.append(
                CSAFVEXBuilder._create_relationship(record["component"], record["stream"])
            )

        return ProductTree(branches=[vendor_branch], relationships=relationships)

    @staticmethod
    def _build_vulnerability(
        data: dict[str, Any],
        product_tree_data: dict[str, Any] | None = None,
        cve_id: str | None = None,
        title: str | None = None,
    ) -> Vulnerability:
        """Transform raw vulnerability data into Vulnerability model.

        Args:
            data: Dict with keys:
                - cwe_id: Optional CWE dict with id and name keys
                - discovery_date: Optional discovery date (ISO format string or datetime)
                - product_status: Dict mapping status to product IDs
                - score: Optional CVSS score dict with vector
                - remediation: Optional remediation text
                - references: List of reference dicts with category, url, summary
                - flags: Optional list of flag dicts with label and product_ids
                - notes: Optional list of note dicts with category, text, and title
            product_tree_data: Optional product tree data to extract product IDs
            cve_id: CVE identifier (injected from top-level parameter)
            title: Vulnerability title (injected from top-level parameter)
        """
        vuln_dict = {"cve": cve_id, "title": title}
        product_ids = []
        if product_tree_data and "products" in product_tree_data:
            product_ids = [
                f"{p.get('stream')}:{p.get('component')}" for p in product_tree_data["products"]
            ]

        if "discovery_date" in data:
            vuln_dict["discovery_date"] = data["discovery_date"]

        if "cwe_id" in data:
            vuln_dict["cwe"] = data["cwe_id"]

        if "product_status" in data:
            vuln_dict["product_status"] = data["product_status"]

        if "score" in data and data["score"].get("vector"):
            vuln_dict["scores"] = [
                {"products": product_ids, "cvss_v3": {"vectorString": data["score"]["vector"]}}
            ]

        if "references" in data:
            vuln_dict["references"] = data["references"]

        if "flags" in data:
            vuln_dict["flags"] = data["flags"]

        if "notes" in data:
            vuln_dict["notes"] = data["notes"]

        if "remediation" in data:
            vuln_dict["remediations"] = [
                {
                    "category": "workaround",
                    "details": data["remediation"],
                    "product_ids": product_ids,
                }
            ]

        return Vulnerability.from_dict(vuln_dict)
