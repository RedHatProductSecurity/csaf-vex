"""Test Set 1: CSAF Standard Compliance Tests.

This module implements tests 1.1-1.14 for verifying compliance with the
CSAF VEX Profile (Profile 5) and mandatory CSAF tests from Section 6.1.
"""

from collections import defaultdict
from typing import Any

from .result import VerificationResult, VerificationSeverity, VerificationStatus

# VEX justification labels as defined in CSAF spec
VEX_JUSTIFICATION_LABELS = frozenset(
    {
        "component_not_present",
        "inline_mitigations_already_exist",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_not_present",
    }
)

# Product status groups for contradiction checking
STATUS_GROUPS = {
    "affected": frozenset({"known_affected"}),
    "not_affected": frozenset({"known_not_affected"}),
    "fixed": frozenset({"first_affected", "first_fixed", "fixed", "last_affected"}),
    "under_investigation": frozenset({"under_investigation"}),
}


def _collect_all_product_ids_from_branches(
    branches: list[dict[str, Any]], collected: set[str] | None = None
) -> set[str]:
    """Recursively collect all product_ids defined in branches."""
    if collected is None:
        collected = set()

    for branch in branches:
        # Check if this branch has a product with product_id
        product = branch.get("product", {})
        if product_id := product.get("product_id"):
            collected.add(product_id)

        # Recurse into nested branches
        if nested_branches := branch.get("branches"):
            _collect_all_product_ids_from_branches(nested_branches, collected)

    return collected


def _collect_all_defined_product_ids(product_tree: dict[str, Any]) -> set[str]:
    """Collect all product_ids defined in the product_tree."""
    defined_ids: set[str] = set()

    # From branches (recursive)
    if branches := product_tree.get("branches"):
        _collect_all_product_ids_from_branches(branches, defined_ids)

    # From full_product_names
    for fpn in product_tree.get("full_product_names", []):
        if product_id := fpn.get("product_id"):
            defined_ids.add(product_id)

    # From relationships
    for rel in product_tree.get("relationships", []):
        fpn = rel.get("full_product_name")
        if fpn and (product_id := fpn.get("product_id")):
            defined_ids.add(product_id)

    return defined_ids


def _collect_all_referenced_product_ids(document: dict[str, Any]) -> set[str]:
    """Collect all product_ids referenced throughout the document."""
    referenced_ids: set[str] = set()

    # From vulnerabilities
    for vuln in document.get("vulnerabilities", []):
        # From product_status
        for status_list in vuln.get("product_status", {}).values():
            if isinstance(status_list, list):
                referenced_ids.update(status_list)

        # From remediations
        for rem in vuln.get("remediations", []):
            referenced_ids.update(rem.get("product_ids", []))
            referenced_ids.update(rem.get("group_ids", []))

        # From scores
        for score in vuln.get("scores", []):
            referenced_ids.update(score.get("products", []))

        # From flags
        for flag in vuln.get("flags", []):
            referenced_ids.update(flag.get("product_ids", []))
            referenced_ids.update(flag.get("group_ids", []))

        # From threats
        for threat in vuln.get("threats", []):
            referenced_ids.update(threat.get("product_ids", []))
            referenced_ids.update(threat.get("group_ids", []))

    # From product_tree relationships
    product_tree = document.get("product_tree", {})
    for rel in product_tree.get("relationships", []):
        if ref_id := rel.get("product_reference"):
            referenced_ids.add(ref_id)
        if rel_to_id := rel.get("relates_to_product_reference"):
            referenced_ids.add(rel_to_id)

    return referenced_ids


def _get_all_product_id_definitions(
    product_tree: dict[str, Any],
) -> dict[str, list[str]]:
    """Get all locations where each product_id is defined."""
    definitions: dict[str, list[str]] = defaultdict(list)

    def _scan_branches(branches: list[dict[str, Any]], path: str) -> None:
        for i, branch in enumerate(branches):
            current_path = f"{path}/branches[{i}]"
            product = branch.get("product")
            if product and (product_id := product.get("product_id")):
                definitions[product_id].append(f"{current_path}/product/product_id")
            if nested := branch.get("branches"):
                _scan_branches(nested, current_path)

    # Scan branches
    if branches := product_tree.get("branches"):
        _scan_branches(branches, "/product_tree")

    # Scan full_product_names
    for i, fpn in enumerate(product_tree.get("full_product_names", [])):
        if product_id := fpn.get("product_id"):
            definitions[product_id].append(f"/product_tree/full_product_names[{i}]/product_id")

    # Scan relationships
    for i, rel in enumerate(product_tree.get("relationships", [])):
        fpn = rel.get("full_product_name")
        if fpn and (product_id := fpn.get("product_id")):
            definitions[product_id].append(
                f"/product_tree/relationships[{i}]/full_product_name/product_id"
            )

    return definitions


def verify_vex_profile_conformance(document: dict[str, Any]) -> VerificationResult:
    """Test 1.1: VEX Profile Conformance.

    The document MUST conform to the VEX profile (Profile 5). This requires:
    - Explicit presence of /document, /product_tree, and /vulnerabilities sections
    - The /document/category value SHALL be csaf_vex
    """
    errors = []

    # Check required sections
    if "document" not in document:
        errors.append("Missing required '/document' section")
    if "product_tree" not in document:
        errors.append("Missing required '/product_tree' section")
    if "vulnerabilities" not in document:
        errors.append("Missing required '/vulnerabilities' section")

    # Check category
    doc_section = document.get("document", {})
    category = doc_section.get("category")
    if category != "csaf_vex":
        errors.append(f"Invalid category: expected 'csaf_vex', got '{category}'")

    if errors:
        return VerificationResult(
            test_id="1.1",
            test_name="VEX Profile Conformance",
            status=VerificationStatus.FAIL,
            message="Document does not conform to VEX profile (Profile 5)",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF VEX Profile (4.5)",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="1.1",
        test_name="VEX Profile Conformance",
        status=VerificationStatus.PASS,
        message="Document conforms to VEX profile (Profile 5)",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF VEX Profile (4.5)",
    )


def verify_base_mandatory_fields(document: dict[str, Any]) -> VerificationResult:
    """Test 1.2: Base Mandatory Fields.

    All required elements of the CSAF Base profile MUST exist and be valid:
    - Core tracking properties (id, status, version, initial_release_date, current_release_date)
    - csaf_version
    - Publisher properties (category, name, namespace)
    - Title
    """
    errors = []
    doc_section = document.get("document", {})

    # Check title
    if not doc_section.get("title"):
        errors.append("Missing required '/document/title'")

    # Check csaf_version
    if not doc_section.get("csaf_version"):
        errors.append("Missing required '/document/csaf_version'")

    # Check publisher
    publisher = doc_section.get("publisher", {})
    if not publisher:
        errors.append("Missing required '/document/publisher'")
    else:
        if not publisher.get("category"):
            errors.append("Missing required '/document/publisher/category'")
        if not publisher.get("name"):
            errors.append("Missing required '/document/publisher/name'")
        if not publisher.get("namespace"):
            errors.append("Missing required '/document/publisher/namespace'")

    # Check tracking
    tracking = doc_section.get("tracking", {})
    if not tracking:
        errors.append("Missing required '/document/tracking'")
    else:
        required_tracking = [
            "id",
            "status",
            "version",
            "initial_release_date",
            "current_release_date",
        ]
        for field in required_tracking:
            if not tracking.get(field):
                errors.append(f"Missing required '/document/tracking/{field}'")

    if errors:
        return VerificationResult(
            test_id="1.2",
            test_name="Base Mandatory Fields",
            status=VerificationStatus.FAIL,
            message="Missing required base profile fields",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Base Profile",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="1.2",
        test_name="Base Mandatory Fields",
        status=VerificationStatus.PASS,
        message="All base mandatory fields are present",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Base Profile",
    )


def verify_vex_product_status_existence(document: dict[str, Any]) -> VerificationResult:
    """Test 1.3: VEX Product Status Existence.

    For each item in /vulnerabilities, at least one of these specific product
    status lists MUST be present: fixed, known_affected, known_not_affected,
    or under_investigation.
    """
    valid_status_types = {"fixed", "known_affected", "known_not_affected", "under_investigation"}
    errors = []

    vulnerabilities = document.get("vulnerabilities", [])
    if not vulnerabilities:
        return VerificationResult(
            test_id="1.3",
            test_name="VEX Product Status Existence",
            status=VerificationStatus.SKIP,
            message="No vulnerabilities present in document",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF VEX Profile (4.5.3)",
        )

    for i, vuln in enumerate(vulnerabilities):
        product_status = vuln.get("product_status", {})
        found_status = set(product_status.keys()) & valid_status_types
        if not found_status:
            vuln_id = vuln.get("cve") or vuln.get("ids", [{}])[0].get("text", f"index {i}")
            errors.append(f"Vulnerability '{vuln_id}' has no VEX product status")

    if errors:
        return VerificationResult(
            test_id="1.3",
            test_name="VEX Product Status Existence",
            status=VerificationStatus.FAIL,
            message="Some vulnerabilities missing VEX product status",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF VEX Profile (4.5.3)",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="1.3",
        test_name="VEX Product Status Existence",
        status=VerificationStatus.PASS,
        message="All vulnerabilities have required product status",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF VEX Profile (4.5.3)",
    )


def verify_vulnerability_id_existence(document: dict[str, Any]) -> VerificationResult:
    """Test 1.4: Vulnerability ID Existence.

    For each item in /vulnerabilities, at least one of the identifiers
    (cve OR ids) MUST be present.
    """
    errors = []

    vulnerabilities = document.get("vulnerabilities", [])
    if not vulnerabilities:
        return VerificationResult(
            test_id="1.4",
            test_name="Vulnerability ID Existence",
            status=VerificationStatus.SKIP,
            message="No vulnerabilities present in document",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF VEX Profile (4.5.3)",
        )

    for i, vuln in enumerate(vulnerabilities):
        has_cve = bool(vuln.get("cve"))
        has_ids = bool(vuln.get("ids"))
        if not has_cve and not has_ids:
            errors.append(f"Vulnerability at index {i} has no CVE or IDs")

    if errors:
        return VerificationResult(
            test_id="1.4",
            test_name="Vulnerability ID Existence",
            status=VerificationStatus.FAIL,
            message="Some vulnerabilities missing identifiers",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF VEX Profile (4.5.3)",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="1.4",
        test_name="Vulnerability ID Existence",
        status=VerificationStatus.PASS,
        message="All vulnerabilities have identifiers",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF VEX Profile (4.5.3)",
    )


def verify_vulnerability_notes_existence(document: dict[str, Any]) -> VerificationResult:
    """Test 1.5: Vulnerability Notes Existence.

    For each item in /vulnerabilities, the notes element MUST exist
    to provide details about the vulnerability.
    """
    errors = []

    vulnerabilities = document.get("vulnerabilities", [])
    if not vulnerabilities:
        return VerificationResult(
            test_id="1.5",
            test_name="Vulnerability Notes Existence",
            status=VerificationStatus.SKIP,
            message="No vulnerabilities present in document",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF VEX Profile (4.5.3)",
        )

    for i, vuln in enumerate(vulnerabilities):
        notes = vuln.get("notes")
        if not notes:
            vuln_id = vuln.get("cve") or vuln.get("ids", [{}])[0].get("text", f"index {i}")
            errors.append(f"Vulnerability '{vuln_id}' has no notes")

    if errors:
        return VerificationResult(
            test_id="1.5",
            test_name="Vulnerability Notes Existence",
            status=VerificationStatus.FAIL,
            message="Some vulnerabilities missing notes",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF VEX Profile (4.5.3)",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="1.5",
        test_name="Vulnerability Notes Existence",
        status=VerificationStatus.PASS,
        message="All vulnerabilities have notes",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF VEX Profile (4.5.3)",
    )


def verify_product_id_defined(document: dict[str, Any]) -> VerificationResult:
    """Test 1.6: Product ID Definition Check (Missing).

    Every product_id referenced in status lists, relationships, remediations,
    scores, or flags MUST be fully defined in a Full Product Name element
    within the /product_tree (CSAF Mandatory Test 6.1.1).
    """
    product_tree = document.get("product_tree", {})
    defined_ids = _collect_all_defined_product_ids(product_tree)
    referenced_ids = _collect_all_referenced_product_ids(document)

    # Also collect group_ids definitions
    defined_group_ids = set()
    for group in product_tree.get("product_groups", []):
        if group_id := group.get("group_id"):
            defined_group_ids.add(group_id)

    # Check for undefined references
    undefined = []
    for ref_id in referenced_ids:
        if ref_id not in defined_ids and ref_id not in defined_group_ids:
            undefined.append(ref_id)

    if undefined:
        return VerificationResult(
            test_id="1.6",
            test_name="Product ID Definition Check (Missing)",
            status=VerificationStatus.FAIL,
            message="Some referenced product_ids are not defined",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.1",
            details={"undefined_ids": undefined},
        )

    return VerificationResult(
        test_id="1.6",
        test_name="Product ID Definition Check (Missing)",
        status=VerificationStatus.PASS,
        message="All referenced product_ids are defined",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.1",
    )


def verify_product_id_unique(document: dict[str, Any]) -> VerificationResult:
    """Test 1.7: Product ID Definition Check (Multiple).

    No single product_id can be defined more than once across all defining
    locations: /product_tree/branches[]/product/product_id,
    /product_tree/full_product_names[]/product_id, and
    /product_tree/relationships[]/full_product_name/product_id (CSAF Mandatory Test 6.1.2).
    """
    product_tree = document.get("product_tree", {})
    definitions = _get_all_product_id_definitions(product_tree)

    duplicates = {pid: locs for pid, locs in definitions.items() if len(locs) > 1}

    if duplicates:
        return VerificationResult(
            test_id="1.7",
            test_name="Product ID Definition Check (Multiple)",
            status=VerificationStatus.FAIL,
            message="Some product_ids are defined multiple times",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.2",
            details={"duplicates": duplicates},
        )

    return VerificationResult(
        test_id="1.7",
        test_name="Product ID Definition Check (Multiple)",
        status=VerificationStatus.PASS,
        message="All product_ids are uniquely defined",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.2",
    )


def verify_no_circular_references(document: dict[str, Any]) -> VerificationResult:
    """Test 1.8: Product ID Definition Check (Circular).

    Relationships defined within /product_tree/relationships MUST NOT result
    in a circular dependency where a product references itself through a
    chain of relationships (CSAF Mandatory Test 6.1.3).
    """
    product_tree = document.get("product_tree", {})
    relationships = product_tree.get("relationships", [])

    if not relationships:
        return VerificationResult(
            test_id="1.8",
            test_name="Product ID Definition Check (Circular)",
            status=VerificationStatus.SKIP,
            message="No relationships defined in product_tree",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF Mandatory Test 6.1.3",
        )

    # Build a graph of product relationships
    # A relationship creates a product from product_reference and relates_to_product_reference
    graph: dict[str, set[str]] = defaultdict(set)

    for rel in relationships:
        result_product = rel.get("full_product_name", {}).get("product_id")
        product_ref = rel.get("product_reference")
        relates_to = rel.get("relates_to_product_reference")

        if result_product:
            # The result product depends on both inputs
            if product_ref:
                graph[result_product].add(product_ref)
            if relates_to:
                graph[result_product].add(relates_to)

    # Check for cycles using DFS
    def has_cycle(node: str, visited: set[str], rec_stack: set[str]) -> list[str] | None:
        visited.add(node)
        rec_stack.add(node)

        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                result = has_cycle(neighbor, visited, rec_stack)
                if result:
                    return [node, *result]
            elif neighbor in rec_stack:
                return [node, neighbor]

        rec_stack.remove(node)
        return None

    visited: set[str] = set()
    for node in graph:
        if node not in visited:
            cycle = has_cycle(node, visited, set())
            if cycle:
                return VerificationResult(
                    test_id="1.8",
                    test_name="Product ID Definition Check (Circular)",
                    status=VerificationStatus.FAIL,
                    message="Circular dependency detected in relationships",
                    severity=VerificationSeverity.ERROR,
                    source_ref="CSAF Mandatory Test 6.1.3",
                    details={"cycle": cycle},
                )

    return VerificationResult(
        test_id="1.8",
        test_name="Product ID Definition Check (Circular)",
        status=VerificationStatus.PASS,
        message="No circular dependencies in relationships",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.3",
    )


def verify_no_contradicting_status(document: dict[str, Any]) -> VerificationResult:
    """Test 1.9: Contradicting Product Status.

    The sets of product IDs belonging to contradicting status groups
    (Affected, Not Affected, Fixed, Under Investigation) MUST be pairwise
    disjoint within a single vulnerability item (CSAF Mandatory Test 6.1.6).
    """
    errors = []

    for i, vuln in enumerate(document.get("vulnerabilities", [])):
        product_status = vuln.get("product_status", {})
        vuln_id = vuln.get("cve") or vuln.get("ids", [{}])[0].get("text", f"index {i}")

        # Collect products by status group
        group_products: dict[str, set[str]] = {}
        for group_name, status_types in STATUS_GROUPS.items():
            products: set[str] = set()
            for status_type in status_types:
                products.update(product_status.get(status_type, []))
            group_products[group_name] = products

        # Check for overlaps between groups
        groups = list(group_products.keys())
        for j, group1 in enumerate(groups):
            for group2 in groups[j + 1 :]:
                overlap = group_products[group1] & group_products[group2]
                if overlap:
                    errors.append(
                        f"Vulnerability '{vuln_id}': products {list(overlap)} "
                        f"appear in both '{group1}' and '{group2}' status groups"
                    )

    if errors:
        return VerificationResult(
            test_id="1.9",
            test_name="Contradicting Product Status",
            status=VerificationStatus.FAIL,
            message="Contradicting product status found",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.6",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="1.9",
        test_name="Contradicting Product Status",
        status=VerificationStatus.PASS,
        message="No contradicting product status found",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.6",
    )


def verify_action_statement_requirement(document: dict[str, Any]) -> VerificationResult:
    """Test 1.10: Action Statement Requirement.

    For every product listed in /vulnerabilities[]/product_status/known_affected,
    a corresponding action statement SHALL exist in /vulnerabilities[]/remediations
    (CSAF Mandatory Test 6.1.27.10).
    """
    errors = []

    for i, vuln in enumerate(document.get("vulnerabilities", [])):
        vuln_id = vuln.get("cve") or vuln.get("ids", [{}])[0].get("text", f"index {i}")
        known_affected = set(vuln.get("product_status", {}).get("known_affected", []))

        if not known_affected:
            continue

        # Collect all products covered by remediations
        remediated_products: set[str] = set()
        for rem in vuln.get("remediations", []):
            remediated_products.update(rem.get("product_ids", []))
            # Also check group_ids - they expand to products
            # (for simplicity, we include group_ids directly)
            remediated_products.update(rem.get("group_ids", []))

        # Check if all known_affected have remediations
        uncovered = known_affected - remediated_products
        if uncovered:
            errors.append(
                f"Vulnerability '{vuln_id}': known_affected products {list(uncovered)} "
                "have no remediation action statement"
            )

    if errors:
        return VerificationResult(
            test_id="1.10",
            test_name="Action Statement Requirement",
            status=VerificationStatus.FAIL,
            message="Some known_affected products lack action statements",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.27.10",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="1.10",
        test_name="Action Statement Requirement",
        status=VerificationStatus.PASS,
        message="All known_affected products have action statements",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.27.10",
    )


def verify_impact_statement_requirement(document: dict[str, Any]) -> VerificationResult:
    """Test 1.11: Impact Statement Requirement.

    For every product listed in /vulnerabilities[]/product_status/known_not_affected,
    an impact statement SHALL exist as a machine-readable flag in /vulnerabilities[]/flags
    or as a human-readable justification in /vulnerabilities[]/threats with category: impact
    (CSAF Mandatory Test 6.1.27.9).
    """
    errors = []

    for i, vuln in enumerate(document.get("vulnerabilities", [])):
        vuln_id = vuln.get("cve") or vuln.get("ids", [{}])[0].get("text", f"index {i}")
        known_not_affected = set(vuln.get("product_status", {}).get("known_not_affected", []))

        if not known_not_affected:
            continue

        # Collect products covered by flags (with VEX justification)
        flagged_products: set[str] = set()
        for flag in vuln.get("flags", []):
            label = flag.get("label", "")
            if label in VEX_JUSTIFICATION_LABELS:
                flagged_products.update(flag.get("product_ids", []))
                flagged_products.update(flag.get("group_ids", []))

        # Collect products covered by threats with category: impact
        threat_products: set[str] = set()
        for threat in vuln.get("threats", []):
            if threat.get("category") == "impact":
                threat_products.update(threat.get("product_ids", []))
                threat_products.update(threat.get("group_ids", []))

        # Check if all known_not_affected have impact statements
        covered = flagged_products | threat_products
        uncovered = known_not_affected - covered
        if uncovered:
            errors.append(
                f"Vulnerability '{vuln_id}': known_not_affected products {list(uncovered)} "
                "have no impact statement (flag or threat)"
            )

    if errors:
        return VerificationResult(
            test_id="1.11",
            test_name="Impact Statement Requirement",
            status=VerificationStatus.FAIL,
            message="Some known_not_affected products lack impact statements",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.27.9",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="1.11",
        test_name="Impact Statement Requirement",
        status=VerificationStatus.PASS,
        message="All known_not_affected products have impact statements",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.27.9",
    )


def verify_remediation_product_reference(document: dict[str, Any]) -> VerificationResult:
    """Test 1.12: Remediation Product Reference.

    Each remediation item in /vulnerabilities[]/remediations MUST include
    at least one group_ids or product_ids reference to specify which product(s)
    it applies to (CSAF Mandatory Test 6.1.29).
    """
    errors = []

    for i, vuln in enumerate(document.get("vulnerabilities", [])):
        vuln_id = vuln.get("cve") or vuln.get("ids", [{}])[0].get("text", f"index {i}")

        for j, rem in enumerate(vuln.get("remediations", [])):
            has_product_ids = bool(rem.get("product_ids"))
            has_group_ids = bool(rem.get("group_ids"))

            if not has_product_ids and not has_group_ids:
                errors.append(
                    f"Vulnerability '{vuln_id}': remediation at index {j} "
                    "has no product_ids or group_ids"
                )

    if errors:
        return VerificationResult(
            test_id="1.12",
            test_name="Remediation Product Reference",
            status=VerificationStatus.FAIL,
            message="Some remediations lack product references",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.29",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="1.12",
        test_name="Remediation Product Reference",
        status=VerificationStatus.PASS,
        message="All remediations have product references",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.29",
    )


def verify_flag_product_reference(document: dict[str, Any]) -> VerificationResult:
    """Test 1.13: Flag Product Reference.

    Each flag item in /vulnerabilities[]/flags MUST include at least one
    group_ids or product_ids reference to specify which product(s) it applies to
    (CSAF Mandatory Test 6.1.32).
    """
    errors = []

    for i, vuln in enumerate(document.get("vulnerabilities", [])):
        vuln_id = vuln.get("cve") or vuln.get("ids", [{}])[0].get("text", f"index {i}")

        for j, flag in enumerate(vuln.get("flags", [])):
            has_product_ids = bool(flag.get("product_ids"))
            has_group_ids = bool(flag.get("group_ids"))

            if not has_product_ids and not has_group_ids:
                errors.append(
                    f"Vulnerability '{vuln_id}': flag at index {j} has no product_ids or group_ids"
                )

    if errors:
        return VerificationResult(
            test_id="1.13",
            test_name="Flag Product Reference",
            status=VerificationStatus.FAIL,
            message="Some flags lack product references",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.32",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="1.13",
        test_name="Flag Product Reference",
        status=VerificationStatus.PASS,
        message="All flags have product references",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.32",
    )


def verify_unique_vex_justification(document: dict[str, Any]) -> VerificationResult:
    """Test 1.14: Unique VEX Justification.

    A product MUST NOT be a member of more than one Flag item utilizing
    a VEX justification code (e.g., component_not_present)
    (CSAF Mandatory Test 6.1.33).
    """
    errors = []

    for i, vuln in enumerate(document.get("vulnerabilities", [])):
        vuln_id = vuln.get("cve") or vuln.get("ids", [{}])[0].get("text", f"index {i}")

        # Track which products have VEX justification flags
        product_justifications: dict[str, list[str]] = defaultdict(list)

        for flag in vuln.get("flags", []):
            label = flag.get("label", "")
            if label not in VEX_JUSTIFICATION_LABELS:
                continue

            # Collect all products in this flag
            products = set(flag.get("product_ids", []))
            products.update(flag.get("group_ids", []))

            for product in products:
                product_justifications[product].append(label)

        # Check for products with multiple justifications
        for product, justifications in product_justifications.items():
            if len(justifications) > 1:
                errors.append(
                    f"Vulnerability '{vuln_id}': product '{product}' has multiple "
                    f"VEX justifications: {justifications}"
                )

    if errors:
        return VerificationResult(
            test_id="1.14",
            test_name="Unique VEX Justification",
            status=VerificationStatus.FAIL,
            message="Some products have multiple VEX justifications",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.33",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="1.14",
        test_name="Unique VEX Justification",
        status=VerificationStatus.PASS,
        message="All products have unique VEX justifications",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.33",
    )


# Export all test functions
ALL_CSAF_COMPLIANCE_TESTS = [
    verify_vex_profile_conformance,
    verify_base_mandatory_fields,
    verify_vex_product_status_existence,
    verify_vulnerability_id_existence,
    verify_vulnerability_notes_existence,
    verify_product_id_defined,
    verify_product_id_unique,
    verify_no_circular_references,
    verify_no_contradicting_status,
    verify_action_statement_requirement,
    verify_impact_statement_requirement,
    verify_remediation_product_reference,
    verify_flag_product_reference,
    verify_unique_vex_justification,
]
