"""Test Set 2: Data Type Checking Tests.

This module implements tests 2.1-2.16 for verifying data format compliance,
patterns, and schema constraints derived from CSAF Section 3 (Schema Elements)
and Section 6.1 (Mandatory Tests).
"""

import json
import re
from pathlib import Path
from typing import Any

from cvss import CVSS2, CVSS3, CVSS4
from packageurl import PackageURL

from .result import VerificationResult, VerificationSeverity, VerificationStatus

# Lazy-loaded schema cache
_SCHEMA_CACHE: dict[str, Any] = {}

# CPE 2.3 pattern (Formatted String Binding)
CPE_23_PATTERN = re.compile(
    r"^cpe:2\.3:[aho\*\-]"
    r"(?::[A-Za-z0-9\._\-\*\?\\]*){10}"
    r"$"
)

# CPE 2.2 pattern (URI Binding) - case-insensitive prefix per CSAF 2.0 schema
CPE_22_PATTERN = re.compile(
    r"^[cC][pP][eE]:/[AHOaho]?"
    r"(?::[A-Za-z0-9\._\-~%]*){0,6}"
    r"$"
)

# CVE ID pattern
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

# CWE ID pattern (per CSAF 2.0 schema: first digit 1-9, then 0-5 more digits)
CWE_PATTERN = re.compile(r"^CWE-[1-9]\d{0,5}$")

# ISO 8601 / RFC 3339 date-time pattern
DATETIME_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)

# BCP 47 / RFC 5646 language code pattern (simplified)
LANGUAGE_CODE_PATTERN = re.compile(
    r"^[a-zA-Z]{2,3}"  # Primary language
    r"(?:-[a-zA-Z]{4})?"  # Optional script
    r"(?:-[a-zA-Z]{2}|\d{3})?"  # Optional region
    r"(?:-[a-zA-Z0-9]{5,8})*"  # Optional variants
    r"$"
)

# Semantic version pattern
SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:-[a-zA-Z0-9\.\-]+)?(?:\+[a-zA-Z0-9\.\-]+)?$")

# Integer version pattern
INT_VERSION_PATTERN = re.compile(r"^\d+$")

# Version range indicators to detect in product_version names
# Operators use substring matching (unlikely to appear in package names)
# Sorted by length (longest first) to ensure ">=" is checked before ">"
VERSION_RANGE_OPERATORS = ("<=", ">=", "!=", "==", "<", ">")

# Phrase indicators - these multi-word phrases are unlikely to appear in package names
# and can use simple word-boundary matching
VERSION_RANGE_PHRASES = frozenset(
    {
        "and later",
        "and earlier",
        "or later",
        "or earlier",
        "or above",
        "or below",
    }
)

# Precompiled regex patterns for phrase matching (case-insensitive)
_VERSION_RANGE_PHRASE_PATTERNS = {
    phrase: re.compile(rf"\b{re.escape(phrase)}\b", re.IGNORECASE)
    for phrase in VERSION_RANGE_PHRASES
}

# Single-word range indicators require version range context to avoid false positives
# when they appear as part of package names (e.g., "nodejs-through", "aftermath")
# These patterns match: "<word> <version>" or "<version> <word>" contexts
_VERSION_RANGE_WORD_CONTEXT_PATTERNS = {
    # "after X" where X looks like a version (contains digits)
    "after": re.compile(r"\bafter\s+\S*\d", re.IGNORECASE),
    # "before X" where X looks like a version
    "before": re.compile(r"\bbefore\s+\S*\d", re.IGNORECASE),
    # "prior to X" - common phrase
    "prior": re.compile(r"\bprior\s+to\b", re.IGNORECASE),
    # "since X" where X looks like a version
    "since": re.compile(r"\bsince\s+\S*\d", re.IGNORECASE),
    # "until X" where X looks like a version
    "until": re.compile(r"\buntil\s+\S*\d", re.IGNORECASE),
    # "X through Y" where both contain digits: "1.0 through 2.0"
    "through": re.compile(r"\S*\d\S*\s+through\s+\S*\d", re.IGNORECASE),
    # "X thru Y" where both contain digits
    "thru": re.compile(r"\S*\d\S*\s+thru\s+\S*\d", re.IGNORECASE),
    # "X to Y" where both contain digits, or "prior/up to X"
    "to": [
        re.compile(r"\S*\d\S*\s+to\s+\S*\d", re.IGNORECASE),
        re.compile(r"\b(?:prior|up)\s+to\b", re.IGNORECASE),
    ],
}

# Soft limits
SOFT_LIMIT_FILE_SIZE = 15 * 1024 * 1024  # 15 MB
SOFT_LIMIT_ARRAY_LENGTH = 100_000
SOFT_LIMIT_ID_STRING_LENGTH = 1_000
SOFT_LIMIT_DETAIL_STRING_LENGTH = 30_000
SOFT_LIMIT_NOTES_TEXT_LENGTH = 250_000


def _get_schema(schema_name: str) -> dict[str, Any]:
    """Load and cache a JSON schema."""
    if schema_name not in _SCHEMA_CACHE:
        schema_dir = Path(__file__).parent / "schemas"
        schema_path = schema_dir / f"{schema_name}.json"
        if schema_path.exists():
            with open(schema_path) as f:
                _SCHEMA_CACHE[schema_name] = json.load(f)
        else:
            _SCHEMA_CACHE[schema_name] = {}
    return _SCHEMA_CACHE[schema_name]


def _find_all_values(obj: Any, key: str, values: list[Any] | None = None) -> list[Any]:
    """Recursively find all values for a given key in a nested structure."""
    if values is None:
        values = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                values.append(v)
            _find_all_values(v, key, values)
    elif isinstance(obj, list):
        for item in obj:
            _find_all_values(item, key, values)

    return values


def _find_all_branches_with_category(
    branches: list[dict[str, Any]],
    category: str,
    results: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Recursively find all branches with a specific category."""
    if results is None:
        results = []

    for branch in branches:
        if branch.get("category") == category:
            results.append(branch)
        if nested := branch.get("branches"):
            _find_all_branches_with_category(nested, category, results)

    return results


def verify_json_schema(document: dict[str, Any]) -> VerificationResult:
    """Test 2.1: JSON Schema Validation.

    The entire document MUST be validated against the CSAF JSON schema
    to ensure all elements adhere to defined data types, presence, and
    structural hierarchy.
    """
    try:
        import jsonschema
    except ImportError:
        return VerificationResult(
            test_id="2.1",
            test_name="JSON Schema Validation",
            status=VerificationStatus.SKIP,
            message="jsonschema package not installed",
            severity=VerificationSeverity.WARNING,
            source_ref="CSAF JSON Schema",
        )

    schema = _get_schema("csaf_2_0")
    if not schema:
        return VerificationResult(
            test_id="2.1",
            test_name="JSON Schema Validation",
            status=VerificationStatus.SKIP,
            message="CSAF 2.0 schema not found",
            severity=VerificationSeverity.WARNING,
            source_ref="CSAF JSON Schema",
        )

    try:
        jsonschema.validate(instance=document, schema=schema)
    except jsonschema.ValidationError as e:
        return VerificationResult(
            test_id="2.1",
            test_name="JSON Schema Validation",
            status=VerificationStatus.FAIL,
            message="Document does not conform to CSAF JSON schema",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF JSON Schema",
            details={
                "error": e.message,
                "path": list(e.absolute_path),
                "schema_path": list(e.absolute_schema_path),
            },
        )
    except jsonschema.SchemaError as e:
        return VerificationResult(
            test_id="2.1",
            test_name="JSON Schema Validation",
            status=VerificationStatus.SKIP,
            message=f"Invalid schema: {e.message}",
            severity=VerificationSeverity.WARNING,
            source_ref="CSAF JSON Schema",
        )

    return VerificationResult(
        test_id="2.1",
        test_name="JSON Schema Validation",
        status=VerificationStatus.PASS,
        message="Document conforms to CSAF JSON schema",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF JSON Schema",
    )


def _is_valid_purl(purl: str) -> bool:
    """Check if a string is a valid PURL using the official packageurl library."""
    try:
        PackageURL.from_string(purl)
        return True
    except ValueError:
        return False


def verify_purl_format(document: dict[str, Any]) -> VerificationResult:
    """Test 2.2: PURL Format Validation.

    Any value provided for purl (for components) MUST adhere to the standard
    PURL format as defined by the Package URL specification.
    Uses the official packageurl-python library for validation.
    (CSAF Mandatory Test 6.1.13).
    """
    purls = _find_all_values(document, "purl")

    if not purls:
        return VerificationResult(
            test_id="2.2",
            test_name="PURL Format Validation",
            status=VerificationStatus.SKIP,
            message="No PURL values found in document",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF Mandatory Test 6.1.13",
        )

    invalid_purls = [p for p in purls if isinstance(p, str) and not _is_valid_purl(p)]

    if invalid_purls:
        return VerificationResult(
            test_id="2.2",
            test_name="PURL Format Validation",
            status=VerificationStatus.FAIL,
            message="Invalid PURL format detected",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.13",
            details={"invalid_purls": invalid_purls},
        )

    return VerificationResult(
        test_id="2.2",
        test_name="PURL Format Validation",
        status=VerificationStatus.PASS,
        message=f"All {len(purls)} PURL values are valid",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.13",
    )


def verify_cpe_format(document: dict[str, Any]) -> VerificationResult:
    """Test 2.3: CPE Format Validation.

    Any value provided for cpe (for products) MUST adhere to the specified
    complex regex pattern for CPE Version 2.3 or CPE Version 2.2 (URI binding).
    """
    cpes = _find_all_values(document, "cpe")

    if not cpes:
        return VerificationResult(
            test_id="2.3",
            test_name="CPE Format Validation",
            status=VerificationStatus.SKIP,
            message="No CPE values found in document",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF CPE Format",
        )

    invalid_cpes = []
    cpe_23_list: list[str] = []
    cpe_22_list: list[str] = []

    for cpe in cpes:
        if not isinstance(cpe, str):
            invalid_cpes.append(cpe)
            continue

        # Check CPE 2.3 format first (more common/preferred)
        if CPE_23_PATTERN.match(cpe):
            cpe_23_list.append(cpe)
        elif CPE_22_PATTERN.match(cpe):
            cpe_22_list.append(cpe)
        else:
            invalid_cpes.append(cpe)

    # Build format summary
    formats_detected = []
    if cpe_23_list:
        formats_detected.append(f"CPE 2.3: {len(cpe_23_list)}")
    if cpe_22_list:
        formats_detected.append(f"CPE 2.2: {len(cpe_22_list)}")
    format_summary = ", ".join(formats_detected) if formats_detected else "none"

    if invalid_cpes:
        return VerificationResult(
            test_id="2.3",
            test_name="CPE Format Validation",
            status=VerificationStatus.FAIL,
            message=f"Invalid CPE format detected (valid formats: {format_summary})",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF CPE Format",
            details={
                "invalid_cpes": invalid_cpes,
                "cpe_23_count": len(cpe_23_list),
                "cpe_22_count": len(cpe_22_list),
                "cpe_23_values": cpe_23_list,
                "cpe_22_values": cpe_22_list,
            },
        )

    return VerificationResult(
        test_id="2.3",
        test_name="CPE Format Validation",
        status=VerificationStatus.PASS,
        message=f"All {len(cpes)} CPE values are valid ({format_summary})",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF CPE Format",
        details={
            "cpe_23_count": len(cpe_23_list),
            "cpe_22_count": len(cpe_22_list),
            "cpe_23_values": cpe_23_list,
            "cpe_22_values": cpe_22_list,
        },
    )


def verify_datetime_format(document: dict[str, Any]) -> VerificationResult:
    """Test 2.4: Date-Time Format Validation.

    All date/time fields (current_release_date, initial_release_date,
    revision_history[].date, discovery_date, etc.) MUST use the
    ISO 8601/RFC 3339 date-time format.
    """
    datetime_fields = [
        "current_release_date",
        "initial_release_date",
        "date",
        "discovery_date",
        "release_date",
    ]

    all_datetimes: list[tuple[str, str]] = []
    for field in datetime_fields:
        values = _find_all_values(document, field)
        for v in values:
            if isinstance(v, str):
                all_datetimes.append((field, v))

    if not all_datetimes:
        return VerificationResult(
            test_id="2.4",
            test_name="Date-Time Format Validation",
            status=VerificationStatus.SKIP,
            message="No date-time values found in document",
            severity=VerificationSeverity.INFO,
            source_ref="ISO 8601/RFC 3339",
        )

    invalid_datetimes = [
        (field, value) for field, value in all_datetimes if not DATETIME_PATTERN.match(value)
    ]

    if invalid_datetimes:
        return VerificationResult(
            test_id="2.4",
            test_name="Date-Time Format Validation",
            status=VerificationStatus.FAIL,
            message="Invalid date-time format detected",
            severity=VerificationSeverity.ERROR,
            source_ref="ISO 8601/RFC 3339",
            details={"invalid_datetimes": invalid_datetimes},
        )

    return VerificationResult(
        test_id="2.4",
        test_name="Date-Time Format Validation",
        status=VerificationStatus.PASS,
        message=f"All {len(all_datetimes)} date-time values are valid",
        severity=VerificationSeverity.INFO,
        source_ref="ISO 8601/RFC 3339",
    )


def verify_cve_id_format(document: dict[str, Any]) -> VerificationResult:
    """Test 2.5: CVE ID Format.

    Any entry in /vulnerabilities[]/cve MUST match the CVE ID format regex:
    ^CVE-\\d{4}-\\d{4,}$.
    """
    cves = _find_all_values(document, "cve")

    if not cves:
        return VerificationResult(
            test_id="2.5",
            test_name="CVE ID Format",
            status=VerificationStatus.SKIP,
            message="No CVE values found in document",
            severity=VerificationSeverity.INFO,
            source_ref="CVE ID Format",
        )

    invalid_cves = [c for c in cves if isinstance(c, str) and not CVE_PATTERN.match(c)]

    if invalid_cves:
        return VerificationResult(
            test_id="2.5",
            test_name="CVE ID Format",
            status=VerificationStatus.FAIL,
            message="Invalid CVE ID format detected",
            severity=VerificationSeverity.ERROR,
            source_ref="CVE ID Format",
            details={"invalid_cves": invalid_cves},
        )

    return VerificationResult(
        test_id="2.5",
        test_name="CVE ID Format",
        status=VerificationStatus.PASS,
        message=f"All {len(cves)} CVE IDs are valid",
        severity=VerificationSeverity.INFO,
        source_ref="CVE ID Format",
    )


def verify_cwe_id_format(document: dict[str, Any]) -> VerificationResult:
    """Test 2.6: CWE ID Format.

    The CWE ID (/vulnerabilities[]/cwe/id) MUST match the format regex:
    ^CWE-\\d{0,5}$.
    """
    cwes = _find_all_values(document, "cwe")
    cwe_ids = [c.get("id") for c in cwes if isinstance(c, dict) and c.get("id")]

    if not cwe_ids:
        return VerificationResult(
            test_id="2.6",
            test_name="CWE ID Format",
            status=VerificationStatus.SKIP,
            message="No CWE IDs found in document",
            severity=VerificationSeverity.INFO,
            source_ref="CWE ID Format",
        )

    invalid_cwes = [c for c in cwe_ids if not CWE_PATTERN.match(c)]

    if invalid_cwes:
        return VerificationResult(
            test_id="2.6",
            test_name="CWE ID Format",
            status=VerificationStatus.FAIL,
            message="Invalid CWE ID format detected",
            severity=VerificationSeverity.ERROR,
            source_ref="CWE ID Format",
            details={"invalid_cwes": invalid_cwes},
        )

    return VerificationResult(
        test_id="2.6",
        test_name="CWE ID Format",
        status=VerificationStatus.PASS,
        message=f"All {len(cwe_ids)} CWE IDs are valid",
        severity=VerificationSeverity.INFO,
        source_ref="CWE ID Format",
    )


def verify_language_code_format(document: dict[str, Any]) -> VerificationResult:
    """Test 2.7: Language Code Format.

    All language fields (lang, source_lang) MUST adhere to the
    IETF BCP 47 / RFC 5646 language code pattern.
    """
    lang_fields = ["lang", "source_lang"]
    all_langs: list[tuple[str, str]] = []

    for field in lang_fields:
        values = _find_all_values(document, field)
        for v in values:
            if isinstance(v, str):
                all_langs.append((field, v))

    if not all_langs:
        return VerificationResult(
            test_id="2.7",
            test_name="Language Code Format",
            status=VerificationStatus.SKIP,
            message="No language codes found in document",
            severity=VerificationSeverity.INFO,
            source_ref="IETF BCP 47 / RFC 5646",
        )

    invalid_langs = [
        (field, value) for field, value in all_langs if not LANGUAGE_CODE_PATTERN.match(value)
    ]

    if invalid_langs:
        return VerificationResult(
            test_id="2.7",
            test_name="Language Code Format",
            status=VerificationStatus.FAIL,
            message="Invalid language code format detected",
            severity=VerificationSeverity.ERROR,
            source_ref="IETF BCP 47 / RFC 5646",
            details={"invalid_langs": invalid_langs},
        )

    return VerificationResult(
        test_id="2.7",
        test_name="Language Code Format",
        status=VerificationStatus.PASS,
        message=f"All {len(all_langs)} language codes are valid",
        severity=VerificationSeverity.INFO,
        source_ref="IETF BCP 47 / RFC 5646",
    )


def verify_version_range_prohibition(document: dict[str, Any]) -> VerificationResult:
    """Test 2.8: Version Range Prohibition.

    For any branch labeled product_version, the associated name attribute
    MUST NOT contain version ranges of any kind (CSAF Mandatory Test 6.1.31).
    """
    product_tree = document.get("product_tree", {})
    branches = product_tree.get("branches", [])

    if not branches:
        return VerificationResult(
            test_id="2.8",
            test_name="Version Range Prohibition",
            status=VerificationStatus.SKIP,
            message="No branches found in product_tree",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF Mandatory Test 6.1.31",
        )

    version_branches = _find_all_branches_with_category(branches, "product_version")

    if not version_branches:
        return VerificationResult(
            test_id="2.8",
            test_name="Version Range Prohibition",
            status=VerificationStatus.SKIP,
            message="No product_version branches found",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF Mandatory Test 6.1.31",
        )

    invalid_versions = []
    for branch in version_branches:
        name = branch.get("name", "")
        found_indicator = False

        # Check operators (substring match is fine - unlikely false positives)
        for operator in VERSION_RANGE_OPERATORS:
            if operator in name:
                invalid_versions.append({"name": name, "indicator": operator})
                found_indicator = True
                break

        if not found_indicator:
            # Check multi-word phrases (unlikely to appear in package names)
            for phrase, pattern in _VERSION_RANGE_PHRASE_PATTERNS.items():
                if pattern.search(name):
                    invalid_versions.append({"name": name, "indicator": phrase})
                    found_indicator = True
                    break

        if not found_indicator:
            # Check single-word indicators with version range context
            # to avoid false positives like "nodejs-through", "aftermath", etc.
            for word, patterns in _VERSION_RANGE_WORD_CONTEXT_PATTERNS.items():
                # Handle both single pattern and list of patterns
                pattern_list = patterns if isinstance(patterns, list) else [patterns]
                for pattern in pattern_list:
                    if pattern.search(name):
                        invalid_versions.append({"name": name, "indicator": word})
                        found_indicator = True
                        break
                if found_indicator:
                    break

    if invalid_versions:
        return VerificationResult(
            test_id="2.8",
            test_name="Version Range Prohibition",
            status=VerificationStatus.FAIL,
            message="Version ranges detected in product_version names",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.31",
            details={"invalid_versions": invalid_versions},
        )

    return VerificationResult(
        test_id="2.8",
        test_name="Version Range Prohibition",
        status=VerificationStatus.PASS,
        message=f"All {len(version_branches)} product_version names are valid",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.31",
    )


def verify_mixed_versioning_prohibition(document: dict[str, Any]) -> VerificationResult:
    """Test 2.9: Mixed Versioning Prohibition.

    The document MUST use either integer versioning or semantic versioning
    homogeneously across all elements of type version_t
    (/document/tracking/version and /document/tracking/revision_history[]/number)
    (CSAF Mandatory Test 6.1.30).
    """
    tracking = document.get("document", {}).get("tracking", {})

    versions: list[str] = []

    # Get main version
    if main_version := tracking.get("version"):
        versions.append(main_version)

    # Get revision history versions
    for rev in tracking.get("revision_history", []):
        if rev_number := rev.get("number"):
            versions.append(rev_number)

    if not versions:
        return VerificationResult(
            test_id="2.9",
            test_name="Mixed Versioning Prohibition",
            status=VerificationStatus.SKIP,
            message="No version information found",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF Mandatory Test 6.1.30",
        )

    # Classify each version
    int_versions = [v for v in versions if INT_VERSION_PATTERN.match(v)]
    semver_versions = [v for v in versions if SEMVER_PATTERN.match(v)]

    # Check for mixed versioning
    has_int = len(int_versions) > 0
    has_semver = len(semver_versions) > 0
    unclassified = [v for v in versions if v not in int_versions and v not in semver_versions]

    if has_int and has_semver:
        return VerificationResult(
            test_id="2.9",
            test_name="Mixed Versioning Prohibition",
            status=VerificationStatus.FAIL,
            message="Mixed integer and semantic versioning detected",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.30",
            details={
                "integer_versions": int_versions,
                "semantic_versions": semver_versions,
            },
        )

    if unclassified:
        return VerificationResult(
            test_id="2.9",
            test_name="Mixed Versioning Prohibition",
            status=VerificationStatus.WARN,
            message="Some versions could not be classified",
            severity=VerificationSeverity.WARNING,
            source_ref="CSAF Mandatory Test 6.1.30",
            details={"unclassified": unclassified},
        )

    version_type = "integer" if has_int else "semantic"
    return VerificationResult(
        test_id="2.9",
        test_name="Mixed Versioning Prohibition",
        status=VerificationStatus.PASS,
        message=f"Homogeneous {version_type} versioning used",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.30",
    )


def _parse_cvss_vector(vector_string: str) -> CVSS2 | CVSS3 | CVSS4 | None:
    """Parse a CVSS vector string using the appropriate parser.

    Returns the parsed CVSS object or None if parsing fails.
    """
    if not vector_string:
        return None

    try:
        if vector_string.startswith("CVSS:4"):
            return CVSS4(vector_string)
        elif vector_string.startswith("CVSS:3"):
            return CVSS3(vector_string)
        else:
            # CVSS v2 vectors don't have a prefix
            return CVSS2(vector_string)
    except Exception:
        return None


def verify_cvss_syntax(document: dict[str, Any]) -> VerificationResult:
    """Test 2.10: CVSS Syntax Validation.

    Any provided CVSS object (cvss_v2, cvss_v3) MUST be valid according
    to its referenced external schema (CSAF Mandatory Test 6.1.8).

    Uses the cvss library for accurate parsing and validation.
    """
    # Find all CVSS objects in scores
    scores = _find_all_values(document, "scores")
    cvss_objects: list[tuple[str, dict[str, Any]]] = []

    for score_list in scores:
        if isinstance(score_list, list):
            for score in score_list:
                if isinstance(score, dict):
                    if cvss_v2 := score.get("cvss_v2"):
                        cvss_objects.append(("cvss_v2", cvss_v2))
                    if cvss_v3 := score.get("cvss_v3"):
                        cvss_objects.append(("cvss_v3", cvss_v3))
                    if cvss_v4 := score.get("cvss_v4"):
                        cvss_objects.append(("cvss_v4", cvss_v4))

    if not cvss_objects:
        return VerificationResult(
            test_id="2.10",
            test_name="CVSS Syntax Validation",
            status=VerificationStatus.SKIP,
            message="No CVSS objects found in document",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF Mandatory Test 6.1.8",
        )

    errors = []
    for cvss_type, cvss_obj in cvss_objects:
        vector_string = cvss_obj.get("vectorString", "")

        if not vector_string:
            errors.append({"type": cvss_type, "error": "Missing vectorString"})
            continue

        try:
            if cvss_type == "cvss_v4":
                CVSS4(vector_string)
            elif cvss_type == "cvss_v3":
                CVSS3(vector_string)
            elif cvss_type == "cvss_v2":
                CVSS2(vector_string)
        except Exception as e:
            errors.append({"type": cvss_type, "vector": vector_string, "error": str(e)})

    if errors:
        return VerificationResult(
            test_id="2.10",
            test_name="CVSS Syntax Validation",
            status=VerificationStatus.FAIL,
            message="Invalid CVSS vector strings detected",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.8",
            details={"errors": errors},
        )

    return VerificationResult(
        test_id="2.10",
        test_name="CVSS Syntax Validation",
        status=VerificationStatus.PASS,
        message=f"All {len(cvss_objects)} CVSS vectors are valid",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.8",
    )


def verify_cvss_calculation(document: dict[str, Any]) -> VerificationResult:
    """Test 2.11: CVSS Calculation Validation.

    The derived scores (Base, Temporal, Environmental) MUST be computed
    correctly based on the vectorString. The vectorString SHOULD take
    precedence (CSAF Mandatory Test 6.1.9).

    Uses the cvss library to compute actual scores and compare against document values.
    """
    scores = _find_all_values(document, "scores")
    cvss_objects: list[tuple[str, dict[str, Any]]] = []

    for score_list in scores:
        if isinstance(score_list, list):
            for score in score_list:
                if isinstance(score, dict):
                    if cvss_v4 := score.get("cvss_v4"):
                        cvss_objects.append(("cvss_v4", cvss_v4))
                    if cvss_v3 := score.get("cvss_v3"):
                        cvss_objects.append(("cvss_v3", cvss_v3))
                    if cvss_v2 := score.get("cvss_v2"):
                        cvss_objects.append(("cvss_v2", cvss_v2))

    if not cvss_objects:
        return VerificationResult(
            test_id="2.11",
            test_name="CVSS Calculation Validation",
            status=VerificationStatus.SKIP,
            message="No CVSS objects found in document",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF Mandatory Test 6.1.9",
        )

    errors = []
    for cvss_type, cvss_obj in cvss_objects:
        vector_string = cvss_obj.get("vectorString")
        if not vector_string:
            continue

        # Parse the vector and compute scores
        parsed = _parse_cvss_vector(vector_string)
        if not parsed:
            continue  # Syntax validation handles invalid vectors

        computed_scores = parsed.scores()
        doc_base_score = cvss_obj.get("baseScore")

        # Compare base score (first element in scores tuple)
        if doc_base_score is not None:
            computed_base = computed_scores[0]
            # Allow for small floating point differences
            if abs(float(doc_base_score) - computed_base) > 0.1:
                errors.append(
                    {
                        "type": cvss_type,
                        "vector": vector_string,
                        "field": "baseScore",
                        "document_value": doc_base_score,
                        "computed_value": computed_base,
                    }
                )

        # For CVSS v2/v3, check temporal and environmental scores if present
        if cvss_type in ("cvss_v2", "cvss_v3") and len(computed_scores) >= 2:
            doc_temporal = cvss_obj.get("temporalScore")
            if doc_temporal is not None:
                computed_temporal = computed_scores[1]
                if abs(float(doc_temporal) - computed_temporal) > 0.1:
                    errors.append(
                        {
                            "type": cvss_type,
                            "vector": vector_string,
                            "field": "temporalScore",
                            "document_value": doc_temporal,
                            "computed_value": computed_temporal,
                        }
                    )

            if len(computed_scores) >= 3:
                doc_environmental = cvss_obj.get("environmentalScore")
                if doc_environmental is not None:
                    computed_environmental = computed_scores[2]
                    if abs(float(doc_environmental) - computed_environmental) > 0.1:
                        errors.append(
                            {
                                "type": cvss_type,
                                "vector": vector_string,
                                "field": "environmentalScore",
                                "document_value": doc_environmental,
                                "computed_value": computed_environmental,
                            }
                        )

    if errors:
        return VerificationResult(
            test_id="2.11",
            test_name="CVSS Calculation Validation",
            status=VerificationStatus.FAIL,
            message="CVSS scores do not match computed values from vectorString",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.9",
            details={"score_mismatches": errors},
        )

    return VerificationResult(
        test_id="2.11",
        test_name="CVSS Calculation Validation",
        status=VerificationStatus.PASS,
        message=f"All {len(cvss_objects)} CVSS scores match computed values",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.9",
    )


def verify_cvss_vector_consistency(document: dict[str, Any]) -> VerificationResult:
    """Test 2.12: CVSS Vector Consistency.

    The given CVSS properties (e.g., attackVector, scope) MUST NOT contradict
    the values encoded in the vectorString (CSAF Mandatory Test 6.1.10).

    Uses the cvss library's clean_vector() to get the canonical vector string
    and compares it with the provided vector to detect inconsistencies.
    """
    # CVSS v3 abbreviation mappings (vector abbreviation -> JSON property name)
    cvss_v3_abbrev_to_prop = {
        "AV": "attackVector",
        "AC": "attackComplexity",
        "PR": "privilegesRequired",
        "UI": "userInteraction",
        "S": "scope",
        "C": "confidentialityImpact",
        "I": "integrityImpact",
        "A": "availabilityImpact",
    }

    # Reverse mapping for vector values to full names
    cvss_v3_value_to_full = {
        "AV": {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"},
        "AC": {"L": "LOW", "H": "HIGH"},
        "PR": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "UI": {"N": "NONE", "R": "REQUIRED"},
        "S": {"U": "UNCHANGED", "C": "CHANGED"},
        "C": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "I": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        "A": {"N": "NONE", "L": "LOW", "H": "HIGH"},
    }

    scores = _find_all_values(document, "scores")
    cvss_objects: list[tuple[str, dict[str, Any]]] = []

    for score_list in scores:
        if isinstance(score_list, list):
            for score in score_list:
                if isinstance(score, dict):
                    if cvss_v3 := score.get("cvss_v3"):
                        cvss_objects.append(("cvss_v3", cvss_v3))
                    if cvss_v2 := score.get("cvss_v2"):
                        cvss_objects.append(("cvss_v2", cvss_v2))

    if not cvss_objects:
        return VerificationResult(
            test_id="2.12",
            test_name="CVSS Vector Consistency",
            status=VerificationStatus.SKIP,
            message="No CVSS objects found in document",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF Mandatory Test 6.1.10",
        )

    inconsistencies = []
    for cvss_type, cvss_obj in cvss_objects:
        vector_string = cvss_obj.get("vectorString", "")
        if not vector_string:
            continue

        # Parse the vector using the cvss library
        parsed = _parse_cvss_vector(vector_string)
        if not parsed:
            continue  # Syntax validation handles invalid vectors

        # For CVSS v3, check property consistency
        if cvss_type == "cvss_v3" and isinstance(parsed, CVSS3):
            # Parse vector parts from the clean vector
            clean_vector = parsed.clean_vector()
            vector_parts = {}
            for part in clean_vector.split("/"):
                if ":" in part:
                    key, value = part.split(":", 1)
                    vector_parts[key] = value

            # Check each property against the parsed vector
            for abbrev, prop_name in cvss_v3_abbrev_to_prop.items():
                doc_value = cvss_obj.get(prop_name)
                if doc_value is None:
                    continue

                vector_value = vector_parts.get(abbrev)
                if vector_value:
                    expected_full = cvss_v3_value_to_full.get(abbrev, {}).get(vector_value)
                    if expected_full and doc_value != expected_full:
                        inconsistencies.append(
                            {
                                "type": cvss_type,
                                "property": prop_name,
                                "document_value": doc_value,
                                "vector_value": vector_value,
                                "expected": expected_full,
                            }
                        )

    if inconsistencies:
        return VerificationResult(
            test_id="2.12",
            test_name="CVSS Vector Consistency",
            status=VerificationStatus.FAIL,
            message="CVSS properties contradict vectorString",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Mandatory Test 6.1.10",
            details={"inconsistencies": inconsistencies},
        )

    return VerificationResult(
        test_id="2.12",
        test_name="CVSS Vector Consistency",
        status=VerificationStatus.PASS,
        message="All CVSS properties consistent with vectorString",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Mandatory Test 6.1.10",
    )


def verify_soft_limit_file_size(
    document: dict[str, Any], raw_content: bytes | str | None = None
) -> VerificationResult:
    """Test 2.13: Soft Limits Check: File Size.

    The total file size of the CSAF document SHOULD NOT exceed 15 MB
    to ensure processability by CSAF consumers and adherence to BSON/database limits.
    """
    if raw_content is not None:
        if isinstance(raw_content, str):
            size = len(raw_content.encode("utf-8"))
        else:
            size = len(raw_content)
    else:
        # Estimate size by serializing
        size = len(json.dumps(document).encode("utf-8"))

    if size > SOFT_LIMIT_FILE_SIZE:
        size_mb = size / (1024 * 1024)
        return VerificationResult(
            test_id="2.13",
            test_name="Soft Limits Check: File Size",
            status=VerificationStatus.WARN,
            message=f"File size ({size_mb:.2f} MB) exceeds soft limit (15 MB)",
            severity=VerificationSeverity.WARNING,
            source_ref="CSAF Soft Limits",
            details={"size_bytes": size, "limit_bytes": SOFT_LIMIT_FILE_SIZE},
        )

    return VerificationResult(
        test_id="2.13",
        test_name="Soft Limits Check: File Size",
        status=VerificationStatus.PASS,
        message=f"File size ({size / 1024:.2f} KB) within soft limit",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Soft Limits",
    )


def verify_soft_limit_array_length(document: dict[str, Any]) -> VerificationResult:
    """Test 2.14: Soft Limits Check: Array Length.

    Important arrays SHOULD NOT exceed defined soft limits
    (e.g., < 100,000 items for /vulnerabilities, /product_tree/branches,
    and core Product ID lists) to maintain performance and interoperability.
    """
    arrays_to_check = [
        ("/vulnerabilities", document.get("vulnerabilities", [])),
        ("/product_tree/branches", document.get("product_tree", {}).get("branches", [])),
        (
            "/product_tree/full_product_names",
            document.get("product_tree", {}).get("full_product_names", []),
        ),
        (
            "/product_tree/relationships",
            document.get("product_tree", {}).get("relationships", []),
        ),
    ]

    violations = []
    for path, arr in arrays_to_check:
        if isinstance(arr, list) and len(arr) > SOFT_LIMIT_ARRAY_LENGTH:
            violations.append(
                {
                    "path": path,
                    "length": len(arr),
                    "limit": SOFT_LIMIT_ARRAY_LENGTH,
                }
            )

    if violations:
        return VerificationResult(
            test_id="2.14",
            test_name="Soft Limits Check: Array Length",
            status=VerificationStatus.WARN,
            message="Some arrays exceed soft limits",
            severity=VerificationSeverity.WARNING,
            source_ref="CSAF Soft Limits",
            details={"violations": violations},
        )

    return VerificationResult(
        test_id="2.14",
        test_name="Soft Limits Check: Array Length",
        status=VerificationStatus.PASS,
        message="All arrays within soft limits",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Soft Limits",
    )


def verify_soft_limit_string_length(document: dict[str, Any]) -> VerificationResult:
    """Test 2.15: Soft Limits Check: String Length.

    Essential string fields (like IDs, CPEs, PURLs, Names, Titles) SHOULD NOT
    exceed 1,000 characters, while fields intended for human-readable detail
    (like notes[].text, remediations[].details) SHOULD NOT exceed their
    specified soft limits.
    """
    violations = []

    # Check ID-type fields (1000 char limit)
    id_fields = ["product_id", "group_id", "cpe", "purl", "name", "title"]
    for field in id_fields:
        values = _find_all_values(document, field)
        for v in values:
            if isinstance(v, str) and len(v) > SOFT_LIMIT_ID_STRING_LENGTH:
                violations.append(
                    {
                        "field": field,
                        "length": len(v),
                        "limit": SOFT_LIMIT_ID_STRING_LENGTH,
                        "preview": v[:100] + "...",
                    }
                )

    # Check detail fields (30000 char limit)
    detail_fields = ["details", "summary", "description"]
    for field in detail_fields:
        values = _find_all_values(document, field)
        for v in values:
            if isinstance(v, str) and len(v) > SOFT_LIMIT_DETAIL_STRING_LENGTH:
                violations.append(
                    {
                        "field": field,
                        "length": len(v),
                        "limit": SOFT_LIMIT_DETAIL_STRING_LENGTH,
                        "preview": v[:100] + "...",
                    }
                )

    # Check notes text (250000 char limit)
    notes = _find_all_values(document, "notes")
    for note_list in notes:
        if isinstance(note_list, list):
            for note in note_list:
                if isinstance(note, dict):
                    text = note.get("text", "")
                    if isinstance(text, str) and len(text) > SOFT_LIMIT_NOTES_TEXT_LENGTH:
                        violations.append(
                            {
                                "field": "notes[].text",
                                "length": len(text),
                                "limit": SOFT_LIMIT_NOTES_TEXT_LENGTH,
                                "preview": text[:100] + "...",
                            }
                        )

    if violations:
        return VerificationResult(
            test_id="2.15",
            test_name="Soft Limits Check: String Length",
            status=VerificationStatus.WARN,
            message="Some strings exceed soft limits",
            severity=VerificationSeverity.WARNING,
            source_ref="CSAF Soft Limits",
            details={"violations": violations},
        )

    return VerificationResult(
        test_id="2.15",
        test_name="Soft Limits Check: String Length",
        status=VerificationStatus.PASS,
        message="All strings within soft limits",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Soft Limits",
    )


def verify_initial_date_consistency(document: dict[str, Any]) -> VerificationResult:
    """Test 2.16: Initial Date Consistency.

    The value of /document/tracking/initial_release_date MUST be identical
    to the date value in the first entry of /document/tracking/revision_history[].
    """
    tracking = document.get("document", {}).get("tracking", {})

    initial_release_date = tracking.get("initial_release_date")
    revision_history = tracking.get("revision_history", [])

    if not initial_release_date:
        return VerificationResult(
            test_id="2.16",
            test_name="Initial Date Consistency",
            status=VerificationStatus.SKIP,
            message="No initial_release_date found",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF Logic",
        )

    if not revision_history:
        return VerificationResult(
            test_id="2.16",
            test_name="Initial Date Consistency",
            status=VerificationStatus.SKIP,
            message="No revision_history found",
            severity=VerificationSeverity.INFO,
            source_ref="CSAF Logic",
        )

    # Sort revision history by version/number to find the first entry
    # The first entry should be version "1" or the earliest
    sorted_history = sorted(
        revision_history,
        key=lambda x: (
            int(x.get("number", "0")) if x.get("number", "0").isdigit() else 0,
            x.get("date", ""),
        ),
    )

    first_revision = sorted_history[0]
    first_revision_date = first_revision.get("date")

    if first_revision_date != initial_release_date:
        return VerificationResult(
            test_id="2.16",
            test_name="Initial Date Consistency",
            status=VerificationStatus.FAIL,
            message="initial_release_date does not match first revision date",
            severity=VerificationSeverity.ERROR,
            source_ref="CSAF Logic",
            details={
                "initial_release_date": initial_release_date,
                "first_revision_date": first_revision_date,
                "first_revision_number": first_revision.get("number"),
            },
        )

    return VerificationResult(
        test_id="2.16",
        test_name="Initial Date Consistency",
        status=VerificationStatus.PASS,
        message="initial_release_date matches first revision date",
        severity=VerificationSeverity.INFO,
        source_ref="CSAF Logic",
    )


# Export all test functions
ALL_DATA_TYPE_CHECKS = [
    verify_json_schema,
    verify_purl_format,
    verify_cpe_format,
    verify_datetime_format,
    verify_cve_id_format,
    verify_cwe_id_format,
    verify_language_code_format,
    verify_version_range_prohibition,
    verify_mixed_versioning_prohibition,
    verify_cvss_syntax,
    verify_cvss_calculation,
    verify_cvss_vector_consistency,
    verify_soft_limit_file_size,
    verify_soft_limit_array_length,
    verify_soft_limit_string_length,
    verify_initial_date_consistency,
]
