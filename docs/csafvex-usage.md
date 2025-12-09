# CSAF VEX Internal Representation - Usage Guide

## Loading CSAF VEX Documents

### From a File

```python
from csaf_vex.models import CSAFVEX

# Load from JSON file
csafvex = CSAFVEX.from_file("path/to/document.json")
```

### From a Dictionary

```python
import json
from csaf_vex.models import CSAFVEX

# Load from JSON string/dict
with open("document.json") as f:
    data = json.load(f)

csafvex = CSAFVEX.from_dict(data)
```

## Accessing Document Data

### Basic Document Information

```python
# Access document metadata
print(csafvex.document.title)
print(csafvex.document.category)
print(csafvex.document.csaf_version)

# Access publisher information
print(csafvex.document.publisher.name)
print(csafvex.document.publisher.namespace)
print(csafvex.document.publisher.category)

# Access tracking information
print(csafvex.document.tracking.id)
print(csafvex.document.tracking.status)
print(csafvex.document.tracking.version)
print(csafvex.document.tracking.current_release_date)
```

### Product Tree

```python
# Access product tree
if csafvex.product_tree:
    # Iterate through branches
    for branch in csafvex.product_tree.branches:
        print(f"Branch: {branch.name} ({branch.category})")

        # Access nested branches
        for sub_branch in branch.branches:
            print(f"  Sub-branch: {sub_branch.name}")

        # Access product at leaf
        if branch.product:
            print(f"  Product: {branch.product.name}")
            print(f"  Product ID: {branch.product.product_id}")

            # Access product identifiers
            helper = branch.product.product_identification_helper
            if helper:
                if helper.cpe:
                    print(f"  CPE: {helper.cpe}")
                if helper.purl:
                    print(f"  PURL: {helper.purl}")

    # Access relationships
    for rel in csafvex.product_tree.relationships:
        print(f"Relationship: {rel.product_reference} -> {rel.relates_to_product_reference}")
```

### Working with PURLs

```python
from packageurl import PackageURL

# Access PURL from product
for branch in csafvex.product_tree.branches:
    if branch.product and branch.product.product_identification_helper:
        purl = branch.product.product_identification_helper.purl

        # PURL is a PackageURL object
        if isinstance(purl, PackageURL):
            print(f"Type: {purl.type}")
            print(f"Namespace: {purl.namespace}")
            print(f"Name: {purl.name}")
            print(f"Version: {purl.version}")
            print(f"Full PURL: {purl.to_string()}")
```

### Vulnerabilities

```python
# Iterate through vulnerabilities
for vuln in csafvex.vulnerabilities:
    print(f"CVE: {vuln.cve}")
    print(f"Title: {vuln.title}")

    # Access CWE information
    if vuln.cwe:
        print(f"CWE ID: {vuln.cwe.id}")
        print(f"CWE Name: {vuln.cwe.name}")

    # Access notes
    for note in vuln.notes:
        print(f"Note ({note.category}): {note.text}")

    # Access product status
    if vuln.product_status:
        for product_id in vuln.product_status.known_affected:
            print(f"Known affected: {product_id}")
        for product_id in vuln.product_status.fixed:
            print(f"Fixed: {product_id}")
```

### Working with CVSS Scores

```python
from cvss import CVSS2, CVSS3

# Access CVSS scores
for vuln in csafvex.vulnerabilities:
    for score in vuln.scores:
        print(f"Product: {score.products}")

        # CVSS vector is a CVSS2/CVSS3 object
        if isinstance(score.cvss_v3, CVSS3):
            print(f"CVSS v3 Vector: {score.cvss_v3.clean_vector()}")
            print(f"Base Score: {score.cvss_v3.base_score}")
            print(f"Severity: {score.cvss_v3.severities()[0]}")
            print(f"Temporal Score: {score.cvss_v3.temporal_score}")
            print(f"Environmental Score: {score.cvss_v3.environmental_score}")

        elif isinstance(score.cvss_v2, CVSS2):
            print(f"CVSS v2 Vector: {score.cvss_v2.clean_vector()}")
            print(f"Base Score: {score.cvss_v2.base_score}")
```

### Threats and Remediations

```python
# Access threats
for vuln in csafvex.vulnerabilities:
    for threat in vuln.threats:
        print(f"Threat ({threat.category}): {threat.details}")
        print(f"Affected products: {threat.product_ids}")

    # Access remediations
    for remediation in vuln.remediations:
        print(f"Remediation ({remediation.category}): {remediation.details}")
        print(f"Products: {remediation.product_ids}")
        if remediation.url:
            print(f"URL: {remediation.url}")
```

## Serializing to Dictionary

```python
# Convert back to dictionary
data = csafvex.to_dict()

# Save to JSON file
import json
with open("output.json", "w") as f:
    json.dump(data, f, indent=2)
```

### Serialization Notes

The `to_dict()` method automatically handles:
- Converting `datetime` objects to ISO format strings
- Converting `PackageURL` objects to strings
- Converting `CVSS2`/`CVSS3` objects to their JSON representation
- Filtering out `None` values and empty lists
- Recursively serializing nested objects

## Working with Dates

```python
from datetime import datetime

# Dates are parsed as datetime objects
print(csafvex.document.tracking.current_release_date)
print(csafvex.document.tracking.initial_release_date)

# Access revision history
for revision in csafvex.document.tracking.revision_history:
    print(f"Version {revision.number} on {revision.date}: {revision.summary}")
```
