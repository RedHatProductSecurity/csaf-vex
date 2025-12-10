# CSAF VEX Builder Documentation

The `CSAFVEXBuilder` provides a simplified interface for constructing CSAF VEX documents with automatic defaults and smart parameter injection.

## Overview

The builder reduces boilerplate by:
- Accepting CVE ID and title once as top-level parameters
- Auto-injecting these into document and vulnerability sections
- Providing sensible defaults for required CSAF fields
- Handling complex transformations automatically

## Basic Usage

```python
from csaf_vex.builder import CSAFVEXBuilder

vex = CSAFVEXBuilder.build(
    cve_id="CVE-2025-66293",
    title="component: Security Advisory",
    document_data={
        "publisher": {
            "name": "Example Product Security",
            "namespace": "https://example.com",
            "contact_details": "https://example.com/security/contact",
            "issuing_authority": "Example Product Security is responsible...",
        },
        "initial_release_date": "2025-01-01T00:00:00Z",
        "aggregate_severity": {
            "text": "Critical",
            "namespace": "https://example.com/security/classification",
        },
    },
    vulnerability_data={
        "cwe_id": {"id": "CWE-79", "name": "Cross-site Scripting"},
        "discovery_date": "2025-01-01T00:00:00Z",
        "product_status": {
            "known_affected": ["stream1:component1"],
        },
        "score": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "remediation": "Update to the latest version",
        "references": [
            {
                "category": "external",
                "url": "https://example.com/advisory",
                "summary": "Vendor advisory",
            }
        ],
    },
    product_tree_data={
        "name": "Example Vendor",
        "components": [
            {"name": "component1", "purl": "pkg:rpm/example/component1@1.0"}
        ],
        "streams": [
            {"name": "stream1", "cpe": "cpe:/o:example:linux:8"}
        ],
        "products": [
            {
                "name": "Product 1",
                "component": "component1",
                "stream": "stream1",
                "purl": "pkg:rpm/example/component1@1.0",
            }
        ],
    },
)

# Convert to dict and save
with open("vex.json", "w") as f:
    json.dump(vex.to_dict(), f, indent=2)
```

## Parameters

### Required Parameters

#### `cve_id` (str)
CVE identifier. Automatically injected into:
- `document.tracking.id`
- `vulnerability.cve`

**Example:** `"CVE-2025-66293"`

#### `title` (str)
Document and vulnerability title. Automatically injected into:
- `document.title`
- `vulnerability.title`

**Example:** `"openssl: Buffer overflow in SSL parsing"`

### Optional Parameters

#### `document_data` (dict)
Document metadata. The following fields are automatically set if not provided:

**Automatic Defaults:**
- `category`: `"csaf_vex"`
- `csaf_version`: `"2.0"`
- `lang`: `"en"`
- `source_lang`: `"en"`
- `publisher.category`: `"vendor"`
- `distribution.tlp`: `{"label": "WHITE", "url": "https://www.first.org/tlp/"}`
- `tracking.status`: `"final"`
- `tracking.version`: `"1"`
- `tracking.generator.engine.name`: `"csaf-vex"`
- `tracking.generator.engine.version`: Current library version
- `tracking.generator.date`: Current UTC timestamp
- `tracking.current_release_date`: Current UTC timestamp if not provided
- `tracking.revision_history`: Single entry with initial version

**Expected Fields:**
- `publisher` (required): Publisher information
  - `name`: Publisher name
  - `namespace`: Publisher namespace URI
  - `contact_details`: Contact information (optional)
  - `issuing_authority`: Authority statement (optional)
- `initial_release_date`: Initial release date in ISO format (optional)
- `current_release_date`: Current release date (defaults to now)
- `aggregate_severity`: Severity information (optional)
  - `text`: Severity level (e.g., "Critical", "Important")
  - `namespace`: Severity namespace URI
- `distribution`: Distribution rules (optional)
  - `text`: Distribution text
  - `tlp`: TLP information

#### `vulnerability_data` (dict)
Vulnerability information. No need to include CVE ID or title.

**Expected Fields:**
- `cwe_id`: CWE information (optional)
  - `id`: CWE ID (e.g., "CWE-79")
  - `name`: CWE name
- `discovery_date`: Discovery date in ISO format (optional)
- `product_status`: Product status mapping (optional)
  - Maps status to list of product IDs
  - Example: `{"known_affected": ["stream1:component1"]}`
- `score`: CVSS score (optional)
  - `vector`: CVSS vector string
- `remediation`: Remediation text (optional)
- `references`: List of references (optional)
  - `category`: Reference category
  - `url`: Reference URL
  - `summary`: Reference description
- `flags`: List of flags (optional)
  - `label`: Flag label
  - `product_ids`: List of affected product IDs

#### `product_tree_data` (dict)
Product tree structure.

**Expected Fields:**
- `name`: Vendor name (e.g., "Example Vendor")
- `components`: List of component dictionaries
  - `name`: Component name
  - `purl`: Package URL
- `streams`: List of stream dictionaries
  - `name`: Stream name
  - `cpe`: CPE string
- `products`: List of product relationship dictionaries
  - `name`: Product name
  - `component`: Component name (references component from `components`)
  - `stream`: Stream name (references stream from `streams`)
  - `purl`: Package URL

## Available Constants

Import default values for customization:

```python
from csaf_vex.builder import (
    DEFAULT_CATEGORY,
    DEFAULT_CSAF_VERSION,
    DEFAULT_LANG,
    DEFAULT_SOURCE_LANG,
    DEFAULT_PUBLISHER_CATEGORY,
    DEFAULT_TLP_LABEL,
    DEFAULT_TLP_URL,
    DEFAULT_TRACKING_STATUS,
    DEFAULT_TRACKING_VERSION,
    DEFAULT_GENERATOR_ENGINE_NAME,
    DEFAULT_REVISION_NUMBER,
    DEFAULT_REVISION_SUMMARY,
)
```

## Helper Methods

The builder provides static helper methods for product tree construction:

### `_create_stream_branch(name: str, cpe: str) -> Branch`
Create a branch for a stream product.

### `_create_component_branch(name: str, purl: str) -> Branch`
Create a branch for a component product.

### `_create_relationship(component: str, stream: str) -> Relationship`
Create a relationship between component and stream.

## Complete Example

```python
from datetime import datetime, timezone
from csaf_vex.builder import CSAFVEXBuilder

# Prepare data
cve_id = "CVE-2025-12345"
title = "openssl: Critical buffer overflow vulnerability"

document_data = {
    "publisher": {
        "name": "Example Product Security",
        "namespace": "https://example.com",
        "contact_details": "https://example.com/security/contact",
        "issuing_authority": "Example Product Security is responsible for vulnerability handling.",
    },
    "initial_release_date": "2024-01-15T00:00:00Z",
    "aggregate_severity": {
        "text": "Critical",
        "namespace": "https://example.com/security/classification",
    },
}

vulnerability_data = {
    "cwe_id": {"id": "CWE-119", "name": "Buffer Overflow"},
    "discovery_date": "2024-01-10T00:00:00Z",
    "product_status": {
        "known_affected": ["linux-8:openssl", "linux-9:openssl"],
    },
    "score": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "remediation": "Update to openssl version 3.0.8 or later",
    "references": [
        {
            "category": "external",
            "url": "https://example.com/security/cve/CVE-2025-12345",
            "summary": "CVE-2025-12345 on Security Portal",
        },
        {
            "category": "external",
            "url": "https://bugs.example.com/show_bug.cgi?id=123456",
            "summary": "Bug 123456",
        },
    ],
}

product_tree_data = {
    "name": "Example Vendor",
    "components": [
        {"name": "openssl", "purl": "pkg:rpm/example/openssl@3.0.7"},
    ],
    "streams": [
        {"name": "linux-8", "cpe": "cpe:/o:example:linux:8"},
        {"name": "linux-9", "cpe": "cpe:/o:example:linux:9"},
    ],
    "products": [
        {
            "name": "Example Linux 8 - openssl",
            "component": "openssl",
            "stream": "linux-8",
            "purl": "pkg:rpm/example/openssl@3.0.7",
        },
        {
            "name": "Example Linux 9 - openssl",
            "component": "openssl",
            "stream": "linux-9",
            "purl": "pkg:rpm/example/openssl@3.0.7",
        },
    ],
}

# Build VEX document
vex = CSAFVEXBuilder.build(
    cve_id=cve_id,
    title=title,
    document_data=document_data,
    vulnerability_data=vulnerability_data,
    product_tree_data=product_tree_data,
)

# Save to file
import json

with open(f"{cve_id}.json", "w") as f:
    json.dump(vex.to_dict(), f, indent=2)

print(f"Generated VEX document: {cve_id}.json")
```
