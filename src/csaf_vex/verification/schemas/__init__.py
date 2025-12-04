"""JSON schemas for CSAF VEX verification."""

from pathlib import Path

SCHEMAS_DIR = Path(__file__).parent

CSAF_2_0_SCHEMA_PATH = SCHEMAS_DIR / "csaf_2_0.json"
CVSS_V2_0_SCHEMA_PATH = SCHEMAS_DIR / "cvss_v2_0.json"
CVSS_V3_0_SCHEMA_PATH = SCHEMAS_DIR / "cvss_v3_0.json"
CVSS_V3_1_SCHEMA_PATH = SCHEMAS_DIR / "cvss_v3_1.json"
