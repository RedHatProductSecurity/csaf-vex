"""Root CSAF VEX document model."""

import json
from pathlib import Path
from typing import Any

import attrs

from csaf_vex.models.common import SerializableModel, serialize_value
from csaf_vex.models.document import Document
from csaf_vex.models.product_tree import ProductTree
from csaf_vex.models.vulnerability import Vulnerability


@attrs.define
class CSAFVEX(SerializableModel):
    """Represents a complete CSAF VEX file."""

    document: Document
    product_tree: ProductTree | None = attrs.field(default=None)
    vulnerabilities: list[Vulnerability] = attrs.field(factory=list)

    raw_data: dict[str, Any] | None = attrs.field(default=None, repr=False)

    @classmethod
    def from_file(cls, file_path: str | Path) -> "CSAFVEX":
        """Create a CSAFVEX from a JSON file.

        Args:
            file_path: Path to the CSAF VEX JSON file
        """
        path = Path(file_path)
        with path.open() as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CSAFVEX":
        """Create a CSAFVEX from a dictionary (parsed JSON).

        Args:
            data: The complete parsed CSAF VEX JSON data
        """
        product_tree_data = data.get("product_tree")
        vulnerabilities_data = data.get("vulnerabilities", [])

        return cls(
            document=Document.from_dict(data.get("document", {})),
            product_tree=ProductTree.from_dict(product_tree_data)
            if product_tree_data is not None
            else None,
            vulnerabilities=[Vulnerability.from_dict(v) for v in vulnerabilities_data],
            raw_data=data,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to a dictionary, excluding fields marked with repr=False and empty lists."""
        return attrs.asdict(
            self,
            filter=lambda attr, value: value is not None and value != [] and attr.repr,
            value_serializer=serialize_value,
        )
