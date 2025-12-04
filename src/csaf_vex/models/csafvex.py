"""Internal data models for CSAF VEX documents."""

from typing import Any

import attrs


@attrs.define
class Document:
    """Represents the 'document' section of a CSAF VEX file."""

    title: str | None = attrs.field(default=None)
    category: str | None = attrs.field(default=None)
    tracking_id: str | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Document":
        """Create a Document from a dictionary.

        Args:
            data: The 'document' section from parsed JSON
        """
        return cls(
            title=data.get("title"),
            category=data.get("category"),
            tracking_id=data.get("tracking", {}).get("id"),
        )


@attrs.define
class CSAFVEXDocument:
    """Represents a complete CSAF VEX file."""

    document: Document
    product_tree: dict[str, Any] = attrs.field(factory=dict)
    vulnerabilities: list[dict[str, Any]] = attrs.field(factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CSAFVEXDocument":
        """Create a CSAFVEXDocument from a dictionary (parsed JSON).

        Args:
            data: The complete parsed CSAF VEX JSON data
        """
        return cls(
            document=Document.from_dict(data.get("document", {})),
            product_tree=data.get("product_tree", {}),
            vulnerabilities=data.get("vulnerabilities", []),
        )
