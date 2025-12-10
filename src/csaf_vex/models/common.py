"""Common data models shared across CSAF VEX sections."""

from datetime import datetime
from typing import Any

import attrs
from cvss import CVSS2, CVSS3
from packageurl import PackageURL


def serialize_value(inst: type, field: attrs.Attribute, value: Any) -> Any:
    """Custom value serializer for attrs.asdict().

    Handles special types like datetime, CVSS objects, and PackageURL.
    """
    if value is None:
        return None

    # Handle datetime objects
    if isinstance(value, datetime):
        return value.isoformat()

    # Handle PackageURL objects
    if isinstance(value, PackageURL):
        return value.to_string()

    # Handle CVSS objects - use built-in as_json method
    if isinstance(value, (CVSS2, CVSS3)):
        return value.as_json(minimal=True)

    # Handle lists - recursively process items
    if isinstance(value, list):
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in value]

    # Handle nested attrs objects
    if attrs.has(type(value)):
        return value.to_dict()

    # Handle plain dicts - sort keys recursively
    if isinstance(value, dict):
        return dict(sorted((key, serialize_value(inst, field, val)) for key, val in value.items()))

    # Return as-is for other types (str, int, etc.)
    return value


@attrs.define
class SerializableModel:
    """Base class for CSAF VEX models with serialization support."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to a dictionary, excluding None values and empty lists.

        Keys are sorted alphabetically for consistent output.
        """
        result = attrs.asdict(
            self,
            filter=lambda attr, value: value is not None and value != [],
            value_serializer=serialize_value,
        )
        return dict(sorted(result.items()))


@attrs.define
class Note(SerializableModel):
    """Represents a note in the document or vulnerability."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    category: str | None = attrs.field(default=None)
    text: str | None = attrs.field(default=None)

    # Optional fields (CSAF spec order)
    title: str | None = attrs.field(default=None)

    # audience: str | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Note":
        """Create a Note from a dictionary."""
        return cls(
            category=data.get("category"),
            text=data.get("text"),
            title=data.get("title"),
            # audience=data.get("audience"),
        )


@attrs.define
class Reference(SerializableModel):
    """Represents a reference to external resources."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    summary: str | None = attrs.field(default=None)
    url: str | None = attrs.field(default=None)

    # Optional fields (CSAF spec order)
    category: str | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Reference":
        """Create a Reference from a dictionary."""
        return cls(
            summary=data.get("summary"),
            url=data.get("url"),
            category=data.get("category"),
        )


@attrs.define
class Acknowledgment(SerializableModel):
    """Represents an acknowledgment of contributors."""

    names: list[str] = attrs.field(factory=list)
    organization: str | None = attrs.field(default=None)
    summary: str | None = attrs.field(default=None)
    urls: list[str] = attrs.field(factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Acknowledgment":
        """Create an Acknowledgment from a dictionary."""
        return cls(
            names=data.get("names", []),
            organization=data.get("organization"),
            summary=data.get("summary"),
            urls=data.get("urls", []),
        )
