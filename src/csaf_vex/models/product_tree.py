"""Data models for the CSAF VEX product tree section."""

from typing import Any

import attrs
from packageurl import PackageURL

from csaf_vex.models.common import SerializableModel

# @attrs.define
# class FileHash:
#     """Represents a cryptographic hash of a file."""
#     algorithm: str | None = attrs.field(default=None)
#     value: str | None = attrs.field(default=None)
#
#     @classmethod
#     def from_dict(cls, data: dict[str, Any]) -> "FileHash":
#         return cls(
#             algorithm=data.get("algorithm"),
#             value=data.get("value"),
#         )


# @attrs.define
# class CryptographicHashes:
#     """Contains cryptographic hashes to identify a file."""
#     file_hashes: list[FileHash] = attrs.field(factory=list)
#     filename: str | None = attrs.field(default=None)
#
#     @classmethod
#     def from_dict(cls, data: dict[str, Any]) -> "CryptographicHashes":
#         file_hashes_data = data.get("file_hashes", [])
#         return cls(
#             file_hashes=[FileHash.from_dict(h) for h in file_hashes_data],
#             filename=data.get("filename"),
#         )


# @attrs.define
# class GenericURI:
#     """Represents a generic URI identifier."""
#     namespace: str | None = attrs.field(default=None)
#     uri: str | None = attrs.field(default=None)
#
#     @classmethod
#     def from_dict(cls, data: dict[str, Any]) -> "GenericURI":
#         return cls(
#             namespace=data.get("namespace"),
#             uri=data.get("uri"),
#         )


@attrs.define
class ProductIdentificationHelper(SerializableModel):
    """Helper to identify a product using CPE or PURL."""

    # Fields we're currently using (all optional per CSAF spec)
    cpe: str | None = attrs.field(default=None)

    # Can be either a parsed PackageURL object or raw string (if parsing failed)
    purl: PackageURL | str | None = attrs.field(default=None)

    # hashes: list[CryptographicHashes] = attrs.field(factory=list)
    # model_numbers: list[str] = attrs.field(factory=list)
    # sbom_urls: list[str] = attrs.field(factory=list)
    # serial_numbers: list[str] = attrs.field(factory=list)
    # skus: list[str] = attrs.field(factory=list)
    # x_generic_uris: list[GenericURI] = attrs.field(factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProductIdentificationHelper":
        """Create a ProductIdentificationHelper from a dictionary.

        Attempts to parse purl strings using the packageurl library. If parsing fails,
        preserves the raw string data so validation can catch it later.
        """

        purl_data = data.get("purl")

        if purl_data and isinstance(purl_data, str):
            try:
                # Try to parse the purl string
                purl_value = PackageURL.from_string(purl_data)
            except Exception:
                # Parsing failed - keep raw string for validation to catch
                purl_value = purl_data
        else:
            purl_value = purl_data

        # hashes_data = data.get("hashes", [])
        # x_generic_uris_data = data.get("x_generic_uris", [])

        return cls(
            cpe=data.get("cpe"),
            purl=purl_value,
            # hashes=[CryptographicHashes.from_dict(h) for h in hashes_data],
            # model_numbers=data.get("model_numbers", []),
            # sbom_urls=data.get("sbom_urls", []),
            # serial_numbers=data.get("serial_numbers", []),
            # skus=data.get("skus", []),
            # x_generic_uris=[GenericURI.from_dict(u) for u in x_generic_uris_data],
        )


@attrs.define
class FullProductName(SerializableModel):
    """Specifies information about a product."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    name: str | None = attrs.field(default=None)
    product_id: str | None = attrs.field(default=None)

    # Optional fields (CSAF spec order)
    product_identification_helper: ProductIdentificationHelper | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FullProductName":
        """Create a FullProductName from a dictionary."""
        helper_data = data.get("product_identification_helper")

        return cls(
            name=data.get("name"),
            product_id=data.get("product_id"),
            product_identification_helper=ProductIdentificationHelper.from_dict(helper_data)
            if helper_data is not None
            else None,
        )


@attrs.define
class Branch(SerializableModel):
    """Represents a branch in the hierarchical product tree structure."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    category: str | None = attrs.field(default=None)
    name: str | None = attrs.field(default=None)

    # Optional fields - note: must have either branches OR product (not both)
    branches: list["Branch"] = attrs.field(factory=list)
    product: FullProductName | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Branch":
        """Create a Branch from a dictionary."""
        branches_data = data.get("branches", [])
        product_data = data.get("product")

        return cls(
            category=data.get("category"),
            name=data.get("name"),
            branches=[Branch.from_dict(b) for b in branches_data],
            product=FullProductName.from_dict(product_data) if product_data is not None else None,
        )


@attrs.define
class Relationship(SerializableModel):
    """Establishes a relationship between two products."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    category: str | None = attrs.field(default=None)
    full_product_name: FullProductName | None = attrs.field(default=None)
    product_reference: str | None = attrs.field(default=None)
    relates_to_product_reference: str | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Relationship":
        """Create a Relationship from a dictionary."""
        full_product_name_data = data.get("full_product_name")

        return cls(
            category=data.get("category"),
            full_product_name=FullProductName.from_dict(full_product_name_data)
            if full_product_name_data is not None
            else None,
            product_reference=data.get("product_reference"),
            relates_to_product_reference=data.get("relates_to_product_reference"),
        )


# @attrs.define
# class ProductGroup:
#     """Defines a logical group of products."""
#     group_id: str | None = attrs.field(default=None)
#     product_ids: list[str] = attrs.field(factory=list)
#     summary: str | None = attrs.field(default=None)
#
#     @classmethod
#     def from_dict(cls, data: dict[str, Any]) -> "ProductGroup":
#         return cls(
#             group_id=data.get("group_id"),
#             product_ids=data.get("product_ids", []),
#             summary=data.get("summary"),
#         )


@attrs.define
class ProductTree(SerializableModel):
    """Container for all fully qualified product names.

    Note: Validation of product tree structure is handled by the Verifier class
    which validates against the CSAF JSON schema.
    """

    # Fields we're currently using
    branches: list[Branch] = attrs.field(factory=list)
    relationships: list[Relationship] = attrs.field(factory=list)

    # full_product_names: list[FullProductName] = attrs.field(factory=list)
    # product_groups: list[ProductGroup] = attrs.field(factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProductTree":
        """Create a ProductTree from a dictionary.

        Args:
            data: The 'product_tree' section from parsed JSON
        """
        branches_data = data.get("branches", [])
        relationships_data = data.get("relationships", [])
        # full_product_names_data = data.get("full_product_names", [])
        # product_groups_data = data.get("product_groups", [])

        return cls(
            branches=[Branch.from_dict(b) for b in branches_data],
            relationships=[Relationship.from_dict(r) for r in relationships_data],
            # full_product_names=[FullProductName.from_dict(p) for p in full_product_names_data],
            # product_groups=[ProductGroup.from_dict(g) for g in product_groups_data],
        )
