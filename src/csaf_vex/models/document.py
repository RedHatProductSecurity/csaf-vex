"""Data models for the CSAF VEX document section."""

from datetime import datetime
from typing import Any

import attrs

from csaf_vex.models.common import Note, Reference, SerializableModel


@attrs.define
class AggregateSeverity(SerializableModel):
    """Represents the aggregate severity of a document."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    text: str | None = attrs.field(default=None)

    # Optional fields (CSAF spec order)
    namespace: str | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AggregateSeverity":
        """Create an AggregateSeverity from a dictionary."""
        return cls(
            text=data.get("text"),
            namespace=data.get("namespace"),
        )


@attrs.define
class TLP(SerializableModel):
    """Represents Traffic Light Protocol information."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    label: str | None = attrs.field(default=None)

    # Optional fields (CSAF spec order)
    url: str | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TLP":
        """Create a TLP from a dictionary."""
        return cls(
            label=data.get("label"),
            url=data.get("url"),
        )


@attrs.define
class Distribution(SerializableModel):
    """Represents document distribution rules."""

    text: str | None = attrs.field(default=None)
    tlp: TLP | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Distribution":
        """Create a Distribution from a dictionary."""
        tlp_data = data.get("tlp")
        return cls(
            text=data.get("text"),
            tlp=TLP.from_dict(tlp_data) if tlp_data is not None else None,
        )


@attrs.define
class Publisher(SerializableModel):
    """Represents the publisher of the document."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    category: str | None = attrs.field(default=None)
    name: str | None = attrs.field(default=None)
    namespace: str | None = attrs.field(default=None)

    # Optional fields (CSAF spec order)
    contact_details: str | None = attrs.field(default=None)
    issuing_authority: str | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Publisher":
        """Create a Publisher from a dictionary."""
        return cls(
            category=data.get("category"),
            name=data.get("name"),
            namespace=data.get("namespace"),
            contact_details=data.get("contact_details"),
            issuing_authority=data.get("issuing_authority"),
        )


@attrs.define
class Engine(SerializableModel):
    """Represents the document generation engine."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    name: str | None = attrs.field(default=None)

    # Optional fields (CSAF spec order)
    version: str | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Engine":
        """Create an Engine from a dictionary."""
        return cls(
            name=data.get("name"),
            version=data.get("version"),
        )


@attrs.define
class Generator(SerializableModel):
    """Represents the document generator information."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    engine: Engine | None = attrs.field(default=None)

    # Optional fields (CSAF spec order)
    date: datetime | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Generator":
        """Create a Generator from a dictionary."""
        engine_data = data.get("engine", {})
        date_str = data.get("date")
        return cls(
            engine=Engine.from_dict(engine_data) if engine_data is not None else None,
            date=datetime.fromisoformat(date_str) if date_str is not None else None,
        )


@attrs.define
class Revision(SerializableModel):
    """Represents a revision in the document history."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    date: datetime | None = attrs.field(default=None)
    number: str | None = attrs.field(default=None)
    summary: str | None = attrs.field(default=None)

    # Optional fields (CSAF spec order)
    legacy_version: str | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Revision":
        """Create a Revision from a dictionary."""
        date_str = data.get("date")
        return cls(
            date=datetime.fromisoformat(date_str) if date_str is not None else None,
            number=data.get("number"),
            summary=data.get("summary"),
            legacy_version=data.get("legacy_version"),
        )


@attrs.define
class Tracking(SerializableModel):
    """Represents the tracking information of the document."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    id: str | None = attrs.field(default=None)
    status: str | None = attrs.field(default=None)
    version: str | None = attrs.field(default=None)
    current_release_date: datetime | None = attrs.field(default=None)
    initial_release_date: datetime | None = attrs.field(default=None)
    revision_history: list[Revision] = attrs.field(factory=list)

    # Optional fields (CSAF spec order)
    generator: Generator | None = attrs.field(default=None)

    # aliases: list[str] = attrs.field(factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Tracking":
        """Create a Tracking from a dictionary."""
        revision_history_data = data.get("revision_history", [])
        generator_data = data.get("generator")
        current_release_date_str = data.get("current_release_date")
        initial_release_date_str = data.get("initial_release_date")

        return cls(
            id=data.get("id"),
            status=data.get("status"),
            version=data.get("version"),
            current_release_date=datetime.fromisoformat(current_release_date_str)
            if current_release_date_str is not None
            else None,
            initial_release_date=datetime.fromisoformat(initial_release_date_str)
            if initial_release_date_str is not None
            else None,
            revision_history=[Revision.from_dict(r) for r in revision_history_data],
            generator=Generator.from_dict(generator_data) if generator_data is not None else None,
            # aliases=data.get("aliases", []),
        )


@attrs.define
class Document(SerializableModel):
    """Represents the 'document' section of a CSAF VEX file."""

    # Required fields per CSAF spec (nullable to allow parsing invalid documents)
    category: str | None = attrs.field(default=None)
    csaf_version: str | None = attrs.field(default=None)
    publisher: Publisher | None = attrs.field(default=None)
    title: str | None = attrs.field(default=None)
    tracking: Tracking | None = attrs.field(default=None)

    # Optional fields (CSAF spec order)
    # acknowledgments: list[Acknowledgment] = attrs.field(factory=list)
    aggregate_severity: AggregateSeverity | None = attrs.field(default=None)
    distribution: Distribution | None = attrs.field(default=None)
    lang: str | None = attrs.field(default=None)
    notes: list[Note] = attrs.field(factory=list)
    references: list[Reference] = attrs.field(factory=list)
    source_lang: str | None = attrs.field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Document":
        """Create a Document from a dictionary.

        Args:
            data: The 'document' section from parsed JSON
        """
        tracking_data = data.get("tracking", {})
        publisher_data = data.get("publisher", {})
        aggregate_severity_data = data.get("aggregate_severity")
        distribution_data = data.get("distribution")
        notes_data = data.get("notes", [])
        references_data = data.get("references", [])
        # acknowledgments_data = data.get("acknowledgments", [])

        return cls(
            category=data.get("category"),
            csaf_version=data.get("csaf_version"),
            publisher=Publisher.from_dict(publisher_data) if publisher_data is not None else None,
            title=data.get("title"),
            tracking=Tracking.from_dict(tracking_data) if tracking_data is not None else None,
            aggregate_severity=AggregateSeverity.from_dict(aggregate_severity_data)
            if aggregate_severity_data is not None
            else None,
            distribution=Distribution.from_dict(distribution_data)
            if distribution_data is not None
            else None,
            lang=data.get("lang"),
            notes=[Note.from_dict(note) for note in notes_data],
            references=[Reference.from_dict(ref) for ref in references_data],
            source_lang=data.get("source_lang"),
            # acknowledgments=[Acknowledgment.from_dict(ack) for ack in acknowledgments_data],
        )
