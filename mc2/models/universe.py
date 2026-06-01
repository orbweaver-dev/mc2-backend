"""
Universe — OrbWeaver shared reference-data authority.

Stores versioned reference datasets (the single source of truth that every
OrbWeaver site reads instead of shipping fixtures/per-site copies) and the
per-consumer API keys that gate read access.

Generic by design: a Dataset has many Records, each Record is a JSON blob keyed
by `record_key` (unique within the dataset). Bumping any record bumps the
dataset `version` so consumers can cheaply cache + conditionally refresh.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column

from mc2.models.user import Base


def _uid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.utcnow()


class UniverseDataset(Base):
    """A named reference bank, e.g. 'state_regulation', 'license_reciprocity'."""

    __tablename__ = "universe_datasets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    slug: Mapped[str] = mapped_column(String(96), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # bumped whenever any record in the dataset is written — drives consumer cache/etag
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


class UniverseRecord(Base):
    """One record inside a dataset. `data` is a JSON document (stored as text)."""

    __tablename__ = "universe_records"
    __table_args__ = (
        UniqueConstraint("dataset", "record_key", name="uq_universe_record"),
        Index("idx_universe_dataset", "dataset"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    dataset: Mapped[str] = mapped_column(String(96), nullable=False)  # dataset slug
    record_key: Mapped[str] = mapped_column(String(191), nullable=False)
    data: Mapped[str] = mapped_column(Text, nullable=False, default="{}")  # JSON
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


class UniverseConsumerKey(Base):
    """An API key issued to a consumer (an OrbWeaver app on a site) for read access.

    The full key is shown once at creation; only a SHA-256 hash is stored. Lookup
    is by the indexed prefix, then the hash is compared. `datasets` is a JSON list
    of allowed dataset slugs (null/empty = all datasets)."""

    __tablename__ = "universe_consumer_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    consumer_name: Mapped[str] = mapped_column(String(255), nullable=False)
    datasets: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list or null=all
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
