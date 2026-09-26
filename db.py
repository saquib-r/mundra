"""Async SQLAlchemy engine, session factory and ORM table classes.

Pydantic request/response shapes live in models.py; query functions live in
database.py. This file only describes the storage.
"""

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    MetaData,
    String,
    func,
    text,
)
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

import config

ROLES = ("delegate", "oc", "admin")

# Deterministic constraint names, so Alembic can drop and alter them later.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

engine = create_async_engine(
    config.get_settings().database_url,
    pool_size=10,
    max_overflow=10,
    pool_pre_ping=True,
)

# expire_on_commit=False: attributes stay readable after commit, which async
# sessions need because they cannot lazy-load.
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _created_at() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now())


class DelegateRow(Base):
    __tablename__ = "delegates"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    firstname: Mapped[str]
    lastname: Mapped[str]
    email: Mapped[str] = mapped_column(unique=True)
    contact: Mapped[str] = mapped_column(server_default="")
    dateofbirth: Mapped[str] = mapped_column(server_default="")
    gender: Mapped[str] = mapped_column(server_default="")
    verified: Mapped[bool] = mapped_column(server_default=text("false"))
    created_at: Mapped[datetime] = _created_at()

    # lazy="raise": async sessions cannot lazy-load, so every query that needs these
    # must ask for them explicitly (selectinload / contains_eager).
    experiences: Mapped[list["MunExperienceRow"]] = relationship(
        order_by="MunExperienceRow.position",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="raise",
    )
    mm: Mapped["MMDelegateRow | None"] = relationship(
        cascade="all, delete-orphan", passive_deletes=True, lazy="raise"
    )


class UserRow(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            f"role IN ({', '.join(repr(r) for r in ROLES)})", name="role_valid"
        ),
    )

    email: Mapped[str] = mapped_column(
        ForeignKey("delegates.email", onupdate="CASCADE", ondelete="CASCADE"),
        primary_key=True,
    )
    password: Mapped[str]
    role: Mapped[str] = mapped_column(server_default="delegate")
    created_at: Mapped[datetime] = _created_at()


class MunExperienceRow(Base):
    __tablename__ = "mun_experiences"

    id: Mapped[int] = mapped_column(primary_key=True)
    delegate_id: Mapped[str] = mapped_column(
        ForeignKey("delegates.id", ondelete="CASCADE"), index=True
    )
    # Keeps the order the delegate entered their experiences in.
    position: Mapped[int]
    name: Mapped[str]
    committee: Mapped[str] = mapped_column(server_default="")
    delegation: Mapped[str] = mapped_column(server_default="")
    year: Mapped[int]
    award: Mapped[str] = mapped_column(server_default="")


class MMDelegateRow(Base):
    """Mumbai MUN details for a delegate. The delegate's profile lives in delegates."""

    __tablename__ = "mm_delegates"

    delegate_id: Mapped[str] = mapped_column(
        ForeignKey("delegates.id", ondelete="CASCADE"), primary_key=True
    )
    country: Mapped[str] = mapped_column(server_default="")
    committee: Mapped[str] = mapped_column(server_default="")
    d1_bf: Mapped[bool] = mapped_column(server_default=text("true"))
    d1_lunch: Mapped[bool] = mapped_column(server_default=text("false"))
    d1_hitea: Mapped[bool] = mapped_column(server_default=text("false"))
    d2_bf: Mapped[bool] = mapped_column(server_default=text("false"))
    d2_lunch: Mapped[bool] = mapped_column(server_default=text("false"))
    d2_hitea: Mapped[bool] = mapped_column(server_default=text("false"))
    d3_bf: Mapped[bool] = mapped_column(server_default=text("false"))
    d3_lunch: Mapped[bool] = mapped_column(server_default=text("false"))
    d3_hitea: Mapped[bool] = mapped_column(server_default=text("false"))
    created_at: Mapped[datetime] = _created_at()


class AdminAuditRow(Base):
    """One row per role change. Emails are stored as plain text, not foreign keys,
    so the trail survives a deleted account."""

    __tablename__ = "admin_audit"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_email: Mapped[str]
    target_email: Mapped[str]
    old_role: Mapped[str]
    new_role: Mapped[str]
    created_at: Mapped[datetime] = _created_at()
