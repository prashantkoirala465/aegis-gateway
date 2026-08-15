from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base; all ORM models (Phase 1+) inherit from this so
    Alembic's autogenerate can discover the full schema via Base.metadata."""
