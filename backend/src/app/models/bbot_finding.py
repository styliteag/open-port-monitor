"""Bbot finding model for storing bbot scan results."""

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.bbot_scan import BbotScan


class BbotFinding(Base):
    """Bbot finding model for storing individual bbot scan results."""

    __tablename__ = "bbot_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    bbot_scan_id: Mapped[int] = mapped_column(
        ForeignKey("bbot_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    event_type: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True, comment="Type of bbot event (DNS_NAME, OPEN_PORT, VULNERABILITY, etc.)"
    )
    data: Mapped[str] = mapped_column(Text, nullable=False, comment="Primary data/value from bbot event")
    host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    module: Mapped[str | None] = mapped_column(
        String(100), nullable=True, comment="Bbot module that discovered this finding"
    )
    severity: Mapped[str | None] = mapped_column(
        String(20), nullable=True, index=True, comment="Severity level if applicable"
    )
    tags: Mapped[list[str] | None] = mapped_column(JSON, nullable=True, comment="Tags from bbot event")
    raw_event: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True, comment="Full raw bbot event JSON"
    )

    # Relationship to parent scan
    bbot_scan: Mapped["BbotScan"] = relationship("BbotScan", back_populates="findings")
