"""Bbot scan model for tracking bbot security scan jobs."""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.bbot_finding import BbotFinding
    from app.models.network import Network
    from app.models.scanner import Scanner
    from app.models.user import User


class BbotScanStatus(str, Enum):
    """Bbot scan status values."""

    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BbotScan(Base):
    """Bbot scan model for tracking bbot security scan executions."""

    __tablename__ = "bbot_scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id"), nullable=False, index=True)
    scanner_id: Mapped[int | None] = mapped_column(
        ForeignKey("scanners.id"), nullable=True, index=True
    )
    status: Mapped[BbotScanStatus] = mapped_column(
        SQLEnum(BbotScanStatus, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=BbotScanStatus.PLANNED,
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cancelled_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    target: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Target domain or IP for bbot scan"
    )
    modules: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Comma-separated list of bbot modules to run"
    )

    # Relationships
    network: Mapped["Network"] = relationship("Network", back_populates="bbot_scans")
    scanner: Mapped["Scanner | None"] = relationship("Scanner", back_populates="bbot_scans")
    cancelled_by_user: Mapped["User | None"] = relationship("User")
    findings: Mapped[list["BbotFinding"]] = relationship(
        "BbotFinding", back_populates="bbot_scan", cascade="all, delete-orphan"
    )

    @property
    def cancelled_by_email(self) -> str | None:
        """Return the cancelling user's email when available."""
        if self.cancelled_by_user is None:
            return None
        return self.cancelled_by_user.email
