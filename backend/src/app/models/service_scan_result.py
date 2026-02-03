"""Service scan result model for storing detailed service scan data from Nmap NSE scripts."""

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.scan import Scan


class ServiceScanResult(Base):
    """Service scan result model for storing detailed service information from Nmap NSE scripts."""

    __tablename__ = "service_scan_results"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    service_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    # HTTP-specific fields
    http_title: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    http_server: Mapped[str | None] = mapped_column(String(255), nullable=True)
    http_methods: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    http_headers: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Generic NSE script output
    nse_scripts: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Relationship to parent scan
    scan: Mapped["Scan"] = relationship("Scan", back_populates="service_scan_results")
