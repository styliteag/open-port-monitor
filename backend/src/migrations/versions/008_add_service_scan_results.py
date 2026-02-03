"""Add service_scan_results table for HTTP and service scanning.

Revision ID: 008
Revises: 007
Create Date: 2026-02-03

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def table_exists(table_name: str) -> bool:
    """Check if a table exists in the database."""
    bind = op.get_bind()
    inspector = inspect(bind)
    return table_name in inspector.get_table_names()


def index_exists(table_name: str, index_name: str) -> bool:
    """Check if an index exists on a table."""
    bind = op.get_bind()
    inspector = inspect(bind)
    indexes = inspector.get_indexes(table_name)
    return any(idx["name"] == index_name for idx in indexes)


def upgrade() -> None:
    # Create service_scan_results table (idempotent)
    if not table_exists("service_scan_results"):
        op.create_table(
            "service_scan_results",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("scan_id", sa.Integer(), nullable=False),
            sa.Column("host_ip", sa.String(45), nullable=False),
            sa.Column("port", sa.Integer(), nullable=False),
            sa.Column("protocol", sa.String(10), nullable=False, server_default="tcp"),
            sa.Column("service_name", sa.String(100), nullable=True),
            sa.Column(
                "timestamp",
                sa.DateTime(),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            # HTTP-specific fields
            sa.Column("http_title", sa.Text(), nullable=True),
            sa.Column("http_status", sa.Integer(), nullable=True),
            sa.Column("http_server", sa.String(255), nullable=True),
            sa.Column("http_methods", sa.JSON(), nullable=True),
            sa.Column("http_headers", sa.JSON(), nullable=True),
            # Generic NSE script output
            sa.Column("nse_scripts", sa.JSON(), nullable=True),
            # Keys and constraints
            sa.ForeignKeyConstraint(
                ["scan_id"], ["scans.id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint("id"),
        )
    if not index_exists("service_scan_results", "ix_service_scan_results_scan_id"):
        op.create_index("ix_service_scan_results_scan_id", "service_scan_results", ["scan_id"])
    if not index_exists("service_scan_results", "ix_service_scan_results_host_ip"):
        op.create_index("ix_service_scan_results_host_ip", "service_scan_results", ["host_ip"])


def downgrade() -> None:
    op.drop_index("ix_service_scan_results_host_ip", table_name="service_scan_results")
    op.drop_index("ix_service_scan_results_scan_id", table_name="service_scan_results")
    op.drop_table("service_scan_results")
