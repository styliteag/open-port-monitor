"""Add vulnerabilities table for Greenbone scanner results.

Revision ID: 007
Revises: 006
Create Date: 2026-02-03

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create vulnerabilities table
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("host_ip", sa.String(length=45), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=10), nullable=True),
        sa.Column("nvt_oid", sa.String(length=255), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("severity", sa.Float(), nullable=False),
        sa.Column("threat", sa.String(length=20), nullable=False),
        sa.Column("cve", sa.String(length=255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("solution", sa.Text(), nullable=True),
        sa.Column("solution_type", sa.String(length=50), nullable=True),
        sa.Column("references", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_vulnerabilities_scan_id"), "vulnerabilities", ["scan_id"], unique=False)
    op.create_index(op.f("ix_vulnerabilities_host_ip"), "vulnerabilities", ["host_ip"], unique=False)
    op.create_index(op.f("ix_vulnerabilities_severity"), "vulnerabilities", ["severity"], unique=False)


def downgrade() -> None:
    # Drop vulnerabilities table
    op.drop_index(op.f("ix_vulnerabilities_severity"), table_name="vulnerabilities")
    op.drop_index(op.f("ix_vulnerabilities_host_ip"), table_name="vulnerabilities")
    op.drop_index(op.f("ix_vulnerabilities_scan_id"), table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
