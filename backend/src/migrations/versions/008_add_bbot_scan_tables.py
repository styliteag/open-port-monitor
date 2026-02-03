"""add bbot scan tables

Revision ID: 008
Revises: 007
Create Date: 2026-02-03 14:30:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql


# revision identifiers, used by Alembic.
revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create bbot_scans table
    op.create_table('bbot_scans',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('network_id', sa.Integer(), nullable=False),
        sa.Column('scanner_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.Enum('planned', 'running', 'completed', 'failed', 'cancelled', name='bbotscanstatus'), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('cancelled_at', sa.DateTime(), nullable=True),
        sa.Column('cancelled_by', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('target', sa.Text(), nullable=False, comment='Target domain or IP for bbot scan'),
        sa.Column('modules', sa.Text(), nullable=True, comment='Comma-separated list of bbot modules to run'),
        sa.ForeignKeyConstraint(['cancelled_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'], ),
        sa.ForeignKeyConstraint(['scanner_id'], ['scanners.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_bbot_scans_network_id'), 'bbot_scans', ['network_id'], unique=False)
    op.create_index(op.f('ix_bbot_scans_scanner_id'), 'bbot_scans', ['scanner_id'], unique=False)
    op.create_index(op.f('ix_bbot_scans_status'), 'bbot_scans', ['status'], unique=False)

    # Create bbot_findings table
    op.create_table('bbot_findings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('bbot_scan_id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False, comment='Type of bbot event (DNS_NAME, OPEN_PORT, VULNERABILITY, etc.)'),
        sa.Column('data', sa.Text(), nullable=False, comment='Primary data/value from bbot event'),
        sa.Column('host', sa.String(length=255), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(length=20), nullable=True),
        sa.Column('module', sa.String(length=100), nullable=True, comment='Bbot module that discovered this finding'),
        sa.Column('severity', sa.String(length=20), nullable=True, comment='Severity level if applicable'),
        sa.Column('tags', sa.JSON(), nullable=True, comment='Tags from bbot event'),
        sa.Column('raw_event', sa.JSON(), nullable=True, comment='Full raw bbot event JSON'),
        sa.ForeignKeyConstraint(['bbot_scan_id'], ['bbot_scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_bbot_findings_bbot_scan_id'), 'bbot_findings', ['bbot_scan_id'], unique=False)
    op.create_index(op.f('ix_bbot_findings_event_type'), 'bbot_findings', ['event_type'], unique=False)
    op.create_index(op.f('ix_bbot_findings_host'), 'bbot_findings', ['host'], unique=False)
    op.create_index(op.f('ix_bbot_findings_severity'), 'bbot_findings', ['severity'], unique=False)


def downgrade() -> None:
    # Drop bbot_findings table
    op.drop_index(op.f('ix_bbot_findings_severity'), table_name='bbot_findings')
    op.drop_index(op.f('ix_bbot_findings_host'), table_name='bbot_findings')
    op.drop_index(op.f('ix_bbot_findings_event_type'), table_name='bbot_findings')
    op.drop_index(op.f('ix_bbot_findings_bbot_scan_id'), table_name='bbot_findings')
    op.drop_table('bbot_findings')

    # Drop bbot_scans table
    op.drop_index(op.f('ix_bbot_scans_status'), table_name='bbot_scans')
    op.drop_index(op.f('ix_bbot_scans_scanner_id'), table_name='bbot_scans')
    op.drop_index(op.f('ix_bbot_scans_network_id'), table_name='bbot_scans')
    op.drop_table('bbot_scans')
