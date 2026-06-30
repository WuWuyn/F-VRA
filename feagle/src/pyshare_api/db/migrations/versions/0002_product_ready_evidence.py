"""product ready evidence fields

Revision ID: 0002_product_ready_evidence
Revises: 0001_initial_schema
Create Date: 2026-06-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from pyshare_api.db.models import JsonType

revision = "0002_product_ready_evidence"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scan_jobs", sa.Column("failure_step", sa.String(length=128), nullable=False, server_default=""))
    op.add_column("scan_jobs", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scan_findings", sa.Column("evidence_status", sa.String(length=32), nullable=False, server_default="unavailable"))
    op.add_column("reachability_paths", sa.Column("nodes", JsonType, nullable=False, server_default="[]"))
    op.add_column("reachability_paths", sa.Column("warnings", JsonType, nullable=False, server_default="[]"))


def downgrade() -> None:
    op.drop_column("reachability_paths", "warnings")
    op.drop_column("reachability_paths", "nodes")
    op.drop_column("scan_findings", "evidence_status")
    op.drop_column("scan_jobs", "heartbeat_at")
    op.drop_column("scan_jobs", "failure_step")
    op.drop_column("scan_jobs", "retry_count")
