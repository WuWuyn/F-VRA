"""enforce unique project names

Revision ID: 0003_unique_project_names
Revises: 0002_product_ready_evidence
Create Date: 2026-06-30
"""
from __future__ import annotations

from alembic import op

revision = "0003_unique_project_names"
down_revision = "0002_product_ready_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_projects_name_lower ON projects (lower(name))")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_projects_name_lower")
