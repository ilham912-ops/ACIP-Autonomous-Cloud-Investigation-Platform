
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004_add_analyst_verdict"
down_revision = "0003"
branch_labels = None
depends_on = None

analyst_verdict_enum = postgresql.ENUM(
    "pending", "confirmed", "false_positive",
    name="analystverdict",
)


def upgrade() -> None:
    bind = op.get_bind()
    analyst_verdict_enum.create(bind, checkfirst=True)

    op.add_column(
        "findings",
        sa.Column(
            "analyst_verdict",
            analyst_verdict_enum,
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column(
        "findings",
        sa.Column("verdict_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_findings_analyst_verdict", "findings", ["analyst_verdict"])


def downgrade() -> None:
    op.drop_index("ix_findings_analyst_verdict", table_name="findings")
    op.drop_column("findings", "verdict_updated_at")
    op.drop_column("findings", "analyst_verdict")

    bind = op.get_bind()
    analyst_verdict_enum.drop(bind, checkfirst=True)
