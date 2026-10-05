
from alembic import op

revision = "0005_add_ml_finding_type"
down_revision = "0004_add_analyst_verdict"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE findingtype ADD VALUE IF NOT EXISTS 'ANOMALOUS_LOGIN'")


def downgrade() -> None:
    raise NotImplementedError(
        "Downgrade non supporte : PostgreSQL ne permet pas de retirer des "
        "valeurs d'un type ENUM existant sans le recreer entierement."
    )
