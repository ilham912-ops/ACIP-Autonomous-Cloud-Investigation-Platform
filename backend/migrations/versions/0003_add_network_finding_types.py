

from alembic import op


# revision identifiers
revision = "0003"
down_revision = "xxxx"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        "ALTER TYPE findingtype ADD VALUE IF NOT EXISTS 'PORT_SCAN'"
    )

    op.execute(
        "ALTER TYPE findingtype ADD VALUE IF NOT EXISTS 'DATA_EXFILTRATION'"
    )

    op.execute(
        "ALTER TYPE findingtype ADD VALUE IF NOT EXISTS 'SUSPICIOUS_CONNECTION'"
    )


def downgrade():
    # PostgreSQL ne permet pas facilement de supprimer
    # une valeur d'un ENUM.
    pass