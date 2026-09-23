"""investigation: kok_tip ve secili_toollar

Arastirma olusturulurken kullanilacak tool'lar secilir ve kok hedef
DOMAIN yerine IP de olabilir.

MEVCUT SATIRLAR: secili_toollar bos dizi olarak baslar ve bos dizi
"kisit yok" anlamina gelir; eski arastirmalar aynen calismaya devam eder.
kok_tip varsayilani 'domain' — v1'de tum arastirmalar domain kokluydu.

Revision ID: c3f1a7b45d92
Revises: 71a05e732d14
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "c3f1a7b45d92"
down_revision = "71a05e732d14"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigation",
        sa.Column(
            "kok_tip", sa.Text(), nullable=False, server_default=sa.text("'domain'")
        ),
    )
    op.add_column(
        "investigation",
        sa.Column(
            "secili_toollar",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )
    op.create_check_constraint(
        "ck_investigation_kok_tip", "investigation", "kok_tip IN ('domain','ip')"
    )


def downgrade() -> None:
    op.drop_constraint("ck_investigation_kok_tip", "investigation", type_="check")
    op.drop_column("investigation", "secili_toollar")
    op.drop_column("investigation", "kok_tip")
