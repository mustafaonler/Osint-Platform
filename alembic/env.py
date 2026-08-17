"""Alembic ortamı — `docs/veri-modeli.md` Bölüm 6 (Migration Politikası).

Şema değişikliği ELLE SQL ile yapılmaz. Her migration geri alınabilir olmalıdır
(`downgrade` dolu).

Veritabanı URL'i ASLA `alembic.ini`'ye yazılmaz: o dosya commit edilir, URL ise
parola içerir (`docs/kapsam.md` Bölüm 9 — repoda API key/parola yok).
"""

from __future__ import annotations

import os
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool

from app.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# `target_metadata` autogenerate'in karşılaştırma kaynağıdır: modeller neredeyse
# şema odur. Yeni bir tablo app/models.py'ye eklendiğinde buraya dokunulmaz.
target_metadata = Base.metadata

_KOK = Path(__file__).resolve().parents[1]
load_dotenv(_KOK / ".env")


def _db_url() -> str:
    """URL öncelik zinciri.

    1) `alembic -x db_url=...`  — tek seferlik geçersiz kılma (CI, farklı host)
    2) `ALEMBIC_DATABASE_URL`   — HOST tarafı; 'localhost:5432'
    3) `DATABASE_URL`           — container ağı; servis adı 'db'

    İki ayrı değişkenin sebebi: aynı veritabanının nerede durduğuna göre iki
    farklı adı var. 'db' yalnızca docker compose ağı içinde çözülür; host'tan
    çalışan alembic ve pytest için aynı sunucu 127.0.0.1:5432'ye yayınlanmıştır.
    Tek bir URL'i her iki yer için birden doğru yazmak mümkün değildir.
    """
    x = context.get_x_argument(as_dictionary=True).get("db_url")
    url = x or os.getenv("ALEMBIC_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "Veritabanı URL'i yok. .env içinde ALEMBIC_DATABASE_URL veya "
            "DATABASE_URL tanımlayın ya da `alembic -x db_url=...` kullanın."
        )
    return url


def run_migrations_offline() -> None:
    """'Offline' mod: bağlantı açmadan SQL üretir (`alembic upgrade head --sql`)."""
    context.configure(
        url=_db_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """'Online' mod: gerçek bağlantı üzerinden çalıştırır."""
    ayar = config.get_section(config.config_ini_section, {})
    # Parola log'a düşmesin diye URL ini'den değil, koddan verilir.
    ayar["sqlalchemy.url"] = _db_url()

    connectable = engine_from_config(
        ayar, prefix="sqlalchemy.", poolclass=pool.NullPool
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
