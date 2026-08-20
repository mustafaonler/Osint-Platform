"""Veritabani oturumu — api ve worker paylasir."""

from __future__ import annotations

import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

load_dotenv()

# ALEMBIC_DATABASE_URL once gelir (host tarafi icin kacis yolu), sonra
# DATABASE_URL. Ayni oncelik zinciri alembic/env.py'de de var.
DATABASE_URL = os.getenv("ALEMBIC_DATABASE_URL") or os.getenv("DATABASE_URL") or ""

# pool_pre_ping: worker uzun sure bosta kalirsa kopmus baglantiyi sessizce
# kullanmak yerine yeniler.
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

# expire_on_commit=False: commit sonrasi job/entity alanlari hala okunabilsin;
# worker commit'ten sonra da job'un durumunu loglar.
SessionLocal = sessionmaker(engine, class_=Session, expire_on_commit=False)


def oturum() -> Session:
    return SessionLocal()
