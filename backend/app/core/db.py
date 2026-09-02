from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, class_=Session)


def get_db() -> Iterator[Session]:
    """FastAPI route dependency:每個 request 一個 session,結束後自動關閉。"""
    with SessionLocal() as session:
        yield session
