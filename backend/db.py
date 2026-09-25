from collections.abc import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from .config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from . import models  # noqa: F401
    Base.metadata.create_all(engine)
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION auditpilot_audit_immutable() RETURNS trigger AS $$
                BEGIN RAISE EXCEPTION 'audit_log is append-only'; END;
                $$ LANGUAGE plpgsql;
                DROP TRIGGER IF EXISTS audit_log_immutable ON audit_log;
                CREATE TRIGGER audit_log_immutable BEFORE UPDATE OR DELETE ON audit_log
                FOR EACH ROW EXECUTE FUNCTION auditpilot_audit_immutable();
            """))
