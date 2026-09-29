from __future__ import annotations

from .enterprise_ops import postgres_schema


def _psycopg():
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError(
            "PostgreSQL support requires: pip install 'socmind[enterprise]'"
        ) from exc
    return psycopg


def initialize_postgres(dsn: str) -> None:
    psycopg = _psycopg()
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            for statement in postgres_schema().split(";"):
                statement = statement.strip()
                if statement:
                    cur.execute(statement)
        conn.commit()


def postgres_health(dsn: str) -> dict:
    psycopg = _psycopg()
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database(), current_user, version()")
            database, user, version = cur.fetchone()
            cur.execute(
                "SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema='public' "
                "AND table_name IN ('cases','case_notes','case_audit','alerts','case_alerts')"
            )
            tables = int(cur.fetchone()[0])
    return {
        "database": database,
        "user": user,
        "version": version,
        "socmind_tables": tables,
        "ready": tables == 5,
    }
