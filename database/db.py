"""
db.py
-----
Neon PostgreSQL connection module.

Provides:
  - A synchronous psycopg2 connection pool (used in FastAPI sync routes)
  - An asyncpg connection pool (used in FastAPI async routes)
  - Helper functions to get / release connections from either pool

All connection strings are read from environment variables — never
hard-coded. In production these are set as Vercel Environment Variables.

Author  : Member 1 — Project Lead
Phase   : 1
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator

import psycopg2
import psycopg2.pool

logger = logging.getLogger("database")

# ---------------------------------------------------------------------------
# Configuration — pulled from environment
# ---------------------------------------------------------------------------
DATABASE_URL: str = os.getenv("NEON_DB_URL", "")
if not DATABASE_URL:
    logger.warning(
        "NEON_DB_URL is not set. Database features will be unavailable. "
        "Set it in your .env file (see .env.example)."
    )

# Pool size — suitable for a research prototype / Vercel serverless
_POOL_MIN_CONN: int = int(os.getenv("DB_POOL_MIN", "1"))
_POOL_MAX_CONN: int = int(os.getenv("DB_POOL_MAX", "5"))

# ---------------------------------------------------------------------------
# Synchronous psycopg2 connection pool
# ---------------------------------------------------------------------------
_sync_pool: psycopg2.pool.SimpleConnectionPool | None = None


def _get_sync_pool() -> psycopg2.pool.SimpleConnectionPool:
    """Initialise (or return cached) synchronous psycopg2 pool."""
    global _sync_pool  # noqa: PLW0603
    if _sync_pool is None:
        if not DATABASE_URL:
            raise RuntimeError(
                "Cannot create database pool: NEON_DB_URL environment variable is not set."
            )
        _sync_pool = psycopg2.pool.SimpleConnectionPool(
            minconn=_POOL_MIN_CONN,
            maxconn=_POOL_MAX_CONN,
            dsn=DATABASE_URL,
        )
        logger.info("Synchronous psycopg2 pool created (min=%d, max=%d)", _POOL_MIN_CONN, _POOL_MAX_CONN)
    return _sync_pool


@contextmanager
def get_db_connection() -> Generator[psycopg2.extensions.connection, None, None]:
    """
    Context manager that yields a synchronous psycopg2 connection.

    Usage
    -----
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
    """
    pool = _get_sync_pool()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


# ---------------------------------------------------------------------------
# Async asyncpg pool (optional — used in async FastAPI routes)
# ---------------------------------------------------------------------------
_async_pool = None  # asyncpg.Pool — imported lazily to avoid hard dependency


async def init_async_pool() -> None:
    """
    Initialise the asyncpg connection pool.
    Call this once from the FastAPI lifespan event handler.
    """
    global _async_pool  # noqa: PLW0603
    if not DATABASE_URL:
        logger.warning("Skipping asyncpg pool init: NEON_DB_URL not set.")
        return
    try:
        import asyncpg  # noqa: PLC0415

        _async_pool = await asyncpg.create_pool(
            dsn=DATABASE_URL,
            min_size=_POOL_MIN_CONN,
            max_size=_POOL_MAX_CONN,
        )
        logger.info("asyncpg pool created (min=%d, max=%d)", _POOL_MIN_CONN, _POOL_MAX_CONN)
    except ImportError:
        logger.warning("asyncpg not installed — async DB pool unavailable.")


async def close_async_pool() -> None:
    """Close the asyncpg pool. Call from FastAPI shutdown lifespan handler."""
    global _async_pool  # noqa: PLW0603
    if _async_pool is not None:
        await _async_pool.close()
        _async_pool = None
        logger.info("asyncpg pool closed.")


@asynccontextmanager
async def get_async_db_connection() -> AsyncGenerator:
    """
    Async context manager that yields an asyncpg connection.

    Usage
    -----
    async with get_async_db_connection() as conn:
        row = await conn.fetchrow("SELECT 1")
    """
    if _async_pool is None:
        raise RuntimeError(
            "Async database pool is not initialised. "
            "Call `await init_async_pool()` during FastAPI startup."
        )
    async with _async_pool.acquire() as conn:
        yield conn


# ---------------------------------------------------------------------------
# Utility: test connection
# ---------------------------------------------------------------------------
def ping_database() -> dict:
    """
    Test the database connection. Returns a status dict.
    Used by the /health endpoint.
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version();")
                version = cur.fetchone()[0]
        return {"healthy": True, "db_version": version}
    except Exception as exc:  # noqa: BLE001
        return {"healthy": False, "error": str(exc)}
