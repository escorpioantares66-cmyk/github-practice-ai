"""Durable single-host rate-limit and spending state using SQLite."""
from __future__ import annotations

import math
import os
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .secure_storage import ensure_private_directory

DEFAULT_DB_PATH = Path(".agent_state/quotas.sqlite3")


class QuotaStoreError(RuntimeError):
    """Quota storage is unsafe or unavailable; security controls must fail closed."""


def _path() -> Path:
    configured = os.getenv("AGENT_QUOTA_DB_PATH", "").strip()
    target = Path(configured).expanduser() if configured else DEFAULT_DB_PATH
    target = Path(os.path.abspath(target))
    try:
        ensure_private_directory(target.parent)
        if target.is_symlink():
            raise QuotaStoreError("quota database cannot be a symlink")
        if target.exists() and not stat.S_ISREG(target.lstat().st_mode):
            raise QuotaStoreError("quota database must be a regular file")
    except (OSError, ValueError) as exc:
        raise QuotaStoreError("quota storage path is unsafe or unavailable") from exc
    return target


@contextmanager
def _db() -> Iterator[sqlite3.Connection]:
    target = _path()
    connection = None
    try:
        connection = sqlite3.connect(target, timeout=10, isolation_level=None)
        os.chmod(target, 0o600)
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS rate_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identity TEXT NOT NULL,
                role TEXT NOT NULL,
                occurred_at REAL NOT NULL
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS rate_events_window
            ON rate_events(identity, role, occurred_at)
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS daily_usage (
                identity TEXT NOT NULL,
                utc_day TEXT NOT NULL,
                amount_usd REAL NOT NULL DEFAULT 0,
                estimated_usd REAL NOT NULL DEFAULT 0,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                calls INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(identity, utc_day)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS reservations (
                reservation_id TEXT PRIMARY KEY,
                identity TEXT NOT NULL,
                utc_day TEXT NOT NULL,
                amount_usd REAL NOT NULL,
                expires_at REAL NOT NULL
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS reservations_by_owner_day
            ON reservations(identity, utc_day, expires_at)
        """)
        yield connection
    except (sqlite3.Error, OSError) as exc:
        raise QuotaStoreError("durable quota storage operation failed") from exc
    finally:
        if connection is not None:
            connection.close()


@contextmanager
def _transaction() -> Iterator[sqlite3.Connection]:
    with _db() as connection:
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def check_rate_limit(
    identity: str, role: str, limit: int, window_seconds: int = 60,
    now: float | None = None,
) -> bool:
    if not isinstance(identity, str) or not identity.strip():
        return False
    if not isinstance(role, str) or not role.strip():
        return False
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("rate limit must be a positive integer")
    if (
        isinstance(window_seconds, bool)
        or not isinstance(window_seconds, int)
        or window_seconds < 1
    ):
        raise ValueError("rate window must be a positive integer")
    current = time.time() if now is None else now
    cutoff = current - window_seconds
    with _transaction() as connection:
        connection.execute(
            "DELETE FROM rate_events WHERE role=? AND occurred_at<=?",
            (role, cutoff),
        )
        count = connection.execute(
            "SELECT COUNT(*) FROM rate_events WHERE identity=? AND role=? AND occurred_at>?",
            (identity, role, cutoff),
        ).fetchone()[0]
        if count >= limit:
            return False
        connection.execute(
            "INSERT INTO rate_events(identity, role, occurred_at) VALUES (?, ?, ?)",
            (identity, role, current),
        )
        return True


def reset_rate_limits(role: str | None = None) -> None:
    with _transaction() as connection:
        if role is None:
            connection.execute("DELETE FROM rate_events")
        else:
            connection.execute("DELETE FROM rate_events WHERE role=?", (role,))


def reserve_budget(
    identity: str, utc_day: str, reservation_id: str, amount_usd: float,
    daily_limit: float, ttl_seconds: int = 3600, now: float | None = None,
) -> bool:
    if not isinstance(identity, str) or not identity.strip():
        return False
    if not isinstance(reservation_id, str) or not reservation_id.strip():
        return False
    if (
        isinstance(amount_usd, bool) or not isinstance(amount_usd, (int, float))
        or not math.isfinite(amount_usd) or amount_usd < 0
        or isinstance(daily_limit, bool) or not isinstance(daily_limit, (int, float))
        or not math.isfinite(daily_limit) or daily_limit <= 0
        or isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int)
        or ttl_seconds < 1
    ):
        raise ValueError("invalid quota reservation")
    current = time.time() if now is None else now
    with _transaction() as connection:
        connection.execute(
            "DELETE FROM reservations WHERE expires_at<=?",
            (current,),
        )
        spent = connection.execute(
            "SELECT amount_usd FROM daily_usage WHERE identity=? AND utc_day=?",
            (identity, utc_day),
        ).fetchone()
        held = connection.execute(
            "SELECT COALESCE(SUM(amount_usd),0) FROM reservations "
            "WHERE identity=? AND utc_day=?",
            (identity, utc_day),
        ).fetchone()[0]
        total = float(spent[0]) if spent else 0.0
        if total + float(held) + float(amount_usd) > daily_limit:
            return False
        connection.execute(
            "INSERT INTO reservations VALUES (?, ?, ?, ?, ?)",
            (reservation_id, identity, utc_day, float(amount_usd), current + ttl_seconds),
        )
        return True


def release_budget(reservation_id: str) -> None:
    with _transaction() as connection:
        connection.execute(
            "DELETE FROM reservations WHERE reservation_id=?", (reservation_id,)
        )


def has_reservation(identity: str, reservation_id: str) -> bool:
    with _db() as connection:
        row = connection.execute(
            """
            SELECT 1 FROM reservations
            WHERE identity=? AND reservation_id=? AND expires_at>?
            """,
            (identity, reservation_id, time.time()),
        ).fetchone()
    return row is not None


def record_model_usage(
    identity: str, utc_day: str, input_tokens: int, output_tokens: int,
    amount_usd: float,
) -> dict:
    for count in (input_tokens, output_tokens):
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("token counts must be non-negative integers")
    if (
        not isinstance(identity, str) or not identity.strip()
        or isinstance(amount_usd, bool) or not isinstance(amount_usd, (int, float))
        or not math.isfinite(amount_usd) or amount_usd < 0
    ):
        raise ValueError("invalid model usage")
    with _transaction() as connection:
        connection.execute("""
            INSERT INTO daily_usage(
                identity, utc_day, amount_usd, estimated_usd,
                input_tokens, output_tokens, calls
            ) VALUES (?, ?, ?, 0, ?, ?, 1)
            ON CONFLICT(identity, utc_day) DO UPDATE SET
                amount_usd=amount_usd+excluded.amount_usd,
                input_tokens=input_tokens+excluded.input_tokens,
                output_tokens=output_tokens+excluded.output_tokens,
                calls=calls+1
        """, (identity, utc_day, float(amount_usd), input_tokens, output_tokens))
        row = connection.execute("""
            SELECT amount_usd, estimated_usd, input_tokens, output_tokens, calls
            FROM daily_usage WHERE identity=? AND utc_day=?
        """, (identity, utc_day)).fetchone()
    return {
        "total": float(row[0]), "estimated": float(row[1]),
        "input_tokens": int(row[2]), "output_tokens": int(row[3]),
        "calls": int(row[4]),
    }


def reserve_estimated_cost(
    identity: str, utc_day: str, amount_usd: float, daily_limit: float,
) -> tuple[bool, float]:
    """Atomically convert a compatibility estimate into recorded usage."""
    if (
        not isinstance(identity, str) or not identity.strip()
        or isinstance(amount_usd, bool) or not isinstance(amount_usd, (int, float))
        or not math.isfinite(amount_usd) or amount_usd < 0
    ):
        raise ValueError("invalid estimated cost")
    with _transaction() as connection:
        now = time.time()
        connection.execute(
            "DELETE FROM reservations WHERE expires_at<=?",
            (now,),
        )
        spent = connection.execute(
            "SELECT amount_usd FROM daily_usage WHERE identity=? AND utc_day=?",
            (identity, utc_day),
        ).fetchone()
        held = connection.execute(
            "SELECT COALESCE(SUM(amount_usd),0) FROM reservations "
            "WHERE identity=? AND utc_day=?",
            (identity, utc_day),
        ).fetchone()[0]
        total = float(spent[0]) if spent else 0.0
        if total + float(held) + float(amount_usd) > daily_limit:
            return False, total
        connection.execute("""
            INSERT INTO daily_usage(identity, utc_day, amount_usd, estimated_usd)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(identity, utc_day) DO UPDATE SET
                amount_usd=amount_usd+excluded.amount_usd,
                estimated_usd=estimated_usd+excluded.estimated_usd
        """, (identity, utc_day, float(amount_usd), float(amount_usd)))
        row = connection.execute(
            "SELECT amount_usd FROM daily_usage WHERE identity=? AND utc_day=?",
            (identity, utc_day),
        ).fetchone()
    return True, float(row[0])


def add_estimated_cost(identity: str, utc_day: str, amount_usd: float) -> float:
    if (
        not isinstance(identity, str) or not identity.strip()
        or isinstance(amount_usd, bool) or not isinstance(amount_usd, (int, float))
        or not math.isfinite(amount_usd) or amount_usd < 0
    ):
        raise ValueError("invalid estimated cost")
    with _transaction() as connection:
        connection.execute("""
            INSERT INTO daily_usage(identity, utc_day, amount_usd, estimated_usd)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(identity, utc_day) DO UPDATE SET
                amount_usd=amount_usd+excluded.amount_usd,
                estimated_usd=estimated_usd+excluded.estimated_usd
        """, (identity, utc_day, float(amount_usd), float(amount_usd)))
        row = connection.execute(
            "SELECT amount_usd FROM daily_usage WHERE identity=? AND utc_day=?",
            (identity, utc_day),
        ).fetchone()
    return float(row[0])


def get_daily_usage(identity: str, utc_day: str) -> dict:
    with _db() as connection:
        row = connection.execute("""
            SELECT amount_usd, estimated_usd, input_tokens, output_tokens, calls
            FROM daily_usage WHERE identity=? AND utc_day=?
        """, (identity, utc_day)).fetchone()
        reserved = connection.execute("""
            SELECT COALESCE(SUM(amount_usd),0) FROM reservations
            WHERE identity=? AND utc_day=? AND expires_at>?
        """, (identity, utc_day, time.time())).fetchone()[0]
    row = row or (0.0, 0.0, 0, 0, 0)
    return {
        "total": float(row[0]), "estimated": float(row[1]),
        "input_tokens": int(row[2]), "output_tokens": int(row[3]),
        "calls": int(row[4]), "reserved": float(reserved),
    }


def reset_cost_usage() -> None:
    with _transaction() as connection:
        connection.execute("DELETE FROM daily_usage")
        connection.execute("DELETE FROM reservations")
