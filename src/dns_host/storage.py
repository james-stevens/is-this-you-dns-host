"""SQLite store for member zones, the catalog serial, rate limits and cache.

Replacing a zone and updating the catalog happen in one transaction.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS zones (
    apex TEXT PRIMARY KEY,
    serial INTEGER NOT NULL,
    document TEXT NOT NULL,
    admitted_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    rrsig_min_expiry INTEGER NOT NULL,
    rrsig_max_expiry INTEGER NOT NULL,
    last_parent_check INTEGER,
    parent_ok INTEGER NOT NULL DEFAULT 1,
    parent_drift_since INTEGER,
    parent_zone TEXT
);
CREATE TABLE IF NOT EXISTS catalog (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    serial INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS negative_cache (
    apex TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    http_status INTEGER NOT NULL,
    message TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limit (
    bucket TEXT PRIMARY KEY,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS parent_apex_day (
    parent_zone TEXT NOT NULL,
    apex TEXT NOT NULL,
    day TEXT NOT NULL,
    PRIMARY KEY (parent_zone, apex, day)
);
"""


@dataclass
class ZoneRow:
    apex: str
    serial: int
    document: dict
    admitted_at: int
    updated_at: int
    rrsig_min_expiry: int
    rrsig_max_expiry: int
    last_parent_check: int | None
    parent_ok: bool
    parent_drift_since: int | None
    parent_zone: str | None


@dataclass
class CachedFailure:
    reason: str
    http_status: int
    message: str
    expires_at: int


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._read() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @contextmanager
    def _read(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self):
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def ensure_catalog(self, now: int) -> int:
        with self.transaction() as conn:
            row = conn.execute("SELECT serial FROM catalog WHERE id = 1").fetchone()
            if row is None:
                conn.execute("INSERT INTO catalog (id, serial) VALUES (1, ?)", (now,))
                serial = now
            else:
                serial = int(row["serial"])
        self.republish_all()
        return serial

    def catalog_serial(self) -> int:
        with self._read() as conn:
            row = conn.execute("SELECT serial FROM catalog WHERE id = 1").fetchone()
            return int(row["serial"]) if row else 0

    def _row(self, row: sqlite3.Row | None) -> ZoneRow | None:
        if row is None:
            return None
        return ZoneRow(
            apex=row["apex"],
            serial=int(row["serial"]),
            document=json.loads(row["document"]),
            admitted_at=int(row["admitted_at"]),
            updated_at=int(row["updated_at"]),
            rrsig_min_expiry=int(row["rrsig_min_expiry"]),
            rrsig_max_expiry=int(row["rrsig_max_expiry"]),
            last_parent_check=row["last_parent_check"],
            parent_ok=bool(row["parent_ok"]),
            parent_drift_since=row["parent_drift_since"],
            parent_zone=row["parent_zone"],
        )

    def get_zone(self, apex: str) -> ZoneRow | None:
        with self._read() as conn:
            row = conn.execute("SELECT * FROM zones WHERE apex = ?", (apex,)).fetchone()
        return self._row(row)

    def list_zones(self) -> list[ZoneRow]:
        with self._read() as conn:
            rows = conn.execute("SELECT * FROM zones ORDER BY apex").fetchall()
        return [self._row(row) for row in rows]

    def list_members(self) -> list[str]:
        with self._read() as conn:
            rows = conn.execute("SELECT apex FROM zones ORDER BY apex").fetchall()
        return [row["apex"] for row in rows]

    def replace_zone(
        self,
        *,
        apex: str,
        serial: int,
        document: dict,
        now: int,
        rrsig_min_expiry: int,
        rrsig_max_expiry: int,
        parent_zone: str,
    ) -> tuple[bool, int]:
        """Atomically store the zone. Returns (catalog_updated, catalog_serial).

        The serial monotonicity check is repeated inside the transaction.
        """

        from dns_host.errors import ApiError

        with self.transaction() as conn:
            current = conn.execute(
                "SELECT serial FROM zones WHERE apex = ?", (apex,)
            ).fetchone()
            if current is not None and serial <= int(current["serial"]):
                raise ApiError(
                    409,
                    "serial_not_increased",
                    f"SOA serial {serial} is not greater than the stored serial {current['serial']}",
                )
            is_new = current is None
            payload = json.dumps(document, separators=(",", ":"))
            if is_new:
                conn.execute(
                    """INSERT INTO zones (
                        apex, serial, document, admitted_at, updated_at,
                        rrsig_min_expiry, rrsig_max_expiry, last_parent_check,
                        parent_ok, parent_drift_since, parent_zone
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?)""",
                    (
                        apex,
                        serial,
                        payload,
                        now,
                        now,
                        rrsig_min_expiry,
                        rrsig_max_expiry,
                        now,
                        parent_zone,
                    ),
                )
            else:
                conn.execute(
                    """UPDATE zones SET
                        serial = ?, document = ?, updated_at = ?,
                        rrsig_min_expiry = ?, rrsig_max_expiry = ?,
                        last_parent_check = ?, parent_ok = 1,
                        parent_drift_since = NULL, parent_zone = ?
                       WHERE apex = ?""",
                    (
                        serial,
                        payload,
                        now,
                        rrsig_min_expiry,
                        rrsig_max_expiry,
                        now,
                        parent_zone,
                        apex,
                    ),
                )
            catalog_serial = self._bump_catalog(conn, now) if is_new else self._catalog_serial(conn)
            result = (is_new, catalog_serial)
        self.publish_member(apex, document)
        return result

    def _catalog_serial(self, conn: sqlite3.Connection) -> int:
        row = conn.execute("SELECT serial FROM catalog WHERE id = 1").fetchone()
        if row is None:
            raise RuntimeError("catalog serial missing")
        return int(row["serial"])

    def _bump_catalog(self, conn: sqlite3.Connection, now: int) -> int:
        current = self._catalog_serial(conn)
        serial = max(current + 1, now)
        if serial == current:
            serial = current + 1
        conn.execute("UPDATE catalog SET serial = ? WHERE id = 1", (serial,))
        return serial

    def set_parent_state(
        self,
        apex: str,
        *,
        now: int,
        ok: bool,
        drift_since: int | None,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """UPDATE zones SET last_parent_check = ?, parent_ok = ?, parent_drift_since = ?
                   WHERE apex = ?""",
                (now, 1 if ok else 0, drift_since, apex),
            )

    def delete_zone(self, apex: str, now: int) -> int | None:
        """Remove a member and bump the catalog. Returns the new catalog serial."""

        with self.transaction() as conn:
            deleted = conn.execute("DELETE FROM zones WHERE apex = ?", (apex,)).rowcount
            if not deleted:
                serial = None
            else:
                serial = self._bump_catalog(conn, now)
        if serial is None:
            return None
        self.unpublish_member(apex)
        return serial

    def allow_rate(self, bucket: str, limit: int, window: int, now: int) -> bool:
        if limit <= 0:
            return True
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT window_start, count FROM rate_limit WHERE bucket = ?",
                (bucket,),
            ).fetchone()
            if row is None or now >= int(row["window_start"]) + window:
                conn.execute(
                    """INSERT INTO rate_limit (bucket, window_start, count)
                       VALUES (?, ?, 1)
                       ON CONFLICT(bucket) DO UPDATE SET window_start = ?, count = 1""",
                    (bucket, now, now),
                )
                return True
            if int(row["count"]) >= limit:
                return False
            conn.execute(
                "UPDATE rate_limit SET count = count + 1 WHERE bucket = ?",
                (bucket,),
            )
            return True

    def negative_get(self, apex: str, now: int) -> CachedFailure | None:
        with self._read() as conn:
            row = conn.execute(
                "SELECT * FROM negative_cache WHERE apex = ?", (apex,)
            ).fetchone()
        if row is None or int(row["expires_at"]) <= now:
            return None
        return CachedFailure(
            reason=row["reason"],
            http_status=int(row["http_status"]),
            message=row["message"],
            expires_at=int(row["expires_at"]),
        )

    def negative_put(
        self, apex: str, reason: str, http_status: int, message: str, expires_at: int
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO negative_cache (apex, reason, http_status, message, expires_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(apex) DO UPDATE SET
                     reason = excluded.reason,
                     http_status = excluded.http_status,
                     message = excluded.message,
                     expires_at = excluded.expires_at""",
                (apex, reason, http_status, message, expires_at),
            )

    def count_parent_day(self, parent_zone: str, day: str) -> int:
        with self._read() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM parent_apex_day WHERE parent_zone = ? AND day = ?",
                (parent_zone, day),
            ).fetchone()
        return int(row["n"])

    def parent_day_has(self, parent_zone: str, apex: str, day: str) -> bool:
        with self._read() as conn:
            row = conn.execute(
                """SELECT 1 FROM parent_apex_day
                   WHERE parent_zone = ? AND apex = ? AND day = ?""",
                (parent_zone, apex, day),
            ).fetchone()
        return row is not None

    def remember_parent_day(self, parent_zone: str, apex: str, day: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO parent_apex_day (parent_zone, apex, day)
                   VALUES (?, ?, ?)
                   ON CONFLICT DO NOTHING""",
                (parent_zone, apex, day),
            )

    def incr(self, name: str, amount: int = 1) -> None:
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO counters (name, value) VALUES (?, ?)
                   ON CONFLICT(name) DO UPDATE SET value = value + ?""",
                (name, amount, amount),
            )

    def counter(self, name: str) -> int:
        with self._read() as conn:
            row = conn.execute(
                "SELECT value FROM counters WHERE name = ?", (name,)
            ).fetchone()
        return int(row["value"]) if row else 0

    def zones_directory(self) -> Path:
        return self.path.parent / "zones"

    def publish_member(self, apex: str, document: dict) -> None:
        from dns_host.zonesync import write_catalogue, write_member

        directory = self.zones_directory()
        write_member(directory, apex, document)
        write_catalogue(directory, self.catalog_serial(), self._catalogue_members())

    def unpublish_member(self, apex: str) -> None:
        from dns_host.zonesync import write_catalogue, zone_filename

        directory = self.zones_directory()
        write_catalogue(directory, self.catalog_serial(), self._catalogue_members())
        (directory / zone_filename(apex)).unlink(missing_ok=True)

    def republish_all(self) -> None:
        from dns_host.zonesync import write_catalogue, write_member, zone_filename

        directory = self.zones_directory()
        directory.mkdir(parents=True, exist_ok=True)
        keep: set[str] = set()
        for row in self.list_zones():
            write_member(directory, row.apex, row.document)
            keep.add(zone_filename(row.apex))
        for path in directory.glob("*.json"):
            if path.name == "catalogue.json" or path.name in keep:
                continue
            path.unlink()
        write_catalogue(directory, self.catalog_serial(), self._catalogue_members())

    def _catalogue_members(self) -> list[dict]:
        return [{"apex": row.apex, "serial": row.serial} for row in self.list_zones()]

    def zones_in_grace(self, now: int) -> int:
        with self._read() as conn:
            row = conn.execute(
                """SELECT COUNT(*) AS n FROM zones
                   WHERE parent_drift_since IS NOT NULL
                      OR rrsig_max_expiry < ?""",
                (now,),
            ).fetchone()
        return int(row["n"])
