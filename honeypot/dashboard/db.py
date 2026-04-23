"""
db.py
-----
Database query layer for the honeypot dashboard.
All SQLite access goes through here — no queries in routes.

Usage:
    from db import HoneypotDB
    db = HoneypotDB("path/to/honeypot.db")
    sessions = db.get_sessions()
"""

import sqlite3
from pathlib import Path


class HoneypotDB:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self):
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {self.db_path}")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _query(self, sql: str, params: tuple = ()) -> list[dict]:
        try:
            with self._connect() as conn:
                cur = conn.execute(sql, params)
                return [dict(r) for r in cur.fetchall()]
        except (sqlite3.OperationalError, FileNotFoundError):
            return []

    def _query_one(self, sql: str, params: tuple = ()) -> dict:
        rows = self._query(sql, params)
        return rows[0] if rows else {}

    def exists(self) -> bool:
        return self.db_path.exists() and self.db_path.stat().st_size > 0

    # ------------------------------------------------------------------
    # Overview stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        sessions      = self._query_one("SELECT COUNT(*) AS n FROM sessions")
        attempts      = self._query_one("SELECT COUNT(*) AS n FROM auth_attempts")
        successful    = self._query_one("SELECT COUNT(*) AS n FROM auth_attempts WHERE success=1")
        unique_ips    = self._query_one("SELECT COUNT(DISTINCT src_ip) AS n FROM sessions")
        with_commands = self._query_one("SELECT COUNT(*) AS n FROM sessions WHERE commands_run > 0")
        return {
            "total_sessions":   sessions.get("n", 0),
            "total_attempts":   attempts.get("n", 0),
            "successful_logins": successful.get("n", 0),
            "unique_ips":       unique_ips.get("n", 0),
            "sessions_with_commands": with_commands.get("n", 0),
        }

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def get_sessions_per_day(self) -> list[dict]:
        return self._query("""
            SELECT date, COUNT(*) AS count
            FROM sessions
            GROUP BY date
            ORDER BY date ASC
        """)

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def get_sessions(self) -> list[dict]:
        return self._query("""
            SELECT
                session_id, src_ip, start_time, end_time,
                duration_seconds, login_attempts, login_success,
                commands_run, files_downloaded, client_version, hassh, date
            FROM sessions
            ORDER BY start_time DESC
        """)


    def get_session(self, session_id: str) -> dict:
        return self._query_one("""
            SELECT * FROM sessions WHERE session_id = ?
        """, (session_id,))

    # ------------------------------------------------------------------
    # Events (for session drilldown)
    # ------------------------------------------------------------------

    def get_session_events(self, session_id: str) -> list[dict]:
        return self._query("""
            SELECT event_id, timestamp, message, extra
            FROM events
            WHERE session_id = ?
            ORDER BY timestamp ASC
        """, (session_id,))

    def get_session_commands(self, session_id: str) -> list[dict]:
        return self._query("""
            SELECT timestamp, message
            FROM events
            WHERE session_id = ?
              AND event_id IN ('cowrie.command.input', 'cowrie.command.failed')
            ORDER BY timestamp ASC
        """, (session_id,))

    # ------------------------------------------------------------------
    # Auth attempts
    # ------------------------------------------------------------------

    def get_top_passwords(self, limit: int = 10) -> list[dict]:
        return self._query("""
            SELECT password, COUNT(*) AS count
            FROM auth_attempts
            GROUP BY password
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))

    def get_top_usernames(self, limit: int = 10) -> list[dict]:
        return self._query("""
            SELECT username, COUNT(*) AS count
            FROM auth_attempts
            GROUP BY username
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))

    def get_top_credential_pairs(self, limit: int = 10) -> list[dict]:
        return self._query("""
            SELECT username, password, COUNT(*) AS count
            FROM auth_attempts
            GROUP BY username, password
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))

    def get_auth_attempts_for_session(self, session_id: str) -> list[dict]:
        return self._query("""
            SELECT username, password, success, timestamp
            FROM auth_attempts
            WHERE session_id = ?
            ORDER BY timestamp ASC
        """, (session_id,))

    # ------------------------------------------------------------------
    # IP data (for map)
    # ------------------------------------------------------------------

    def get_ip_summary(self) -> list[dict]:
        return self._query("""
            SELECT
                src_ip,
                COUNT(*) AS session_count,
                SUM(login_success) AS successful_logins,
                SUM(commands_run) AS total_commands,
                MIN(start_time) AS first_seen,
                MAX(start_time) AS last_seen
            FROM sessions
            GROUP BY src_ip
            ORDER BY session_count DESC
        """)

    # ------------------------------------------------------------------
    # HASSH fingerprints
    # ------------------------------------------------------------------

    def get_hassh_summary(self) -> list[dict]:
        return self._query("""
            SELECT
                hassh,
                client_version,
                COUNT(*) AS session_count
            FROM sessions
            WHERE hassh IS NOT NULL
            GROUP BY hassh
            ORDER BY session_count DESC
        """)

    def get_session_login_user(self, session_id: str) -> str:
        row = self._query_one("""
            SELECT username FROM auth_attempts
            WHERE session_id = ? AND success = 1
            ORDER BY timestamp ASC LIMIT 1
        """, (session_id,))
        return row.get("username") if row else None