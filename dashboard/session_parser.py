"""
session_parser.py
-----------------
Parses Cowrie honeypot JSONL logs directly from Cowrie's native flat log file:
    honeypot-logs/raw-logs/cowrie.json  (and rotated: cowrie.json.1, cowrie.json.2, …)

Produces three structured outputs in honeypot-logs/analysis/:
    - sessions      : one record per SSH session
    - auth_attempts : one record per login attempt
    - events        : one record per raw event (full detail)

This replaces the old two-step splitter + parser pipeline.
Cowrie writes directly to its JSONL file; this script reads it.

Usage:
    python session_parser.py
    python session_parser.py --log /home/cowrie/Documents/honeypot-logs/raw-logs/cowrie.json
    python session_parser.py --log ... --output ./analysis --format sqlite
"""

import argparse
import csv
import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Event IDs emitted by Cowrie
# ---------------------------------------------------------------------------
EV_CONNECT    = "cowrie.session.connect"
EV_CLOSED     = "cowrie.session.closed"
EV_CLI_VER    = "cowrie.client.version"
EV_CLI_KEX    = "cowrie.client.kex"
EV_LOGIN_FAIL = "cowrie.login.failed"
EV_LOGIN_OK   = "cowrie.login.success"
EV_CMD_INPUT  = "cowrie.command.input"
EV_CMD_FAIL   = "cowrie.command.failed"
EV_FILE_DL    = "cowrie.session.file_download"
EV_FILE_UL    = "cowrie.session.file_upload"
EV_TTY_CLOSED = "cowrie.log.closed"


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_HERE          = Path(__file__).parent.resolve()
DEFAULT_LOG    = _HERE.parent / "logs" / "raw-logs" / "cowrie.json"
DEFAULT_OUTPUT = _HERE.parent / "logs" / "analysis"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_timestamp(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_flat_log(log_path: Path) -> list[dict]:
    """
    Read Cowrie's flat JSONL log file (and any rotated siblings like
    cowrie.json.1, cowrie.json.2, …) and return deduplicated event list
    sorted by timestamp ascending.

    Cowrie rotates logs by appending a numeric suffix; we read all of them
    so a fresh parse always sees the full history.
    """
    log_path = Path(log_path)
    if not log_path.exists():
        raise FileNotFoundError(f"Cowrie log not found: {log_path}")

    # Collect the primary log + any rotated copies
    parent   = log_path.parent
    stem     = log_path.name          # e.g. "cowrie.json"
    siblings = sorted(parent.glob(f"{stem}.*"), reverse=True)  # .1 oldest → .N newest? actually reversed
    # Read rotated first (oldest data), then current
    files_to_read = siblings + [log_path]

    events   = []
    seen_keys: set[tuple] = set()

    for fpath in files_to_read:
        print(f"  Reading {fpath}")
        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError as exc:
                    print(f"  [WARN] {fpath}:{line_no} — JSON parse error: {exc}")
                    continue

                dedup_key = (
                    ev.get("uuid"),
                    ev.get("eventid"),
                    ev.get("timestamp"),
                )
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)
                events.append(ev)

    # Sort chronologically
    def sort_key(ev):
        ts = ev.get("timestamp", "")
        try:
            return parse_timestamp(ts)
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    events.sort(key=sort_key)
    print(f"  Loaded {len(events)} unique events total.")
    return events


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

class CowrieParser:
    def __init__(self):
        self._sessions:    dict[str, dict] = {}
        self.auth_attempts: list[dict]     = []
        self.raw_events:    list[dict]     = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_events(self, events: list[dict]):
        for ev in events:
            self._process_event(ev)

    @property
    def sessions(self) -> list[dict]:
        return list(self._sessions.values())

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_session(self, session_id: str, ev: dict) -> dict:
        if session_id not in self._sessions:
            # Derive the date string from the event's own timestamp
            ts_str = ev.get("timestamp", "")
            try:
                date_str = parse_timestamp(ts_str).strftime("%Y-%m-%d")
            except Exception:
                date_str = ""

            self._sessions[session_id] = {
                "session_id":       session_id,
                "src_ip":           ev.get("src_ip", ""),
                "src_port":         None,
                "dst_ip":           None,
                "dst_port":         None,
                "protocol":         ev.get("protocol", "ssh"),
                "date":             date_str,
                "start_time":       None,
                "end_time":         None,
                "duration_seconds": None,
                "client_version":   None,
                "hassh":            None,
                "login_attempts":   0,
                "login_success":    False,
                "commands_run":     0,
                "files_downloaded": 0,
                "files_uploaded":   0,
                "ttylog": None,
            }
        return self._sessions[session_id]

    def _process_event(self, ev: dict):
        event_id   = ev.get("eventid", "")
        session_id = ev.get("session", "unknown")
        timestamp  = ev.get("timestamp", "")

        session = self._get_session(session_id, ev)

        raw_msg = ev.get("message", "")
        if not isinstance(raw_msg, str):
            raw_msg = json.dumps(raw_msg)

        extra_data = {
            k: v for k, v in ev.items()
            if k not in {"eventid", "session", "src_ip", "timestamp",
                         "message", "sensor", "uuid"}
        }

        self.raw_events.append({
            "session_id": str(session_id),
            "src_ip":     str(ev.get("src_ip", "")),
            "event_id":   str(event_id),
            "timestamp":  str(timestamp),
            "message":    raw_msg,
            "extra":      json.dumps(extra_data),
        })

        if event_id == EV_CONNECT:
            self._handle_connect(session, ev, timestamp)
        elif event_id == EV_CLOSED:
            self._handle_closed(session, ev, timestamp)
        elif event_id == EV_CLI_VER:
            session["client_version"] = ev.get("version")
        elif event_id == EV_CLI_KEX:
            session["hassh"] = ev.get("hassh")
        elif event_id in (EV_LOGIN_FAIL, EV_LOGIN_OK):
            self._handle_login(session, ev, timestamp, event_id)
        elif event_id in (EV_CMD_INPUT, EV_CMD_FAIL):
            session["commands_run"] += 1
        elif event_id == EV_FILE_DL:
            session["files_downloaded"] += 1
        elif event_id == EV_FILE_UL:
            session["files_uploaded"] += 1
        elif event_id == EV_TTY_CLOSED:
            session["ttylog"] = ev.get("ttylog")

    def _handle_connect(self, session: dict, ev: dict, timestamp: str):
        session["src_port"] = ev.get("src_port")
        session["dst_ip"]   = ev.get("dst_ip")
        session["dst_port"] = ev.get("dst_port")
        if session["start_time"] is None:
            session["start_time"] = timestamp

    def _handle_closed(self, session: dict, ev: dict, timestamp: str):
        session["end_time"] = timestamp
        if session["start_time"]:
            try:
                start = parse_timestamp(session["start_time"])
                end   = parse_timestamp(timestamp)
                session["duration_seconds"] = round(
                    (end - start).total_seconds(), 2
                )
            except ValueError:
                pass

    def _handle_login(self, session: dict, ev: dict, timestamp: str, event_id: str):
        success = event_id == EV_LOGIN_OK
        session["login_attempts"] += 1
        if success:
            session["login_success"] = True

        self.auth_attempts.append({
            "session_id": session["session_id"],
            "src_ip":     ev.get("src_ip", ""),
            "username":   ev.get("username", ""),
            "password":   ev.get("password", ""),
            "success":    success,
            "timestamp":  timestamp,
        })


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_csv(sessions, auth_attempts, raw_events, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    def dump(name, rows, fieldnames):
        path = output_dir / f"{name}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, escapechar='\\', doublequote=True)
            writer.writeheader()
            writer.writerows(rows)
        print(f"  Wrote {len(rows):>6} rows → {path}")

    dump("sessions", sessions, [
        "session_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "date", "start_time", "end_time", "duration_seconds",
        "client_version", "hassh",
        "login_attempts", "login_success", "commands_run",
        "files_downloaded", "files_uploaded", "ttylog",
    ])
    dump("auth_attempts", auth_attempts, [
        "session_id", "src_ip", "username", "password", "success", "timestamp",
    ])
    dump("events", raw_events, [
        "session_id", "src_ip", "event_id", "timestamp", "message", "extra",
    ])


def write_sqlite(sessions, auth_attempts, raw_events, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    db_path = output_dir / "honeypot.db"

    conn = sqlite3.connect(db_path)
    cur  = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id       TEXT PRIMARY KEY,
            src_ip           TEXT,
            src_port         INTEGER,
            dst_ip           TEXT,
            dst_port         INTEGER,
            protocol         TEXT,
            date             TEXT,
            start_time       TEXT,
            end_time         TEXT,
            duration_seconds REAL,
            client_version   TEXT,
            hassh            TEXT,
            login_attempts   INTEGER DEFAULT 0,
            login_success    INTEGER DEFAULT 0,
            commands_run     INTEGER DEFAULT 0,
            files_downloaded INTEGER DEFAULT 0,
            files_uploaded   INTEGER DEFAULT 0,
            ttylog           TEXT
        );

        CREATE TABLE IF NOT EXISTS auth_attempts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            src_ip     TEXT,
            username   TEXT,
            password   TEXT,
            success    INTEGER,
            timestamp  TEXT
        );

        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            src_ip     TEXT,
            event_id   TEXT,
            timestamp  TEXT,
            message    TEXT,
            extra      TEXT
        );

        -- Wipe old data so a fresh parse is always consistent
        DELETE FROM sessions;
        DELETE FROM auth_attempts;
        DELETE FROM events;
    """)

    try:
        conn.execute("ALTER TABLE sessions ADD COLUMN ttylog TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # column already exists

    cur.executemany("""
        INSERT OR REPLACE INTO sessions VALUES (
            :session_id, :src_ip, :src_port, :dst_ip, :dst_port, :protocol,
            :date, :start_time, :end_time, :duration_seconds,
            :client_version, :hassh,
            :login_attempts, :login_success, :commands_run,
            :files_downloaded, :files_uploaded, :ttylog
        )
    """, [{**s, "login_success": int(s["login_success"])} for s in sessions])

    cur.executemany("""
        INSERT INTO auth_attempts
            (session_id, src_ip, username, password, success, timestamp)
        VALUES
            (:session_id, :src_ip, :username, :password, :success, :timestamp)
    """, [{**a, "success": int(a["success"])} for a in auth_attempts])

    cur.executemany("""
        INSERT INTO events (session_id, src_ip, event_id, timestamp, message, extra)
        VALUES (:session_id, :src_ip, :event_id, :timestamp, :message, :extra)
    """, raw_events)

    conn.commit()
    conn.close()

    print(f"  Wrote SQLite → {db_path}")
    print(f"    sessions:      {len(sessions)}")
    print(f"    auth_attempts: {len(auth_attempts)}")
    print(f"    events:        {len(raw_events)}")


def print_summary(sessions, auth_attempts):
    print("\n" + "=" * 50)
    print("PARSE SUMMARY")
    print("=" * 50)
    print(f"  Total sessions:       {len(sessions)}")
    print(f"  Total auth attempts:  {len(auth_attempts)}")

    successful = [a for a in auth_attempts if a["success"]]
    print(f"  Successful logins:    {len(successful)}")

    unique_ips = {s["src_ip"] for s in sessions}
    print(f"  Unique source IPs:    {len(unique_ips)}")

    pw_counts = Counter(a["password"] for a in auth_attempts)
    print("\n  Top 5 passwords tried:")
    for pw, count in pw_counts.most_common(5):
        print(f"    {count:>4}x  {pw!r}")

    user_counts = Counter(a["username"] for a in auth_attempts)
    print("\n  Top 5 usernames tried:")
    for user, count in user_counts.most_common(5):
        print(f"    {count:>4}x  {user!r}")

    print("=" * 50)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Parse Cowrie flat JSONL log into structured data."
    )
    parser.add_argument(
        "--log",
        default=DEFAULT_LOG,
        help=f"Path to cowrie.json (default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--format",
        choices=["csv", "sqlite", "both"],
        default="both",
        help="Output format (default: both)",
    )
    args = parser.parse_args()

    log_path   = Path(args.log)
    output_dir = Path(args.output)

    print(f"\nCowrie Session Parser")
    print(f"  Log file : {log_path}")
    print(f"  Output   : {output_dir}")
    print(f"  Format   : {args.format}")
    print()

    events = load_flat_log(log_path)

    cp = CowrieParser()
    cp.parse_events(events)

    sessions      = cp.sessions
    auth_attempts = cp.auth_attempts
    raw_events    = cp.raw_events

    print("\nWriting output…")
    if args.format in ("csv", "both"):
        write_csv(sessions, auth_attempts, raw_events, output_dir)
    if args.format in ("sqlite", "both"):
        write_sqlite(sessions, auth_attempts, raw_events, output_dir)

    print_summary(sessions, auth_attempts)


if __name__ == "__main__":
    main()