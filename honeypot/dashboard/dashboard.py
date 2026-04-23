"""
dashboard.py
------------
Flask application for the Cowrie honeypot dashboard.
Routes only — all data access goes through db.py, scoring through threat.py.

Usage:
    pip install flask
    python dashboard.py
    python dashboard.py --db ../honeypot-logs/analysis/honeypot.db --port 5000
"""

from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os

load_dotenv()

import argparse
from pathlib import Path

from flask import Flask, render_template, jsonify, json, abort, request

from db import HoneypotDB
from threat import ThreatScorer

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    if username == os.getenv("DASHBOARD_USER") and \
       check_password_hash(generate_password_hash(os.getenv("DASHBOARD_PASS")), password):
        return username

# These are set at startup via CLI args
DB_PATH         = "../honeypot-logs/analysis/honeypot.db"
SIGNATURES_PATH = "signatures.json"
TTY_PATH        = Path.home() / "cowrie/var/lib/cowrie/tty"

def get_db() -> HoneypotDB:
    return HoneypotDB(DB_PATH)

def get_scorer() -> ThreatScorer:
    return ThreatScorer(SIGNATURES_PATH)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
@auth.login_required
def overview():
    db       = get_db()
    stats    = db.get_stats()
    timeline = db.get_sessions_per_day()
    hassh    = db.get_hassh_summary()
    top_pw   = db.get_top_passwords(limit=5)
    top_us   = db.get_top_usernames(limit=5)
    return render_template("overview.html",
        stats=stats,
        timeline=timeline,
        hassh=hassh,
        top_passwords=top_pw,
        top_usernames=top_us,
    )


@app.route("/sessions")
@auth.login_required
def sessions():
    db     = get_db()
    scorer = get_scorer()
    rows   = db.get_sessions()

    # Score all sessions
    scored = []
    for s in rows:
        commands = db.get_session_commands(s["session_id"])
        result   = scorer.score(s, commands)
        scored.append({
            **s,
            "threat": result.to_dict(),
            "login_user": db.get_session_login_user(s["session_id"])
        })

    # Date filtering
    date_from = request.args.get("date_from", "")
    date_to   = request.args.get("date_to", "")
    label     = request.args.get("label", "all")
    search    = request.args.get("search", "")
    try:
        page  = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page  = 1

    PER_PAGE = 25

    # Apply filters
    filtered = scored
    if date_from:
        filtered = [s for s in filtered if s.get("date", "") >= date_from]
    if date_to:
        filtered = [s for s in filtered if s.get("date", "") <= date_to]
    if label != "all":
        filtered = [s for s in filtered if s["threat"]["label"] == label]
    if search:
        q = search.lower()
        filtered = [s for s in filtered if
            q in s["src_ip"].lower() or
            q in s["session_id"].lower()]

    total      = len(filtered)
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page       = min(page, total_pages)
    paginated  = filtered[(page - 1) * PER_PAGE : page * PER_PAGE]

    return render_template("sessions.html",
        sessions=paginated,
        page=page,
        total_pages=total_pages,
        total=total,
        date_from=date_from,
        date_to=date_to,
        label=label,
        search=search,
    )


@app.route("/session/<session_id>")
@auth.login_required
def session_detail(session_id):
    db      = get_db()
    scorer  = get_scorer()

    session  = db.get_session(session_id)
    if not session:
        abort(404)

    events   = db.get_session_events(session_id)
    commands = db.get_session_commands(session_id)
    auth     = db.get_auth_attempts_for_session(session_id)
    threat   = scorer.score(session, commands)
    login_user = db.get_session_login_user(session_id)

    # Check if a TTY log exists for this session
    tty_file = None
    if session.get("ttylog"):
        full_path = Path.home() / "cowrie" / session["ttylog"]
        if full_path.exists():
            tty_file = full_path.name

    return render_template("session.html",
        session=session,
        events=events,
        commands=commands,
        auth=auth,
        threat=threat.to_dict(),
        tty_file=tty_file,
        login_user=login_user,
    )


@app.route("/map")
@auth.login_required
def ip_map():
    db      = get_db()
    ip_data = db.get_ip_summary()
    return render_template("map.html", ip_data=ip_data)


@app.route("/replay/<session_id>")
@auth.login_required
def replay(session_id):
    db      = get_db()
    session = db.get_session(session_id)
    if not session:
        abort(404)
    return render_template("replay.html", session=session, session_id=session_id)


# ---------------------------------------------------------------------------
# API endpoints (called by JS in templates)
# ---------------------------------------------------------------------------

@app.route("/api/stats")
@auth.login_required
def api_stats():
    return jsonify(get_db().get_stats())


@app.route("/api/sessions")
@auth.login_required
def api_sessions():
    return jsonify(get_db().get_sessions())


@app.route("/api/ip_summary")
@auth.login_required
def api_ip_summary():
    return jsonify(get_db().get_ip_summary())


@app.route("/api/tty/<session_id>")
@auth.login_required
def api_tty(session_id):
    """Return TTY log bytes for replay in the browser (ttyrec format)."""
    db      = get_db()
    session = db.get_session(session_id)

    if not session or not session.get("ttylog"):
        return jsonify({"error": "No TTY log recorded for this session"}), 404

    tty_file = Path.home() / "cowrie" / session["ttylog"]
    if not tty_file.exists():
        return jsonify({"error": "TTY file not found on disk", "path": str(tty_file)}), 404

    try:
        data = tty_file.read_bytes()
        return jsonify({
            "session_id": session_id,
            "filename":   tty_file.name,
            "size_bytes": len(data),
            "data":       list(data),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/session/<session_id>/export")
def export_session(session_id):
    db     = get_db()
    scorer = get_scorer()

    session  = db.get_session(session_id)
    if not session:
        abort(404)

    events   = db.get_session_events(session_id)
    commands = db.get_session_commands(session_id)
    auth     = db.get_auth_attempts_for_session(session_id)
    threat   = scorer.score(session, commands)

    payload = {
        "session":    session,
        "threat":     threat.to_dict(),
        "events":     events,
        "commands":   commands,
        "auth":       auth,
    }

    filename = f"session_{session_id[:12]}_{session.get('date', 'unknown')}.json"

    from flask import Response
    return Response(
        json.dumps(payload, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ---------------------------------------------------------------------------
# Error pages
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", error="Page not found"), 404


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    global DB_PATH, SIGNATURES_PATH, TTY_PATH

    parser = argparse.ArgumentParser(description="Cowrie Honeypot Dashboard")
    parser.add_argument("--db",
        default="../honeypot-logs/analysis/honeypot.db",
        help="Path to honeypot.db")
    parser.add_argument("--signatures",
        default="signatures.json",
        help="Path to signatures.json")
    parser.add_argument("--tty",
        default=str(Path.home() / "cowrie/var/lib/cowrie/tty"),
        help="Path to Cowrie TTY log directory")
    parser.add_argument("--port", type=int, default=5000,
        help="Port to serve on (default: 5000)")
    parser.add_argument("--debug", action="store_true",
        help="Run Flask in debug mode")
    args = parser.parse_args()

    DB_PATH         = args.db
    SIGNATURES_PATH = args.signatures
    TTY_PATH        = Path(args.tty)

    if not Path(DB_PATH).exists():
        print(f"[WARN] Database not found at '{DB_PATH}' — dashboard will show empty state.")
        print(f"       Run session_parser.py first.\n")

    print(f"  Honeypot Dashboard")
    print(f"  DB         : {DB_PATH}")
    print(f"  Signatures : {SIGNATURES_PATH}")
    print(f"  TTY logs   : {TTY_PATH}")
    print(f"  URL        : http://localhost:{args.port}\n")

    app.run(host="localhost", port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()