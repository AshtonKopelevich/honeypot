"""
threat.py
---------
Threat scoring engine for Cowrie honeypot sessions.

Combines rule-based signature matching against commands with
behavioral analysis (command bursting, execution from sensitive paths).

Usage:
    from threat import ThreatScorer
    scorer = ThreatScorer("signatures.json")
    result = scorer.score(session, events, commands)
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ThreatHit:
    severity: str       # CRITICAL, HIGH, MEDIUM, BEHAVIORAL
    rule:     str       # machine-readable rule name
    detail:   str       # human-readable description
    command:  str = ""  # the command that triggered it (if applicable)


@dataclass
class ThreatResult:
    score:  int
    label:  str                      # CRITICAL, HIGH, MEDIUM, LOW
    hits:   list[ThreatHit] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "label": self.label,
            "hits": [
                {
                    "severity": h.severity,
                    "rule":     h.rule,
                    "detail":   h.detail,
                    "command":  h.command,
                }
                for h in self.hits
            ],
        }


# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {
    "CRITICAL":   40,
    "HIGH":       20,
    "MEDIUM":      8,
    "BEHAVIORAL": 15,
}

SCORE_LABELS = [
    (75, "CRITICAL"),
    (50, "HIGH"),
    (25, "MEDIUM"),
    (0,  "LOW"),
]

# Behavioral thresholds
BURST_WINDOW_SECONDS  = 1.0   # time window for burst detection
BURST_COMMAND_THRESHOLD = 10  # commands within window = burst
RECON_WINDOW_SECONDS  = 5.0   # window for rapid recon sequence
RECON_SEQUENCE_MIN    = 3     # min recon hits within window = flag

RECON_RULES = {
    "system_fingerprint", "user_enumeration", "network_discovery",
    "process_discovery", "hostname_recon",
}

SENSITIVE_EXEC_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/"]


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class ThreatScorer:
    def __init__(self, signatures_path: str):
        path = Path(signatures_path)
        if not path.exists():
            raise FileNotFoundError(f"Signatures file not found: {path}")

        with open(path, "r") as f:
            raw = json.load(f)

        # Compile all regex patterns once at load time
        self._signatures: dict[str, list[dict]] = {}
        for severity, rules in raw.items():
            compiled = []
            for rule in rules:
                try:
                    compiled.append({
                        "rule":        rule["rule"],
                        "description": rule["description"],
                        "pattern":     re.compile(rule["pattern"], re.IGNORECASE),
                    })
                except re.error as e:
                    print(f"[WARN] Bad regex in rule '{rule['rule']}': {e}")
            self._signatures[severity] = compiled

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, session: dict, commands: list[dict]) -> ThreatResult:
        """
        Score a session given its metadata and command list.

        Args:
            session:  dict from db.get_session()
            commands: list of dicts from db.get_session_commands()

        Returns:
            ThreatResult with score, label, and list of hits
        """
        hits: list[ThreatHit] = []

        hits.extend(self._match_signatures(commands))
        hits.extend(self._detect_command_burst(commands))
        hits.extend(self._detect_recon_sequence(hits, commands))

        # Deduplicate by rule — only count each rule once per session
        seen_rules = set()
        deduped = []
        for hit in hits:
            if hit.rule not in seen_rules:
                seen_rules.add(hit.rule)
                deduped.append(hit)

        score = self._calculate_score(deduped)
        label = self._label(score)

        return ThreatResult(score=score, label=label, hits=deduped)

    # ------------------------------------------------------------------
    # Signature matching
    # ------------------------------------------------------------------

    def _match_signatures(self, commands: list[dict]) -> list[ThreatHit]:
        hits = []
        for cmd in commands:
            raw_cmd = self._extract_command(cmd.get("message", ""))
            if not raw_cmd:
                continue
            for severity, rules in self._signatures.items():
                for rule in rules:
                    if rule["pattern"].search(raw_cmd):
                        hits.append(ThreatHit(
                            severity=severity,
                            rule=rule["rule"],
                            detail=rule["description"],
                            command=raw_cmd,
                        ))
        return hits

    # ------------------------------------------------------------------
    # Behavioral detection
    # ------------------------------------------------------------------

    def _detect_command_burst(self, commands: list[dict]) -> list[ThreatHit]:
        """Flag sessions where commands arrive faster than humanly possible."""
        if len(commands) < BURST_COMMAND_THRESHOLD:
            return []

        timestamps = []
        for cmd in commands:
            ts = self._parse_timestamp(cmd.get("timestamp", ""))
            if ts:
                timestamps.append(ts)

        if len(timestamps) < BURST_COMMAND_THRESHOLD:
            return []

        timestamps.sort()
        for i in range(len(timestamps) - BURST_COMMAND_THRESHOLD + 1):
            window = (timestamps[i + BURST_COMMAND_THRESHOLD - 1] - timestamps[i]).total_seconds()
            if window <= BURST_WINDOW_SECONDS:
                count = BURST_COMMAND_THRESHOLD
                return [ThreatHit(
                    severity="BEHAVIORAL",
                    rule="command_burst",
                    detail=f"{count}+ commands executed in {window:.1f}s — automated script likely",
                )]
        return []

    def _detect_recon_sequence(self, existing_hits: list[ThreatHit], commands: list[dict]) -> list[ThreatHit]:
        """
        Flag rapid succession of recon commands within a short window.
        Only triggers if not already caught by individual signature hits.
        """
        recon_hits = [h for h in existing_hits if h.rule in RECON_RULES]
        if len(recon_hits) >= RECON_SEQUENCE_MIN:
            return [ThreatHit(
                severity="BEHAVIORAL",
                rule="recon_sequence",
                detail=f"{len(recon_hits)} reconnaissance commands detected in session",
            )]
        return []

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _calculate_score(self, hits: list[ThreatHit]) -> int:
        total = sum(SEVERITY_WEIGHTS.get(h.severity, 0) for h in hits)
        return min(total, 100)

    def _label(self, score: int) -> str:
        for threshold, label in SCORE_LABELS:
            if score >= threshold:
                return label
        return "LOW"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_command(self, message: str) -> str:
        """Strip Cowrie's 'CMD: ' prefix from command messages."""
        if message.startswith("CMD: "):
            return message[5:].strip()
        return message.strip()

    def _parse_timestamp(self, ts: str) -> datetime | None:
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None