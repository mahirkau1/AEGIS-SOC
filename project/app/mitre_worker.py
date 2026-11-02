"""AEGIS SOC automatic MITRE analysis worker."""

import argparse
import json
import logging
import os
import sqlite3
import time

from app import storage
from app.mitre_adapter import analyze_process
from app.aegis_mitre import ProcessTracker

tracker = ProcessTracker()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

LOG = logging.getLogger("aegis.mitre")

POLL_SECONDS = 10
BATCH_SIZE = 500


def initialize(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS mitre_analysis (
            event_id INTEGER PRIMARY KEY,
            host TEXT,
            process_guid TEXT,
            risk_score INTEGER NOT NULL,
            verdict TEXT,
            findings TEXT NOT NULL,
            analyzed_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS mitre_worker_state (
            name TEXT PRIMARY KEY,
            last_event_id INTEGER NOT NULL DEFAULT 0
        )
    """)

    db.execute("""
        INSERT OR IGNORE INTO mitre_worker_state
        (name, last_event_id)
        VALUES ('sysmon', 0)
    """)

    db.commit()


def process_batch(db):
    cursor = db.execute("""
        SELECT last_event_id
        FROM mitre_worker_state
        WHERE name = 'sysmon'
    """)

    last_id = cursor.fetchone()[0]

    rows = db.execute("""
        SELECT id, payload
        FROM events
        WHERE id > ?
          AND source = 'SYSMON'
        ORDER BY id ASC
        LIMIT ?
    """, (last_id, BATCH_SIZE)).fetchall()

    if not rows:
        return 0, 0

    analyzed = 0
    detected = 0

    for event_id, raw in rows:
        try:
            event = json.loads(raw)
            if os.getenv("AEGIS_MITRE_V2", "0") == "1":
                result = tracker.analyze(event)
            else:
                result = analyze_process(event)

            if result.get("analyzed"):
                analyzed += 1

                if result.get("detections"):
                    detected += 1

                db.execute("""
                    INSERT OR IGNORE INTO mitre_analysis (
                        event_id,
                        host,
                        process_guid,
                        risk_score,
                        verdict,
                        findings
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    event_id,
                    result.get("host"),
                    result.get("process_guid"),
                    result.get("risk_score", 0),
                    result.get("verdict", "none"),
                    json.dumps(result, ensure_ascii=False),
                ))

        except Exception:
            LOG.exception("Failed to analyze event %s", event_id)
            db.rollback()
            raise

    db.execute("""
        UPDATE mitre_worker_state
        SET last_event_id = ?
        WHERE name = 'sysmon'
    """, (rows[-1][0],))

    db.commit()
    return analyzed, detected


def run(once=False):
    LOG.info("AEGIS MITRE worker started")

    with storage.connect() as db:
        initialize(db)

        while True:
            before = db.execute(
                "SELECT last_event_id FROM mitre_worker_state "
                "WHERE name='sysmon'"
            ).fetchone()[0]

            analyzed, detected = process_batch(db)

            after = db.execute(
                "SELECT last_event_id FROM mitre_worker_state "
                "WHERE name='sysmon'"
            ).fetchone()[0]

            if after != before:
                LOG.info(
                    "last_id=%s processes=%s detections=%s",
                    after, analyzed, detected
                )

            if once:
                break

            if after == before:
                time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    run(once=args.once)