#!/usr/bin/env python3
"""Bounded, resumable app/PostgreSQL log collection for the local bank lab.

The source files remain authoritative. A changed inode or shorter file stops
collection visibly because continuing from a guessed offset would hide a gap.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import signal
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from purple.collector.collector import (
    EvidenceError, PinnedHEC, matches_source_checkpoint, source_checkpoint,
)


MAX_LINE_BYTES = 16 * 1024
MAX_READ_BYTES = 64 * 1024
MAX_BATCH = 100
MAX_PENDING = 10_000
MAX_DB_BYTES = 64 * 1024 * 1024
SOURCETYPES = {
    "app": "artex:vuln-bank:app",
    "postgres": "artex:vuln-bank:postgres",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_status(path, value):
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, ensure_ascii=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


class BankHEC(PinnedHEC):
    def send(self, events):
        connection = self._connection()
        try:
            token = self.token_file.read_text().strip()
            if not token or "\n" in token or "\r" in token:
                raise EvidenceError("HEC token file is invalid")
            body = "\n".join(json.dumps({
                "time": datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).timestamp(),
                "host": "artex-vuln-bank-lab",
                "source": event["source"],
                "sourcetype": event["sourcetype"],
                "index": self.index,
                "event": event,
            }, ensure_ascii=False, separators=(",", ":")) for event in events).encode()
            connection.request("POST", self.path, body=body, headers={
                "Authorization": "Splunk " + token,
                "Content-Type": "application/json",
            })
            response = connection.getresponse()
            result = json.loads(response.read(16 * 1024))
            if (response.status != 200 or not isinstance(result, dict)
                    or type(result.get("code")) is not int or result["code"] != 0):
                raise EvidenceError("HEC did not acknowledge the log batch")
        finally:
            connection.close()


class Collector:
    def __init__(self, state_dir, sources, hec=None):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.sources = {name: Path(path) for name, path in sources.items()}
        self.hec = hec
        self.db_path = self.state_dir / "collector.sqlite3"
        self.db = sqlite3.connect(self.db_path)
        self.db.execute("CREATE TABLE IF NOT EXISTS state (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, payload TEXT NOT NULL, uploaded INTEGER NOT NULL DEFAULT 0)")
        self.db.commit()
        self.healthy = True
        self.hec_healthy = False
        self.failure_code = None
        self.last_read_at = None

    def _state(self, name, default=""):
        row = self.db.execute("SELECT value FROM state WHERE name=?", (name,)).fetchone()
        return row[0] if row else default

    def _save_state(self, name, value):
        self.db.execute("INSERT OR REPLACE INTO state(name,value) VALUES (?,?)", (name, str(value)))

    def pending(self):
        return self.db.execute("SELECT count(*) FROM events WHERE uploaded=0").fetchone()[0]

    def ingest_source(self, name):
        path = self.sources[name]
        identity_key, offset_key = f"{name}:identity", f"{name}:offset"
        if not path.exists():
            if self._state(identity_key):
                raise EvidenceError("previously observed log source is missing")
            return 0
        with path.open("rb") as stream:
            stat = os.fstat(stream.fileno())
            identity = f"{stat.st_dev}:{stat.st_ino}"
            saved_identity = self._state(identity_key)
            offset = int(self._state(offset_key, "0"))
            if stat.st_size < offset:
                raise EvidenceError("log source shrank; coverage is incomplete")
            if not matches_source_checkpoint(stream, saved_identity, offset):
                raise EvidenceError("log source was replaced; coverage is incomplete")
            stream.seek(offset)
            count, remaining = 0, MAX_READ_BYTES
            while count < MAX_BATCH and remaining > 0:
                line = stream.readline(min(MAX_LINE_BYTES + 1, remaining))
                if not line:
                    break
                if len(line) > MAX_LINE_BYTES:
                    raise EvidenceError("log line exceeds the 16 KiB limit")
                if not line.endswith(b"\n"):
                    break  # Wait for a complete line; do not advance the offset.
                if self.pending() >= MAX_PENDING:
                    raise EvidenceError("pending HEC queue reached its limit")
                digest = hashlib.sha256(line).hexdigest()
                event = {
                    "id": str(uuid5(NAMESPACE_URL, f"artex-vuln-bank:{name}:{identity}:{offset}:{digest}")),
                    "timestamp": utc_now(),
                    "timestamp_basis": "collector_observation",
                    "source": f"vuln-bank-{name}",
                    "sourcetype": SOURCETYPES[name],
                    "message": line.decode("utf-8", errors="replace").rstrip("\r\n"),
                    "raw_base64": base64.b64encode(line).decode("ascii"),
                    "raw_sha256": digest,
                    "coverage_claim": "observed_log_line",
                }
                with self.db:
                    self.db.execute("INSERT OR IGNORE INTO events(id,payload) VALUES (?,?)",
                                    (event["id"], json.dumps(event, ensure_ascii=False)))
                    offset += len(line)
                    self._save_state(identity_key, source_checkpoint(stream, offset))
                    self._save_state(offset_key, offset)
                count += 1
                remaining -= len(line)
                self.last_read_at = event["timestamp"]
        if self.db_path.stat().st_size > MAX_DB_BYTES:
            raise EvidenceError("collector database reached its 64 MiB limit")
        return count

    def ingest(self):
        for name in SOURCETYPES:
            self.ingest_source(name)

    def upload(self):
        if self.hec is None:
            return
        rows = self.db.execute(
            "SELECT id,payload FROM events WHERE uploaded=0 ORDER BY rowid LIMIT ?", (MAX_BATCH,)
        ).fetchall()
        if not rows:
            return
        self.hec.send([json.loads(payload) for _, payload in rows])
        with self.db:
            self.db.executemany("UPDATE events SET uploaded=1 WHERE id=?", ((row[0],) for row in rows))
        self.hec_healthy = True

    def status(self, event="heartbeat"):
        status = {
            "timestamp": utc_now(),
            "updated_at": utc_now(),
            "scope": "artex-vuln-bank-logs",
            "event": event,
            "healthy": self.healthy,
            "hec_healthy": self.hec_healthy,
            "pending_count": self.pending(),
            "source_present": {name: path.exists() for name, path in self.sources.items()},
            "last_read_at": self.last_read_at,
            "coverage_claim": "collector_health_only",
        }
        if self.failure_code:
            status["failure_code"] = self.failure_code
        write_status(self.state_dir / "collector-status.json", status)
        return status

    def close(self):
        self.db.close()


def health(state_dir):
    try:
        status = json.loads((Path(state_dir) / "collector-status.json").read_text())
        updated = datetime.fromisoformat(status["updated_at"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - updated).total_seconds()
        return (status.get("healthy") is True and
                all(status.get("source_present", {}).values()) and
                len(status.get("source_present", {})) == 2 and 0 <= age <= 30)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--health", action="store_true")
    args = parser.parse_args()
    state_dir = os.environ.get("STATE_DIR", "/state")
    if args.health:
        return 0 if health(state_dir) else 1
    os.umask(0o077)
    hec = BankHEC(
        os.environ.get("SPLUNK_HEC_URL", "https://purple-lab-splunk:8088/services/collector/event"),
        os.environ.get("SPLUNK_HEC_TOKEN_FILE", "/run/lab-secrets/hec-token"),
        os.environ.get("SPLUNK_HEC_PIN_FILE", "/run/lab-secrets/splunk-hec.sha256"),
        os.environ.get("SPLUNK_INDEX", "ag_vuln_bank"),
    )
    collector = Collector(state_dir, {
        "app": os.environ.get("APP_LOG_PATH", "/logs/app.log"),
        "postgres": os.environ.get("POSTGRES_LOG_PATH", "/pglogs/postgresql.log"),
    }, hec)
    stopped = False

    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    collector.status("started")
    next_status = 0
    while not stopped:
        try:
            collector.ingest()
        except (OSError, ValueError, sqlite3.Error):
            collector.healthy = False
            collector.failure_code = "LOCAL_EVIDENCE_ERROR"
            collector.status("evidence_read_failed")
            print("bank logs collector: evidence error; preserving source and stopping", file=sys.stderr)
            collector.close()
            return 1
        try:
            collector.upload()
        except (OSError, ValueError, http.client.HTTPException):
            collector.hec_healthy = False
            # Never log URLs, raw events, credentials, or response bodies.
        if time.monotonic() >= next_status:
            collector.status()
            next_status = time.monotonic() + 5
        time.sleep(1)
    collector.status("stopped")
    collector.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
