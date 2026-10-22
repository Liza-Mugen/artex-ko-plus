#!/usr/bin/env python3
"""Normalize real ModSecurity native transactions and ship audits to Splunk HEC.

This collector never manufactures alerts. Detection is performed by Splunk's
saved search. A 403 response alone is never proof of WAF interception.
"""

import argparse
import hashlib
import hmac
import http.client
import json
import os
import re
import signal
import sqlite3
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4, uuid5, NAMESPACE_URL


MAX_TRANSACTION_BYTES = 256 * 1024
MAX_LOCAL_BYTES = 64 * 1024 * 1024
MAX_BATCH = 100
PART = re.compile(rb"^--([A-Za-z0-9]+)-([A-Z])--\r?\n", re.MULTILINE)
START = re.compile(rb"^--([A-Za-z0-9]+)-A--\r?\n", re.MULTILINE)
RULE_META = re.compile(r'(?<!\\)\[file "(?:\\.|[^"\\])*"\]\s+\[line "\d+"\]\s+\[id "(\d+)"\]')
SCOPE = os.environ.get("CONTROL_SCOPE", "artex-purple-lab-modsecurity")
ID_NAMESPACES = {
    "artex-purple-lab-modsecurity": "artex-purple-lab",
    "artex-vuln-bank-modsecurity": "artex-vuln-bank",
}
if SCOPE not in ID_NAMESPACES:
    raise ValueError("unsupported local collector scope")


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def source_checkpoint(stream, offset):
    """Bind a cursor to file content and inode, not Docker's mount device ID.

    Docker Desktop can assign a new st_dev to the same bind-mounted file after
    its VM restarts. The inode and two bounded content anchors still protect
    against replacement or in-place rewriting around the saved cursor.
    """
    position = stream.tell()
    try:
        length = min(offset, 4096)
        stream.seek(0)
        prefix = hashlib.sha256(stream.read(length)).hexdigest()
        stream.seek(offset - length)
        tail = hashlib.sha256(stream.read(length)).hexdigest()
    finally:
        stream.seek(position)
    return f"v2:{os.fstat(stream.fileno()).st_ino}:{offset}:{prefix}:{tail}"


def matches_source_checkpoint(stream, saved, offset):
    if not saved:
        return True
    if saved.startswith("v2:"):
        return hmac.compare_digest(saved, source_checkpoint(stream, offset))
    # Legacy state stored st_dev:st_ino. The device ID is unstable on Docker
    # Desktop bind mounts; accepting the same inode is no weaker than that
    # legacy check when the host file is unchanged.
    parts = saved.split(":")
    return len(parts) == 2 and all(part.isdecimal() for part in parts) and int(parts[1]) == os.fstat(stream.fileno()).st_ino


class EvidenceError(ValueError):
    pass


def native_frames(data):
    """Yield only complete native A..Z frames and their byte end offsets.

    Empty separators are permitted. Unexpected non-whitespace data, nested A
    sections, and oversize incomplete records stop the collector visibly.
    """
    cursor = 0
    while cursor < len(data):
        first = START.search(data, cursor)
        if not first:
            if data[cursor:].strip() and len(data[cursor:]) >= MAX_TRANSACTION_BYTES:
                raise EvidenceError("unrecognized or oversize native audit data")
            return
        if data[cursor:first.start()].strip():
            raise EvidenceError("unrecognized native audit prefix")
        boundary = first.group(1)
        ending = re.compile(rb"^--" + boundary + rb"-Z--\r?\n", re.MULTILINE).search(data, first.end())
        next_start = START.search(data, first.end())
        if next_start and (ending is None or next_start.start() < ending.start()):
            raise EvidenceError("native audit transaction ended without Z")
        if ending is None:
            if len(data) - first.start() >= MAX_TRANSACTION_BYTES:
                raise EvidenceError("native audit transaction exceeds size limit")
            return
        if ending.end() - first.start() > MAX_TRANSACTION_BYTES:
            raise EvidenceError("native audit transaction exceeds size limit")
        yield data[first.start():ending.end()], ending.end()
        cursor = ending.end()


def normalize_native(raw, default_target="purple-lab-target:8080"):
    matches = list(PART.finditer(raw))
    if not matches or matches[0].group(2) != b"A" or matches[-1].group(2) != b"Z":
        raise EvidenceError("native audit is not a complete A..Z transaction")
    boundary = matches[0].group(1)
    parts = {}
    for index, match in enumerate(matches):
        if match.group(1) != boundary:
            raise EvidenceError("native audit section boundary mismatch")
        section = match.group(2).decode("ascii")
        if section in parts:
            raise EvidenceError("duplicate native audit section")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(raw)
        try:
            parts[section] = raw[match.end():end].decode("utf-8", errors="strict").strip("\r\n")
        except UnicodeDecodeError as exc:
            raise EvidenceError("native audit is not UTF-8") from exc
    if not all(part in parts for part in ("A", "B", "H", "Z")):
        raise EvidenceError("native audit lacks required ABHZ sections")

    header = re.match(r"^\[([^\]]+)\]\s+(\S+)\s+(\S+)\s+\d+\s+\S+\s+\d+", parts["A"])
    if not header:
        raise EvidenceError("native audit has an invalid transaction header")
    try:
        # Current Apache images retain microseconds; older native logs do not.
        time_format = "%d/%b/%Y:%H:%M:%S.%f %z" if "." in header.group(1) else "%d/%b/%Y:%H:%M:%S %z"
        header_timestamp = datetime.strptime(header.group(1), time_format).astimezone(timezone.utc)
    except ValueError as exc:
        raise EvidenceError("native audit has an invalid timestamp") from exc

    request_lines = parts["B"].splitlines()
    request = re.match(r"^(\S+)\s+(\S+)\s+HTTP/\d(?:\.\d)?$", request_lines[0] if request_lines else "")
    if not request:
        raise EvidenceError("native audit has an invalid request line")
    method, request_target = request.groups()
    headers = {}
    for line in request_lines[1:]:
        name, separator, value = line.partition(":")
        if not separator:
            raise EvidenceError("native request headers are malformed")
        headers.setdefault(name.lower(), []).append(value.strip())

    verification_values = headers.get("x-artex-verification-id", [])
    correlation = {"correlation_status": "missing" if not verification_values else "invalid"}
    if len(verification_values) == 1:
        try:
            candidate = verification_values[0]
            canonical = str(UUID(candidate))
            if candidate.lower() == canonical:
                correlation = {"correlation_status": "valid", "artex_verification_id": canonical}
        except (ValueError, AttributeError):
            pass

    hosts = headers.get("host", [])
    request_host = hosts[0] if len(hosts) == 1 and re.fullmatch(r"[A-Za-z0-9.\[\]:_-]{1,255}", hosts[0]) else None
    # Origin/absolute-form URI parsing does not contact the URI's host.
    parsed_request = urlsplit(request_target)
    path = parsed_request.path if request_target.startswith(("http://", "https://")) else request_target.split("?", 1)[0]
    # Preserve the observed URI for independent SIEM rules. Dropping the query
    # previously made SQLi/XSS payloads invisible outside the WAF rule IDs.
    query_string = parsed_request.query
    h_lines = parts["H"].splitlines()
    # ModSecurity's documented Stopwatch first value is the transaction's
    # Unix timestamp in microseconds. Use this request start time rather than
    # collection time; preserve A as a separate audit-header observation.
    # https://github.com/owasp-modsecurity/ModSecurity/wiki/ModSecurity-2-Data-Formats#stopwatch
    stopwatch = []
    for line in h_lines:
        if line.startswith(("Stopwatch:", "Stopwatch2:")):
            match = re.match(r"^Stopwatch2?: (\d{1,20}) (\d{1,20})(?:\s|;|$)", line)
            if not match:
                raise EvidenceError("native audit has an invalid stopwatch")
            stopwatch.append((int(match.group(1)), int(match.group(2))))
    timestamp, timestamp_basis = header_timestamp, "native_audit_header"
    if stopwatch:
        if len(stopwatch) > 2 or len({value[0] for value in stopwatch}) != 1:
            raise EvidenceError("native audit stopwatch timestamps disagree")
        micros, duration = stopwatch[0]
        try:
            timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micros)
        except OverflowError as exc:
            raise EvidenceError("native audit stopwatch timestamp is out of range") from exc
        header_delta = header_timestamp - timestamp
        if header_delta < timedelta(seconds=-1) or header_delta > timedelta(microseconds=duration) + timedelta(seconds=1):
            raise EvidenceError("native audit stopwatch does not match its header time")
        timestamp_basis = "modsecurity_stopwatch_transaction_start"
    mode_lines = [line for line in h_lines if line.startswith("Engine-Mode:")]
    mode = None
    if len(mode_lines) == 1:
        match = re.fullmatch(r'Engine-Mode:\s*"(ENABLED|DETECTION_ONLY|DISABLED)"', mode_lines[0])
        mode = match.group(1) if match else None
    actions = [line for line in h_lines if line.startswith("Action:")]
    intercepted = len(actions) == 1 and re.fullmatch(r"Action:\s*Intercepted \(phase [1-5]\)", actions[0]) is not None
    response = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s|$)", parts.get("F", ""))
    status = int(response.group(1)) if response else None
    if mode == "ENABLED" and intercepted:
        action, action_reason = "blocked", "modsecurity_intercepted_transaction"
    elif mode in ("ENABLED", "DETECTION_ONLY") and not actions and response:
        action, action_reason = "allowed", "modsecurity_completed_without_interception"
    else:
        action, action_reason = "unknown", "missing_or_inconsistent_engine_action"
    rule_ids = []
    for line in h_lines:
        if line.startswith("Message:"):
            for rule_id in RULE_META.findall(line):
                if rule_id != "1001002" and rule_id not in rule_ids:
                    rule_ids.append(rule_id)
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "id": str(uuid5(NAMESPACE_URL, ID_NAMESPACES[SCOPE] + "-native:" + digest)),
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"), "timestamp_basis": timestamp_basis,
        "audit_header_timestamp": header_timestamp.isoformat().replace("+00:00", "Z"),
        "request_uid": header.group(2), "source_ip": header.group(3),
        "event_kind": "audit", "control_scope": SCOPE, "source": "modsecurity-native-audit",
        "method": method, "target": default_target, "request_host": request_host,
        "path": path[:2048], "request_target": request_target[:4096],
        "query_string": query_string[:4096], "status": status,
        "action": action, "action_reason": action_reason,
        "action_basis": actions[0] if intercepted else "native completed transaction; no interception action",
        "engine_mode": mode or "unknown", "rule_ids": rule_ids,
        "rule_id": rule_ids[0] if rule_ids else "", "matched_rules": bool(rule_ids),
        "transaction_complete": True, "raw_sha256": digest, **correlation,
        **({"path_truncated": True} if len(path) > 2048 else {}),
        **({"request_target_truncated": True} if len(request_target) > 4096 else {}),
        **({"query_string_truncated": True} if len(query_string) > 4096 else {}),
    }


def append_json(path, value):
    data = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    if path.exists() and path.stat().st_size + len(data) > MAX_LOCAL_BYTES:
        raise EvidenceError("local evidence file reached the 64 MiB limit")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "ab") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def write_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, ensure_ascii=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


class PinnedHEC:
    """Verify pinned leaf identity and OpenSSL certificate validity before auth.

    The first anonymous handshake obtains the certificate. The verified second
    handshake uses that pinned leaf as a trust anchor and validates notBefore /
    notAfter. No credential is sent on the anonymous discovery connection.
    """

    def __init__(self, url, token_file, pin_file, index="artex_lab"):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("HEC URL must be an HTTPS endpoint without URL credentials")
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.path = parsed.path or "/services/collector/event"
        self.token_file = Path(token_file)
        self.pin_file = Path(pin_file)
        self.index = index
        self.context = None
        self.context_pin = None

    def _pin(self):
        pin = self.pin_file.read_text().strip().lower().replace(":", "")
        if not re.fullmatch(r"[0-9a-f]{64}", pin):
            raise EvidenceError("HEC certificate pin is invalid")
        return pin

    def _check_pin(self, certificate, pin):
        if not certificate or not hmac.compare_digest(hashlib.sha256(certificate).hexdigest(), pin):
            raise EvidenceError("HEC certificate pin does not match")

    def _connection(self):
        pin = self._pin()
        if self.context is None or self.context_pin != pin:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            discovery = http.client.HTTPSConnection(self.host, self.port, timeout=15, context=context)
            try:
                discovery.connect()
                cert = discovery.sock.getpeercert(binary_form=True)
                self._check_pin(cert, pin)
            finally:
                discovery.close()
            if not hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
                raise EvidenceError("TLS runtime does not support pinned leaf validation")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False  # Exact certificate identity is pinned.
            context.verify_mode = ssl.CERT_REQUIRED
            context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(cert))
            self.context, self.context_pin = context, pin
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=15, context=self.context)
        try:
            connection.connect()
            self._check_pin(connection.sock.getpeercert(binary_form=True), pin)
        except Exception:
            connection.close()
            raise
        return connection

    def send(self, events):
        connection = self._connection()
        try:
            token = self.token_file.read_text().strip()
            if not token or "\n" in token or "\r" in token:
                raise EvidenceError("HEC token file is invalid")
            body = "\n".join(json.dumps({
                "time": datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).timestamp(),
                # Keep indexed metadata and raw event source identical so
                # explicit JSON extraction cannot create conflicting values.
                "host": os.environ.get("LAB_HEC_HOST", "artex-purple-lab"),
                "source": event["source"],
                "sourcetype": "artex:lab:audit", "index": self.index, "event": event,
            }, ensure_ascii=False, separators=(",", ":")) for event in events).encode()
            connection.request("POST", self.path, body=body, headers={
                "Authorization": "Splunk " + token, "Content-Type": "application/json",
            })
            response = connection.getresponse()
            data = response.read(16 * 1024)
            result = json.loads(data)
            if (response.status != 200 or not isinstance(result, dict)
                    or type(result.get("code")) is not int or result["code"] != 0):
                raise EvidenceError("HEC did not acknowledge the audit batch")
        finally:
            connection.close()


class Collector:
    def __init__(self, directory, source, target, hec=None):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.source = Path(source)
        self.target = target
        self.hec = hec
        self.instance = str(uuid4())
        self.db = sqlite3.connect(self.directory / "collector.sqlite3")
        self.db.execute("CREATE TABLE IF NOT EXISTS state (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, payload TEXT NOT NULL, exported INTEGER DEFAULT 0, uploaded INTEGER DEFAULT 0)")
        self.db.commit()
        self.healthy, self.hec_healthy = True, False
        self.failure_code = None
        self.last_read_at = None
        self.exported_ids = set()
        audit = self.directory / "audit.jsonl"
        if audit.exists():
            if audit.stat().st_size > MAX_LOCAL_BYTES:
                raise EvidenceError("audit evidence exceeds size limit")
            with audit.open() as stream:
                for line in stream:
                    self.exported_ids.add(json.loads(line)["id"])
        else:
            fd = os.open(audit, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)

    def _state(self, name, default=""):
        row = self.db.execute("SELECT value FROM state WHERE name=?", (name,)).fetchone()
        return row[0] if row else default

    def _save_state(self, name, value):
        self.db.execute("INSERT OR REPLACE INTO state(name,value) VALUES (?,?)", (name, str(value)))

    def ingest(self):
        if not self.source.exists():
            return
        with self.source.open("rb") as stream:
            stat = os.fstat(stream.fileno())
            saved_identity = self._state("source_identity")
            offset = int(self._state("offset", "0"))
            if stat.st_size < offset:
                raise EvidenceError("audit source shrank; collection coverage is incomplete")
            if not matches_source_checkpoint(stream, saved_identity, offset):
                raise EvidenceError("audit source rotated; explicit new collection is required")
            stream.seek(offset)
            data = stream.read(MAX_TRANSACTION_BYTES * 2)
            for raw, end_offset in native_frames(data):
                event = normalize_native(raw, self.target)
                checkpoint = source_checkpoint(stream, offset + end_offset)
                with self.db:
                    self.db.execute("INSERT OR IGNORE INTO events(id,payload) VALUES (?,?)", (event["id"], json.dumps(event, ensure_ascii=False)))
                    self._save_state("source_identity", checkpoint)
                    self._save_state("offset", offset + end_offset)
                self.last_read_at = utc_now()

    def export(self):
        rows = self.db.execute("SELECT id,payload FROM events WHERE exported=0 ORDER BY rowid LIMIT ?", (MAX_BATCH,)).fetchall()
        for event_id, payload in rows:
            if event_id not in self.exported_ids:
                append_json(self.directory / "audit.jsonl", json.loads(payload))
                self.exported_ids.add(event_id)
            with self.db:
                self.db.execute("UPDATE events SET exported=1 WHERE id=?", (event_id,))

    def upload(self):
        if self.hec is None:
            return
        rows = self.db.execute("SELECT id,payload FROM events WHERE exported=1 AND uploaded=0 ORDER BY rowid LIMIT ?", (MAX_BATCH,)).fetchall()
        if not rows:
            return
        self.hec.send([json.loads(row[1]) for row in rows])
        with self.db:
            self.db.executemany("UPDATE events SET uploaded=1 WHERE id=?", ((row[0],) for row in rows))
        self.hec_healthy = True

    def status(self, event="heartbeat"):
        pending = self.db.execute("SELECT count(*) FROM events WHERE uploaded=0").fetchone()[0]
        status = {"timestamp": utc_now(), "updated_at": utc_now(), "instance_id": self.instance,
                  "scope": SCOPE, "event": event, "healthy": self.healthy,
                  "hec_healthy": self.hec_healthy, "pending_count": pending,
                  "last_read_at": self.last_read_at,
                  "source_present": self.source.exists(),
                  "coverage_claim": "collector_health_only"}
        if self.failure_code:
            status["failure_code"] = self.failure_code
        write_json(self.directory / "collector-status.json", status)
        append_json(self.directory / "metadata.jsonl", status)
        return status


def health(directory):
    try:
        status = json.loads((Path(directory) / "collector-status.json").read_text())
        observed = datetime.fromisoformat(status["updated_at"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - observed).total_seconds()
        return status.get("healthy") is True and status.get("source_present") is True and 0 <= age <= 30
    except (OSError, ValueError, KeyError):
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--health", action="store_true")
    args = parser.parse_args()
    directory = os.environ.get("LOG_DIR", "/logs")
    if args.health:
        return 0 if health(directory) else 1
    os.umask(0o077)
    hec = PinnedHEC(
        os.environ.get("SPLUNK_HEC_URL", "https://purple-lab-splunk:8088/services/collector/event"),
        os.environ.get("SPLUNK_HEC_TOKEN_FILE", "/run/lab-secrets/hec-token"),
        os.environ.get("SPLUNK_HEC_PIN_FILE", "/run/lab-secrets/splunk-hec.sha256"),
        os.environ.get("SPLUNK_INDEX", "artex_lab"),
    )
    collector = Collector(directory, os.environ.get("MODSEC_AUDIT_PATH", "/logs/modsec_audit.log"),
                          os.environ.get("TARGET", "purple-lab-target:8080"), hec)
    stopped = False

    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    collector.status("started")
    next_journal = 0
    while not stopped:
        try:
            collector.ingest()
            collector.export()
        except (OSError, ValueError, sqlite3.Error):
            collector.healthy = False
            collector.failure_code = "LOCAL_EVIDENCE_ERROR"
            collector.status("evidence_write_failed")
            print("collector: local evidence error; preserving source and stopping", file=sys.stderr)
            return 1
        try:
            collector.upload()
        except (OSError, ValueError, http.client.HTTPException):
            collector.hec_healthy = False
            # No raw error text, URLs, auth headers, or credential values in logs.
        if time.monotonic() >= next_journal:
            collector.status()
            next_journal = time.monotonic() + 5
        time.sleep(1)
    collector.status("stopped")
    collector.db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
