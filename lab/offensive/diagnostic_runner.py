"""Scoped discovery and durable tool execution for ARTEX's integrated diagnosis.

Architecture adapted from RedAmon's staged recon and CyberStrikeAI's explicit tool
lifecycle; this is an independently implemented adapter, not either application.
No model calls, source uploads, arbitrary commands, or secret persistence.
"""
from __future__ import annotations

import collections
import contextlib
import copy
import datetime as dt
import hashlib
import hmac
import html
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid

from api_discovery import Links, static_js_paths, safe_path, query_names, origin, within

MAX_BODY = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_ARTIFACT = 4 * 1024 * 1024
MAX_RUNS = 200
MAX_API_OPERATIONS = 300
PATH_MODEL_VERSION = 4
ACTIVE = {'queued', 'running'}
TOOLS = ('http_probe', 'surface_map', 'crawl', 'nuclei')
# Read-only, general web entry points. These are leads, never vulnerability proof.
COMMON_SURFACE_PATHS = ('robots.txt', 'sitemap.xml', '.well-known/security.txt',
                        'api', 'api/docs', 'docs', 'swagger', 'openapi.json',
                        'swagger.json', 'api/openapi.json', 'static/openapi.json',
                        'ftp', 'files', 'uploads', 'admin', 'health', 'status')
OPENAPI_DOCUMENT_PATH = re.compile(r'(?:^|/)(?:openapi|swagger|api-docs)(?:[-_./][^/]*)?\.json$', re.I)
STATE_CHANGING_LEAD = re.compile(r'delete|remove|reset|execute|run|trigger|create|transfer|withdraw|approve|publish|send|submit|update|signout|logout', re.I)
SECRET_KEY = re.compile(r'password|passwd|secret|token|authorization|cookie|api.?key|credential|session|jwt', re.I)
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
ARTIFACT_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$')
DENIED_HOSTS = {'localhost', 'metadata', 'metadata.google.internal', 'instance-data', 'offensive-runner', 'artex', 'host.docker.internal', 'gateway.docker.internal'}
DENIED_PORTS = {8090, 8787, 8788}
PROVENANCE = [
    {'project': 'RedAmon', 'role': 'staged discovery and result provenance design', 'url': 'https://github.com/samugit83/redamon', 'revision': 'e1dfdff671b7e76d3a002eeba37b01d92cb949e1', 'integration': 'independent implementation'},
    {'project': 'CyberStrikeAI', 'role': 'execution identity, lifecycle, cancellation and structured errors design', 'url': 'https://github.com/AIPentest/CyberStrikeAI', 'revision': 'e6121e83eb5e307b7e88d7ccb05dd649d083fd82', 'integration': 'independent implementation'},
]


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


class DiagnosticError(Exception):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


def clean_url(value):
    """Never retain query values, fragments or embedded credentials in evidence."""
    try:
        p = urllib.parse.urlsplit(value)
        host = p.hostname or ''
        if ':' in host:
            host = '[' + host + ']'
        if p.port:
            host += ':' + str(p.port)
        return urllib.parse.urlunsplit((p.scheme, host, p.path, '', ''))
    except ValueError:
        return '[invalid URL]'


def redact(value, secrets=()):
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if SECRET_KEY.search(str(k)) else redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if not isinstance(value, str):
        return value
    for secret in secrets:
        if secret:
            value = value.replace(secret, '[REDACTED]')
    value = re.sub(r'(?im)^\s*(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie)\s*:[^\r\n]*', '[REDACTED HEADER]', value)
    value = re.sub(r'(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*', 'Bearer [REDACTED]', value)
    value = re.sub(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED]', value)
    value = re.sub(r'(?i)(["\']?(?:password|passwd|secret|token|access_token|refresh_token|api[_-]?key|session)["\']?\s*[:=]\s*)(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;}&]+)', r'\1"[REDACTED]"', value)
    # All URL query values are omitted even when their names are unfamiliar.
    value = re.sub(r'https?://[^\s<>"\']+', lambda m: clean_url(m[0]), value)
    return value


def check_address(address):
    ip = ipaddress.ip_address(address.split('%')[0])
    mapped = ip.ipv4_mapped if ip.version == 6 else None
    for candidate in (ip, mapped):
        if candidate and (candidate.is_loopback or candidate.is_link_local or candidate.is_unspecified or candidate.is_multicast or candidate.is_reserved):
            raise DiagnosticError('policy_denied', 'Loopback, metadata, link-local and reserved addresses are outside assessment scope.')


class Scope:
    def __init__(self, value):
        if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 or ord(c) == 127 or c == '\\' for c in value):
            raise ValueError('Target URL must be a valid HTTP(S) URL.')
        p = urllib.parse.urlsplit(value)
        self.origin = origin(value)
        if p.query or p.fragment or p.username or p.password or '%' in (p.hostname or ''):
            raise ValueError('Target URL must not include credentials, query values or fragments.')
        host = p.hostname.lower().rstrip('.')
        if host in DENIED_HOSTS or host.endswith('.localhost') or p.port in DENIED_PORTS:
            raise ValueError('Runner, application management, loopback and metadata endpoints are excluded.')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            try:
                check_address(host)
            except DiagnosticError as exc:
                raise ValueError(str(exc)) from exc
        self.prefix = safe_path(p.path or '/').rstrip('/')
        self.target = self.origin + (self.prefix or '/')

    def normalize(self, value, base=None):
        if not isinstance(value, str) or not value or len(value) > 2048 or value.startswith('//') or '\\' in value or any(ord(c) < 33 for c in value):
            raise DiagnosticError('policy_denied', 'Invalid or protocol-relative discovered URL.')
        joined = urllib.parse.urljoin(base or self.target, value)
        try:
            p = urllib.parse.urlsplit(joined)
            if origin(joined) != self.origin:
                raise ValueError('origin mismatch')
            path = safe_path(p.path or '/')
            if not within(path, self.prefix):
                raise ValueError('path prefix mismatch')
            names = query_names(p.query)
        except ValueError as exc:
            raise DiagnosticError('policy_denied', 'Discovered URL is outside the fixed origin/path scope.') from exc
        return self.origin + path, names


class ScopeSet:
    """Frozen URL-prefix allowlist. Discovery never grants new origins."""
    def __init__(self, target, values=None):
        primary = Scope(target)
        if values is None:
            values = [primary.target]
        if not isinstance(values, list) or not 1 <= len(values) <= 8 or any(not isinstance(v, str) for v in values):
            raise ValueError('Provide 1–8 explicit HTTP(S) scope URLs.')
        self.entries = [Scope(value) for value in values]
        if not any(self._accepts(entry, primary.target) for entry in self.entries):
            raise ValueError('Starting URL must be inside the registered scope.')
        self.target = primary.target
        self.seeds = list(dict.fromkeys([self.target] + [entry.target for entry in self.entries]))
        self.origin = primary.origin
        self.prefix = next(entry.prefix for entry in self.entries if self._accepts(entry, self.target))
        self.scope_urls = list(dict.fromkeys(entry.target for entry in self.entries))

    @staticmethod
    def _accepts(entry, value):
        try:
            entry.normalize(value)
            return True
        except DiagnosticError:
            return False

    def normalize(self, value, base=None):
        for entry in self.entries:
            try:
                return entry.normalize(value, base)
            except DiagnosticError:
                pass
        raise DiagnosticError('policy_denied', 'Discovered URL is outside the fixed URL-prefix scope.')


class RequestContext:
    """Single run's bounded, DNS-pinned HTTP transport; auth exists in memory only."""
    def __init__(self, scope, token, deadline, cancel, max_urls):
        self.scope, self.token, self.deadline, self.cancel = scope, token, deadline, cancel
        self.lock = threading.Lock()
        self.requests, self.bytes = 0, 0
        self.max_requests = max_urls * 6 + 12
        self.max_urls, self.seen = max_urls, set()
        self.last_request = 0.0

    def check(self):
        if self.cancel.is_set():
            raise DiagnosticError('cancelled', 'Run cancelled; partial evidence is retained.')
        if time.monotonic() >= self.deadline:
            raise DiagnosticError('execution_timeout', 'Run time budget exhausted; partial evidence is retained.')

    def fetch(self, value, headers=None):
        self.check()
        url, _ = self.scope.normalize(value)
        # Known read-URL logout/delete actions are not followed automatically.
        if re.search(r'/(?:logout|signout|delete|remove|reset-password)(?:/|$)', urllib.parse.urlsplit(url).path, re.I):
            raise DiagnosticError('policy_denied', 'State-changing action URL is excluded from automatic discovery.')
        with self.lock:
            if self.requests >= self.max_requests or self.bytes >= MAX_TOTAL:
                raise DiagnosticError('budget_exhausted', 'HTTP request or response-byte budget exhausted.')
            if url not in self.seen and len(self.seen) >= self.max_urls:
                raise DiagnosticError('url_limit', 'Distinct URL budget exhausted.')
            self.seen.add(url)
            self.requests += 1
            pause = max(0, self.last_request + 0.2 - time.monotonic())
            self.last_request = time.monotonic() + pause
        if self.cancel.wait(pause):
            self.check()
        self.check()
        request_deadline = min(self.deadline, time.monotonic() + 8)
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        resolved = queue.Queue(maxsize=1)
        def resolve():
            try:
                resolved.put((socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM), None))
            except OSError as exc:
                resolved.put((None, exc))
        threading.Thread(target=resolve, daemon=True).start()
        while True:
            self.check()
            try:
                addresses, error = resolved.get(timeout=min(0.1, max(0.001, request_deadline - time.monotonic())))
                break
            except queue.Empty:
                if time.monotonic() >= request_deadline:
                    raise DiagnosticError('execution_timeout', 'DNS resolution exceeded request deadline.')
        if error or not addresses:
            raise DiagnosticError('transient_dependency_error', 'Target hostname could not be resolved.')
        for address in addresses:
            check_address(address[4][0])
        ip = addresses[0][4][0]
        def remaining():
            self.check()
            left = request_deadline - time.monotonic()
            if left <= 0:
                raise DiagnosticError('execution_timeout', 'HTTP request exceeded its deadline.')
            return left
        conn = (http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection)(parsed.hostname, port, timeout=remaining())
        conn._create_connection = lambda address, timeout=None, source_address=None, **kwargs: socket.create_connection((ip, port), remaining(), source_address)
        stopped = threading.Event()
        active_socket = [None]
        def watchdog():
            while not stopped.wait(0.05):
                if self.cancel.is_set() or time.monotonic() >= request_deadline:
                    sock = conn.sock or active_socket[0]
                    if sock:
                        with contextlib.suppress(OSError):
                            sock.shutdown(socket.SHUT_RDWR)
                    return
        threading.Thread(target=watchdog, daemon=True).start()
        request_headers = {'User-Agent': 'AegisLoop-Diagnostics/1', 'Accept-Encoding': 'identity', 'Connection': 'close'}
        # Fixed adapter headers only; do not forward client cookies/auth/Host.
        if headers and headers.get('Origin') == 'https://aegisloop-origin.invalid':
            request_headers['Origin'] = headers['Origin']
        if self.token:
            request_headers['Authorization'] = 'Bearer ' + self.token
        try:
            conn.request('GET', parsed.path or '/', headers=request_headers)
            active_socket[0] = conn.sock
            response = conn.getresponse()
            remaining()
            response_headers = {key.lower(): val for key, val in response.getheaders()}
            if response_headers.get('content-encoding', '').lower() not in ('', 'identity'):
                raise DiagnosticError('parse_error', 'Compressed response was not expanded by the bounded transport.')
            data = bytearray()
            truncated = False
            while True:
                left = remaining()
                if response.isclosed() or response.length == 0:
                    break
                sock = conn.sock or active_socket[0]
                if sock:
                    sock.settimeout(left)
                with self.lock:
                    allowance = min(MAX_BODY - len(data), MAX_TOTAL - self.bytes)
                if allowance <= 0:
                    truncated = True
                    break
                chunk = response.read1(min(65536, allowance))
                with self.lock:
                    self.bytes += len(chunk)
                remaining()
                if not chunk:
                    break
                data.extend(chunk)
            return {'url': url, 'status': response.status, 'headers': response_headers, 'body': bytes(data), 'truncated': truncated}
        except DiagnosticError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            self.check()
            kind = 'execution_timeout' if time.monotonic() >= request_deadline or isinstance(exc, TimeoutError) else 'transient_dependency_error'
            raise DiagnosticError(kind, 'HTTP connection failed or exceeded its request deadline.') from exc
        finally:
            stopped.set()
            conn.close()


def technologies(result):
    headers = result['headers']
    text = result['body'][:100000].decode('utf-8', 'replace')
    values = []
    for key in ('server', 'x-powered-by'):
        if headers.get(key):
            values.append(headers[key][:100])
    for name, marker in [('Angular', 'ng-version='), ('React', '__next'), ('WordPress', 'wp-content/'), ('ASP.NET', '__VIEWSTATE'), ('Swagger/OpenAPI UI', 'swagger-ui')]:
        if marker.lower() in text.lower():
            values.append(name)
    return sorted(set(values))[:15]


def extract_links(result):
    """Literal leads only: do not evaluate JavaScript or submit forms."""
    links = []
    content_type = result['headers'].get('content-type', '').lower()
    text = result['body'].decode('utf-8', 'replace')
    if 300 <= result['status'] < 400:
        links.append((result['headers'].get('location', ''), 'http_redirect'))
    elif result['status'] < 400 and ('html' in content_type or (text.lstrip().startswith('<') and 'xml' not in content_type and not urllib.parse.urlsplit(result['url']).path.lower().endswith('.xml'))):
        parser = Links()
        parser.feed(text)
        links += [(link, 'html_link') for link in parser.links]
        links += [(link, 'html_script') for link in parser.scripts]
        links += [(link, 'javascript_literal') for link in static_js_paths(text)]
        if 'swaggeruibundle' in text.lower() or 'swagger-ui' in text.lower():
            # Swagger UI commonly embeds the spec URL in a literal `url:`
            # property. Do not evaluate JavaScript or accept a new origin.
            for match in re.finditer(r'\burl\s*:\s*["\']([^"\']{1,500}\.json)["\']', text, re.I):
                if OPENAPI_DOCUMENT_PATH.search(urllib.parse.urlsplit(match[1]).path):
                    links.append((match[1], 'openapi_document_link'))
    elif result['status'] < 400 and ('javascript' in content_type or urllib.parse.urlsplit(result['url']).path.lower().endswith(('.js', '.mjs'))):
        links += [(link, 'javascript_literal') for link in static_js_paths(text)]
    elif result['status'] < 400 and 'json' in content_type:
        links += [(m, 'json_link') for m in re.findall(r'"((?:https?://[^"\s]+|/[^"\s]*))"', text)[:100]]
    elif result['status'] < 400 and ('xml' in content_type or urllib.parse.urlsplit(result['url']).path.lower().endswith('.xml')):
        links += [(html.unescape(m.strip()), 'sitemap_entry') for m in re.findall(r'<loc\b[^>]*>([^<]+)</loc>', text, re.I)[:200]]
    elif result['status'] < 400 and urllib.parse.urlsplit(result['url']).path.lower().endswith('/robots.txt'):
        links += [(m.strip(), 'robots_hint') for m in re.findall(r'(?im)^\s*(?:sitemap|disallow)\s*:\s*(\S+)', text)[:100] if m.strip() not in ('/', '*')]
    return links[:500]


def auto_probe_openapi_get(operation):
    """Conservative GET selection; GET alone does not imply no side effects."""
    return (operation.get('method') == 'GET' and bool(operation.get('url')) and
            not STATE_CHANGING_LEAD.search(urllib.parse.urlsplit(operation['url']).path) and
            not STATE_CHANGING_LEAD.search(operation.get('operation_id', '')) and
            not STATE_CHANGING_LEAD.search(operation.get('summary', '')))


def openapi_operations(result, scope, evidence_ref):
    """Inventory a bounded JSON OpenAPI document; never execute its operations.

    An API description is a lead, not proof that an endpoint exists or that its
    declared security controls are effective. Server URLs must fit the frozen
    scope; unresolved path parameters have no executable URL.
    """
    if result['status'] != 200 or result.get('truncated') or len(result['body']) > MAX_BODY:
        return [], False, False
    content_type = result['headers'].get('content-type', '').lower()
    if 'json' not in content_type and not result['url'].lower().endswith('.json'):
        return [], False, False
    try:
        document = json.loads(result['body'].decode('utf-8-sig'))
    except (ValueError, UnicodeError, RecursionError):
        return [], False, False
    if not isinstance(document, dict) or not isinstance(document.get('paths'), dict):
        return [], False, False
    if not (isinstance(document.get('openapi'), str) and document['openapi'].startswith('3.') or
            isinstance(document.get('swagger'), str) and document['swagger'].startswith('2.')):
        return [], False, False
    base_urls = []
    if 'openapi' in document:
        servers = document.get('servers', [{'url': '/'}])
        if not isinstance(servers, list):
            return [], False, True
        for server in servers[:8]:
            value = server.get('url') if isinstance(server, dict) else None
            if not isinstance(value, str) or not value or '{' in value or '}' in value:
                continue
            base_urls.append(urllib.parse.urljoin(result['url'], value))
    else:
        host, base_path = document.get('host'), document.get('basePath', '/')
        if host is not None and (not isinstance(host, str) or '/' in host or '@' in host or '{' in host):
            return [], False, True
        if not isinstance(base_path, str) or not base_path.startswith('/'):
            return [], False, True
        schemes = document.get('schemes', [])
        if host:
            if not isinstance(schemes, list):
                return [], False, True
            for scheme in schemes or [urllib.parse.urlsplit(result['url']).scheme]:
                if scheme in ('http', 'https'):
                    base_urls.append(f'{scheme}://{host}{base_path}')
        else:
            base_urls.append(scope.origin + base_path)
    scoped_bases = []
    source_origin = origin(result['url'])
    for base in base_urls:
        try:
            parsed = urllib.parse.urlsplit(base)
            server_origin = origin(base)
            if parsed.query or parsed.fragment:
                continue
            safe_path(parsed.path or '/')
            # Public OpenAPI documents often advertise their production host.
            # Treat that host as untrusted metadata and remap only its path to
            # the already authorized origin that served this document.
            scoped_bases.append((source_origin + (parsed.path or '/'),
                                 server_origin != source_origin))
        except (DiagnosticError, ValueError):
            continue
    if not scoped_bases:
        return [], False, True
    operations, seen = [], set()
    methods = ('get', 'head', 'post', 'put', 'patch', 'delete', 'options', 'trace')
    truncated = False
    for raw_path, path_item in document['paths'].items():
        if not isinstance(raw_path, str) or not isinstance(path_item, dict) or not raw_path.startswith('/'):
            continue
        # Template variables remain a display-only path; static endpoints are
        # validated with the same traversal and URL-prefix checks as discovery.
        templated = bool(re.search(r'\{[A-Za-z_][A-Za-z0-9_.-]{0,79}\}', raw_path))
        check_path = re.sub(r'\{[A-Za-z_][A-Za-z0-9_.-]{0,79}\}', 'aegis-placeholder', raw_path)
        try:
            safe_path(check_path)
        except ValueError:
            continue
        for base, server_origin_mismatch in scoped_bases:
            joined = base.rstrip('/') + raw_path
            try:
                validated, _ = scope.normalize(base.rstrip('/') + check_path)
            except DiagnosticError:
                continue
            for method in methods:
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue
                url = '' if templated else validated
                key = (method, joined)
                if key in seen:
                    continue
                seen.add(key)
                if len(operations) >= MAX_API_OPERATIONS:
                    truncated = True
                    break
                summary = operation.get('summary') or operation.get('operationId') or ''
                summary = re.sub(r'\s+', ' ', redact(summary)).strip()[:160] if isinstance(summary, str) else ''
                operation_id = operation.get('operationId', '')
                operation_id = operation_id if isinstance(operation_id, str) else ''
                row = {'method': method.upper(), 'path': raw_path,
                       'url': url, 'summary': summary,
                       'source_url': result['url'], 'evidence_ref': evidence_ref,
                       'server_origin_mismatch': server_origin_mismatch,
                       'verification': 'documented_unverified'}
                row['auto_probe_eligible'] = auto_probe_openapi_get({**row, 'operation_id': operation_id})
                operations.append(row)
            if truncated:
                break
        if truncated:
            break
    return operations, truncated, True


def build_attack_paths(run):
    """Rank evidence-backed leads; an observed path is never a proven compromise."""
    observations = {row['url']: row for row in run.get('observations', [])}
    outgoing = collections.defaultdict(list)
    for edge in run.get('surface_edges', []):
        outgoing[edge['from']].append(edge)
    candidates = collections.defaultdict(list)
    for row in run.get('candidates', []):
        candidates[row.get('url')].append(row)
    roots = set(run.get('scope_urls') or [run['target_url']]) | {run['target_url']}
    goal = str(run.get('goal', '')).lower()
    wants_documents = bool(re.search(r'문서|파일|자료|노출|다운로드|document|file|expos|download', goal))
    wants_admin = bool(re.search(r'관리자|인증|권한|로그인|admin|auth|privileg|login', goal))
    wants_api = bool(re.search(r'api|인터페이스|엔드포인트|swagger|openapi', goal))
    # Breadth-first provenance avoids choosing a later circular or unrelated
    # inbound link as the apparent parent of a discovered URL.
    path_edges = {root: [] for root in roots if root in observations}
    pending = collections.deque(path_edges)
    while pending:
        parent = pending.popleft()
        if len(path_edges[parent]) >= 5:
            continue
        for edge in outgoing.get(parent, []):
            child = edge['to']
            if child in observations and child not in path_edges:
                path_edges[child] = path_edges[parent] + [edge]
                pending.append(child)
    scored = []
    for url, row in observations.items():
        if row.get('confidence') != 'observed' or url in roots:
            continue
        path = urllib.parse.urlsplit(url).path.lower()
        if (path in ('/robots.txt', '/sitemap.xml', '/.well-known/security.txt') or
                path.endswith(('.js', '.mjs', '.css', '.map', '.png', '.jpg', '.svg', '.ico')) or
                path.endswith(('/oauth2-redirect.html', '/openapi.json', '/swagger.json')) or
                path.rstrip('/') in ('/docs', '/api/docs', '/swagger')) and not candidates.get(url):
            continue
        if 'same_as_scope_root' in row.get('sources', []) and not candidates.get(url):
            continue
        status = row.get('status_code')
        if not isinstance(status, int) or status >= 500 or status == 404:
            continue
        matched = candidates.get(url, [])
        if not matched and status not in (200, 201, 202, 204, 301, 302, 307, 308, 401, 403):
            continue
        lineage = path_edges.get(url, [])
        chain_urls = [lineage[0]['from']] + [edge['to'] for edge in lineage] if lineage else [url]
        chain = []
        for index, step_url in enumerate(chain_urls):
            item = observations[step_url]
            chain.append({'url': step_url, 'status_code': item.get('status_code'),
                          'confidence': item.get('confidence'), 'evidence_ref': item.get('evidence_ref'),
                          'relation': lineage[index - 1]['relation'] if index else 'seed'})
        refs = list(dict.fromkeys([step['evidence_ref'] for step in chain if step.get('evidence_ref')] +
                                  [ref for candidate in matched for ref in candidate.get('evidence_refs', [])]))[:20]
        sensitive_lead = bool(re.search(r'/(?:ftp|files?|uploads?|backup|admin|debug|internal)(?:/|$)', path))
        document_lead = wants_documents and bool(re.search(r'\.(?:md|txt|pdf|docx?|xlsx?|json|csv|kdbx)$|/(?:ftp|files?|uploads?|backup)/?$', path))
        admin_lead = wants_admin and bool(re.search(r'/(?:admin|auth|login|users?|roles?|permissions?)(?:/|$)', path))
        api_lead = wants_api and bool(re.search(r'/(?:api|swagger|openapi|graphql)(?:/|$|\.)', path))
        priority = (100 if matched else 0) + (20 if status == 200 else 5) + (15 if sensitive_lead else 0) + (30 if document_lead or admin_lead or api_lead else 0) + max(0, 6 - len(chain))
        priority_basis = (['도구 후보'] if matched else []) + (['입력한 목표와 관련된 경로'] if document_lead or admin_lead or api_lead else []) + (['HTTP 응답 관측'] if status else [])
        scored.append((priority, url, {'id': hashlib.sha256(url.encode()).hexdigest()[:16],
            'goal': run.get('goal', ''), 'target_url': url, 'status': 'verification_required',
            'steps': chain, 'candidate_ids': [candidate['id'] for candidate in matched],
            'evidence_refs': refs, 'priority_basis': priority_basis,
            'assessment': '도구 후보가 관측됐으나 취약점·목표 달성은 ARTEX 검증 전입니다.' if matched else
                          'HTTP 접근이 관측됐습니다. 보안 영향과 목표 달성은 확인되지 않았습니다.',
            'next_action': 'ARTEX에서 영향·대조군을 검증하세요.' if matched else '이 경로의 보안 의미와 접근통제를 확인하세요.'}))
    scored.sort(key=lambda item: (-item[0], item[1]))
    selected, canonical_urls = [], set()
    for _, url, path in scored:
        canonical = url.rstrip('/')
        if canonical in canonical_urls:
            continue
        canonical_urls.add(canonical)
        selected.append(path)
        if len(selected) == 8:
            break
    return selected


class Runner:
    def __init__(self, data_dir=None, token=None, fetcher=None, binaries=None):
        self.root = Path(data_dir or os.getenv('OFFENSIVE_DIAGNOSTICS_DIR', '/data/offensive/diagnostics'))
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if token is None:
            token_file = os.getenv('ARTEX_OFFENSIVE_TOKEN_FILE', '')
            token = Path(token_file).read_text().strip() if token_file else ''
        if len(token) < 24:
            raise ValueError('ARTEX_OFFENSIVE_TOKEN_FILE must contain a token of at least 24 characters.')
        self.token, self.fetcher = token, fetcher
        self.lock, self.active = threading.RLock(), {}
        self.tools = {}
        for name in ('httpx', 'katana', 'nuclei'):
            path = binaries.get(name) if binaries is not None else shutil.which(name)
            version = ''
            if path:
                try:
                    with tempfile.TemporaryDirectory(prefix='aegis-tool-version-') as version_home:
                        result = subprocess.run([path, '-version'], capture_output=True, timeout=3, env=self.tool_env(version_home), cwd=version_home, text=True)
                    raw_version = re.sub(r'\x1b\[[0-9;]*m', '', (result.stdout + result.stderr)).strip()
                    match = re.search(r'(?i)(?:current version|version)[: ]+v?([0-9][0-9A-Za-z.+-]+)', raw_version)
                    version = match[1] if match else raw_version[:240]
                    if result.returncode != 0:
                        path = None
                except (OSError, subprocess.TimeoutExpired):
                    path = None
            self.tools[name] = {'path': path, 'version': version}
        self.recover()

    @staticmethod
    def tool_env(home=None):
        # No service/API credentials or inherited proxies reach CLI subprocesses.
        result = {'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'), 'LANG': 'C.UTF-8', 'NO_COLOR': '1', 'DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD': 'true'}
        if home:
            result['HOME'] = str(home)
            result['XDG_CONFIG_HOME'] = str(Path(home) / '.config')
        return result

    def recover(self):
        for directory in self.root.iterdir():
            if not directory.is_dir() or not UUID_RE.fullmatch(directory.name):
                continue
            try:
                run = self._load(directory.name)
                changed = False
                if run.get('status') in ACTIVE:
                    run['status'], run['finished_at'] = 'interrupted', now()
                    run['error'] = 'Runner restarted. Prior tool completion is unknown; no command was replayed.'
                    for execution in run['executions']:
                        if execution['status'] in ACTIVE:
                            execution.update(status='interrupted', finished_at=now(), error_kind='unknown_execution_state', error='Runner restarted; execution was not replayed.')
                    if run['followup']['status'] == 'pending':
                        run['followup'] = {'status': 'available', 'error': 'Discovery was interrupted; review partial evidence before starting a new run.'}
                    changed = True
                if run.get('surface_edges') and run.get('path_model_version') != PATH_MODEL_VERSION:
                    run['attack_paths'] = build_attack_paths(run)
                    run['path_model_version'] = PATH_MODEL_VERSION
                    changed = True
                if changed:
                    self._save(run)
            except (ValueError, OSError, LookupError):
                continue

    def catalog(self):
        rows = []
        for tool, binary, label in [('http_probe', 'httpx', 'HTTP 서비스·기술 탐색'), ('surface_map', None, '공격 표면·기본 경로 탐색'), ('crawl', 'katana', '경로·JavaScript 탐색'), ('nuclei', 'nuclei', 'Nuclei 근거 후보 검사')]:
            if tool == 'surface_map':
                rows.append({'id': tool, 'label': label, 'available': True, 'version': 'stdlib-v1', 'backend': 'native_http', 'detail': '등록한 범위의 시작점·일반 웹 경로·발견 링크만 GET으로 확인하고 연결 근거를 저장합니다.'})
                continue
            installed = self.tools[binary]['path'] is not None
            rows.append({'id': tool, 'label': label, 'available': installed or tool != 'nuclei', 'version': self.tools[binary]['version'] if installed else 'stdlib-v1', 'backend': binary if installed else ('native_http' if tool != 'nuclei' else 'unavailable'), 'detail': ('HTTP targets use the installed CLI through the origin/path enforcing broker; HTTPS probe/crawl use native TLS transport.' if installed else 'Bounded native HTTP GET/static discovery; no external scanner is being simulated.') if tool != 'nuclei' else 'Three local read-only HTTP templates (directory listing, debug trace, reflected credentialed CORS). Candidate matches require ARTEX verification. HTTPS CLI scanning is unavailable.'})
        return {'tools': rows, 'provenance': PROVENANCE}

    def _path(self, run_id):
        if not isinstance(run_id, str) or not UUID_RE.fullmatch(run_id):
            raise LookupError('Run not found.')
        path = self.root / run_id
        if path.is_symlink():
            raise LookupError('Run not found.')
        return path

    def _load(self, run_id):
        try:
            path = self._path(run_id) / 'run.json'
            if path.is_symlink() or path.stat().st_size > MAX_ARTIFACT:
                raise LookupError('Invalid run data.')
            return json.loads(path.read_text())
        except FileNotFoundError as exc:
            raise LookupError('Run not found.') from exc

    def _save(self, run):
        directory = self._path(run['id'])
        directory.mkdir(mode=0o700, exist_ok=True)
        temp = directory / ('run.' + uuid.uuid4().hex + '.tmp')
        try:
            with temp.open('x', encoding='utf-8') as handle:
                os.chmod(temp, 0o600)
                json.dump(run, handle, ensure_ascii=False, separators=(',', ':'))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, directory / 'run.json')
        finally:
            temp.unlink(missing_ok=True)

    def get(self, run_id):
        with self.lock:
            return self._load(run_id)

    @staticmethod
    def _list_summary(run):
        """History/monitor responses never carry collected evidence payloads.

        Detailed records remain untouched and are fetched separately by run ID.
        Counts preserve useful history metadata without replicating large arrays.
        """
        keys = ('id', 'name', 'target_url', 'scope_urls', 'status', 'created_at', 'started_at',
                'finished_at', 'tools', 'timeout_seconds', 'max_urls',
                'auto_followup', 'llm_profile_ids', 'followup', 'auth_context')
        result = {key: run[key] for key in keys if key in run}
        result.update(is_summary=True, goal='', summary=str(run.get('summary', ''))[:500],
                      warnings=[], observations=[], candidates=[], artifacts=[], surface_edges=[], attack_paths=[], api_operations=[],
                      coverage=run.get('coverage', {}),
                      counts={key: len(run.get(key, [])) for key in
                              ('observations', 'candidates', 'artifacts', 'executions', 'attack_paths', 'api_operations')})
        if run.get('error'):
            result['error'] = str(run['error'])[:500]
        execution_keys = ('id', 'tool', 'label', 'backend', 'version', 'status',
                          'started_at', 'finished_at', 'elapsed_ms', 'exit_code', 'error_kind')
        result['executions'] = [
            {**{key: execution[key] for key in execution_keys if key in execution},
             'artifact_names': []}
            for execution in run.get('executions', [])
        ]
        return result

    def list(self):
        summaries = []
        with self.lock:
            for directory in self.root.iterdir():
                if UUID_RE.fullmatch(directory.name):
                    with contextlib.suppress(ValueError, OSError, LookupError):
                        summaries.append(self._list_summary(self._load(directory.name)))
        summaries.sort(key=lambda row: row.get('created_at', ''), reverse=True)
        # Completed history is bounded, but a run awaiting monitor reconciliation
        # must not disappear merely because newer completed runs were created.
        return [run for index, run in enumerate(summaries)
                if index < MAX_RUNS or run.get('status') in ACTIVE or
                run.get('followup', {}).get('status') in ('pending', 'launching', 'running')]

    def create(self, body):
        if not isinstance(body, dict):
            raise ValueError('JSON object required.')
        allowed = {'name', 'target_url', 'scope_urls', 'goal', 'tools', 'timeout_seconds', 'max_urls', 'bearer_token', 'auto_followup', 'llm_profile_ids'}
        if set(body) - allowed:
            raise ValueError('Unsupported diagnostic input fields.')
        scope = ScopeSet(body.get('target_url'), body.get('scope_urls'))
        selected = body.get('tools', ['http_probe', 'surface_map', 'crawl'])
        if not isinstance(selected, list) or not selected or any(tool not in TOOLS for tool in selected) or len(set(selected)) != len(selected):
            raise ValueError('Select one or more supported tools without duplicates.')
        timeout, max_urls = body.get('timeout_seconds', 300), body.get('max_urls', 50)
        if type(timeout) is not int or not 60 <= timeout <= 900 or type(max_urls) is not int or not 1 <= max_urls <= 100:
            raise ValueError('Timeout must be 60–900 seconds and max_urls must be 1–100.')
        name, goal = body.get('name', '자율 진단'), body.get('goal', '')
        token = body.get('bearer_token', '')
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100 or not isinstance(goal, str) or not 1 <= len(goal.strip()) <= 4000:
            raise ValueError('Run name or goal is invalid.')
        if not isinstance(token, str) or len(token) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError('Bearer token must be an ASCII token without whitespace.')
        auto = body.get('auto_followup', False)
        profiles = body.get('llm_profile_ids', [])
        if type(auto) is not bool or not isinstance(profiles, list) or len(profiles) > 8 or any(type(p) is not int or p <= 0 for p in profiles):
            raise ValueError('Follow-up model configuration is invalid.')
        run_id = str(uuid.uuid4())
        run = {'id': run_id, 'name': redact(name.strip(), (token,)), 'target_url': scope.target, 'scope_urls': scope.scope_urls, 'goal': redact(goal.strip(), (token,)), 'status': 'queued', 'created_at': now(), 'tools': [t for t in TOOLS if t in selected], 'timeout_seconds': timeout, 'max_urls': max_urls, 'auto_followup': auto, 'llm_profile_ids': list(dict.fromkeys(profiles)), 'executions': [{'id': str(uuid.uuid4()), 'tool': tool, 'status': 'queued', 'artifact_names': []} for tool in TOOLS if tool in selected], 'observations': [], 'candidates': [], 'surface_edges': [], 'attack_paths': [], 'api_operations': [], 'path_model_version': PATH_MODEL_VERSION, 'artifacts': [], 'warnings': ['Discovery uses GET requests only. Query values and credentials are not persisted; parameter names from links are observations, not tested input contracts.'], 'summary': 'Waiting to start discovery.', 'followup': {'status': 'pending' if auto else 'available'}, 'auth_context': 'provided_bearer' if token else 'anonymous', 'provenance': PROVENANCE,
               'coverage': {'observed_get_urls': 0, 'inferred_urls': 0, 'http_requests': 0, 'max_http_requests': max_urls * 6 + 12, 'distinct_urls_requested': 0, 'max_distinct_urls': max_urls, 'documented_operations': 0, 'observed_documented_get_operations': 0, 'unverified_documented_operations': 0, 'scanner_candidates': 0, 'limits': [], 'exhaustive': False}}
        with self.lock:
            if len(self.active) >= 2:
                raise RuntimeError('Two diagnostic runs are already active; wait or cancel one.')
            cancel = threading.Event()
            self.active[run_id] = {'cancel': cancel, 'process': None}
            self._save(run)
            thread = threading.Thread(target=self._work, args=(run_id, scope, token, cancel), daemon=True)
            self.active[run_id]['thread'] = thread
            thread.start()
        return run

    def _mutate(self, run_id, fn):
        with self.lock:
            run = self._load(run_id)
            fn(run)
            self._save(run)
            return run

    def _execution(self, run_id, tool, **fields):
        def change(run):
            execution = next(e for e in run['executions'] if e['tool'] == tool)
            if execution['status'] == 'cancelled' and fields.get('status') in ('running', 'completed'):
                return
            execution.update(fields)
        self._mutate(run_id, change)

    def _warning(self, run_id, message):
        def change(run):
            if message not in run['warnings'] and len(run['warnings']) < 40:
                run['warnings'].append(message)
        self._mutate(run_id, change)

    def _artifact(self, run_id, name, value, secrets=()):
        if not ARTIFACT_RE.fullmatch(name):
            raise ValueError('Invalid artifact name.')
        clean = redact(value, secrets)
        data = json.dumps(clean, ensure_ascii=False, indent=2).encode()
        if len(data) > MAX_ARTIFACT:
            raise DiagnosticError('budget_exhausted', 'Artifact output exceeded 4 MiB.')
        directory = self._path(run_id)
        with self.lock:
            path = directory / name
            # All callers use unique evidence names; a symlink can never redirect a write.
            with path.open('xb') as handle:
                os.chmod(path, 0o600)
                handle.write(data)
            artifact = {'name': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'content_type': 'application/json'}
            self._mutate(run_id, lambda run: run['artifacts'].append(artifact))
        return name

    def artifact(self, run_id, name):
        if not ARTIFACT_RE.fullmatch(name):
            raise LookupError('Artifact not found.')
        with self.lock:
            run = self._load(run_id)
            metadata = next((a for a in run['artifacts'] if a['name'] == name), None)
            path = self._path(run_id) / name
            if not metadata or path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT:
                raise LookupError('Artifact not found.')
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != metadata['sha256']:
                raise RuntimeError('Artifact integrity check failed.')
            return data

    def _observe(self, run_id, ctx, url, source, evidence, confidence='inferred', status=None, tech=(), parameters=(), kind='endpoint', parent_url=None, relation=None):
        try:
            clean, names = ctx.scope.normalize(url)
        except DiagnosticError:
            return
        parent = None
        if parent_url:
            try:
                parent, _ = ctx.scope.normalize(parent_url)
            except DiagnosticError:
                return
        names = sorted(set(names) | {n for n in parameters if isinstance(n, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,79}', n) and not SECRET_KEY.search(n)})[:50]
        def change(run):
            existing = next((o for o in run['observations'] if o['url'] == clean and o['method'] == 'GET'), None)
            if existing:
                existing['parameters'] = sorted(set(existing['parameters']) | set(names))[:50]
                existing['sources'] = sorted(set(existing['sources']) | {source})
                existing['technologies'] = sorted(set(existing['technologies']) | set(tech))[:20]
                if confidence == 'observed':
                    existing.update(confidence=confidence, evidence_ref=evidence)
                    if status is not None:
                        existing['status_code'] = status
                if kind == 'service':
                    existing['kind'] = 'service'
            elif len(run['observations']) < run['max_urls'] * 3:
                observation = {'id': str(uuid.uuid4()), 'kind': kind, 'url': clean, 'method': 'GET', 'parameters': names, 'technologies': list(tech), 'sources': [source], 'confidence': confidence, 'evidence_ref': evidence, 'auth_context': run['auth_context']}
                if status is not None:
                    observation['status_code'] = status
                run['observations'].append(observation)
            if parent and parent != clean and not any(edge['from'] == parent and edge['to'] == clean for edge in run.get('surface_edges', [])) and len(run['surface_edges']) < run['max_urls'] * 5:
                run['surface_edges'].append({'from': parent, 'to': clean, 'relation': relation or source, 'evidence_ref': evidence})
        self._mutate(run_id, change)

    def _record_openapi(self, run_id, ctx, result, evidence_ref):
        operations, truncated, recognized = openapi_operations(result, ctx.scope, evidence_ref)
        if not recognized:
            return None
        def add(run):
            existing = {(row['method'], row['url'] or row['path']) for row in run.get('api_operations', [])}
            for row in operations:
                key = (row['method'], row['url'] or row['path'])
                if key in existing:
                    continue
                if len(run['api_operations']) >= MAX_API_OPERATIONS:
                    run['api_inventory_truncated'] = True
                    break
                run['api_operations'].append(row)
                existing.add(key)
            if truncated:
                run['api_inventory_truncated'] = True
        if operations or truncated:
            self._mutate(run_id, add)
            # Polling clients should see the inventory count as soon as the
            # document is parsed, rather than only when this tool stage ends.
            self._refresh_coverage(run_id, ctx)
        if truncated or self.get(run_id).get('api_inventory_truncated'):
            self._warning(run_id, 'OpenAPI operation inventory reached its 300-entry limit; remaining documented operations were not recorded.')
        if any(row['server_origin_mismatch'] for row in operations):
            self._warning(run_id, 'OpenAPI advertises a different server origin. Its path was mapped to the explicitly configured target; no request to the advertised origin was made.')
        return operations

    def _refresh_coverage(self, run_id, ctx):
        def refresh(run):
            observed = {row['url'] for row in run['observations']
                        if row.get('confidence') == 'observed' and row.get('method') == 'GET'}
            for operation in run.get('api_operations', []):
                operation['verification'] = ('observed_get' if operation['method'] == 'GET' and
                                             operation['url'] and operation['url'] in observed else
                                             'documented_unverified')
            limits = []
            if len(ctx.seen) >= ctx.max_urls or any(e.get('error_kind') in ('url_limit', 'collection_limit') for e in run['executions']):
                limits.append('url_budget_reached')
            if ctx.requests >= ctx.max_requests:
                limits.append('request_budget_reached')
            if ctx.bytes >= MAX_TOTAL:
                limits.append('response_budget_reached')
            if run.get('api_inventory_truncated'):
                limits.append('operation_inventory_limit_reached')
            if any(e.get('error_kind') == 'execution_timeout' for e in run['executions']):
                limits.append('time_budget_reached')
            if any(e.get('status') in ('failed', 'timed_out', 'unavailable', 'cancelled', 'interrupted') for e in run['executions']):
                limits.append('tool_incomplete')
            documented = run.get('api_operations', [])
            observed_documented = sum(row['verification'] == 'observed_get' for row in documented)
            run['coverage'] = {'observed_get_urls': len(observed),
                               'inferred_urls': sum(row.get('confidence') == 'inferred' for row in run['observations']),
                               'http_requests': ctx.requests, 'max_http_requests': ctx.max_requests,
                               'distinct_urls_requested': len(ctx.seen), 'max_distinct_urls': ctx.max_urls,
                               'documented_operations': len(documented),
                               'observed_documented_get_operations': observed_documented,
                               'unverified_documented_operations': len(documented) - observed_documented,
                               'scanner_candidates': len(run['candidates']), 'limits': limits,
                               'exhaustive': False}
        self._mutate(run_id, refresh)

    def _replan(self, run_id, ctx):
        self._mutate(run_id, lambda run: run.update(attack_paths=build_attack_paths(run)))
        self._refresh_coverage(run_id, ctx)

    def _fetch(self, ctx, url, headers=None):
        ctx.check()
        return self.fetcher(ctx, url, headers) if self.fetcher else ctx.fetch(url, headers)

    def _response_evidence(self, run_id, ctx, result, source):
        body = result['body'].decode('utf-8', 'replace')
        try:
            preview = json.loads(body) if len(body) < 20000 else body[:12000]
        except (ValueError, RecursionError):
            preview = body[:12000]
        headers = {key: value[:500] for key, value in result['headers'].items() if key in ('content-type', 'server', 'x-powered-by', 'location', 'content-length', 'access-control-allow-origin', 'access-control-allow-credentials')}
        evidence = self._artifact(run_id, source + '-' + uuid.uuid4().hex[:12] + '.json', {'source': source, 'url': result['url'], 'method': 'GET', 'status_code': result['status'], 'headers': headers, 'body_preview': preview, 'body_sha256': hashlib.sha256(result['body']).hexdigest(), 'body_bytes': len(result['body']), 'truncated': result.get('truncated', False) or len(body) > 12000, 'redacted': True, 'observed_at': now()}, (ctx.token,))
        if result['status'] in (401, 403):
            self._warning(run_id, 'One or more paths require authorization or were denied; this is not evidence of absence of vulnerabilities.')
        if result.get('truncated'):
            self._warning(run_id, 'A response exceeded the bounded body size; its discovery/evidence may be incomplete.')
        return evidence

    def _native(self, run_id, tool, ctx):
        pending, visited, artifacts = collections.deque((seed, 0, None, None) for seed in ctx.scope.seeds), set(), []
        seed_bodies = {}
        if tool == 'surface_map':
            for entry in ctx.scope.entries:
                for path in COMMON_SURFACE_PATHS:
                    lead = urllib.parse.urljoin(entry.origin + (entry.prefix + '/' if entry.prefix else '/'), path)
                    try:
                        lead, _ = ctx.scope.normalize(lead)
                    except DiagnosticError:
                        continue
                    pending.append((lead, 1, entry.target, 'common_path'))
        if tool == 'crawl':
            # Prior HTTP probe observations seed the next stage, not a second independent scan.
            previous = self.get(run_id)
            mapped = any(e['tool'] == 'surface_map' and e['status'] == 'completed'
                         for e in previous['executions'])
            # Surface mapping has already fetched and parsed its observed
            # responses. Spend this stage on still-inferred leads instead of
            # repeating those GETs, while retaining the root seed for a run
            # that omitted or failed surface mapping.
            rows = [row for row in previous['observations']
                    if not mapped or row['confidence'] == 'inferred']
            for row in rows:
                pending.append((row['url'], 0, None, None))
            for row in reversed([row for row in previous.get('api_operations', [])
                                 if row.get('auto_probe_eligible') and row['verification'] != 'observed_get'][:ctx.max_urls]):
                pending.appendleft((row['url'], 0, row['source_url'], 'openapi_get'))
        errors = []
        stage_limit = min(ctx.max_urls, max(12, int(ctx.max_urls * 0.5))) if tool == 'surface_map' else ctx.max_urls
        while pending and len(visited) < stage_limit:
            ctx.check()
            url, depth, parent, relation = pending.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                result = self._fetch(ctx, url)
                is_fallback = bool(tool == 'surface_map' and relation == 'common_path' and parent in seed_bodies and
                                   result['status'] == 200 and result['body'] == seed_bodies[parent])
                evidence = self._response_evidence(run_id, ctx, result, 'native-' + tool)
                artifacts.append(evidence)
                self._observe(run_id, ctx, url, 'same_as_scope_root' if is_fallback else 'native_http_response', evidence, 'observed', result['status'], technologies(result), kind='service' if tool == 'http_probe' else 'endpoint', parent_url=parent, relation=relation)
                documented = self._record_openapi(run_id, ctx, result, evidence)
                if tool == 'surface_map' and url in ctx.scope.seeds:
                    seed_bodies[url] = result['body']
                if tool == 'http_probe':
                    continue
                if result['status'] >= 400 or is_fallback:
                    continue
                # Generic JSON path extraction cannot distinguish GET from POST.
                # A recognized OpenAPI document is handled by method-aware
                # inventory; only static GET paths are eligible for probing.
                links = [] if documented is not None else extract_links(result)
                if tool == 'surface_map' and relation == 'common_path':
                    links.reverse()
                priority_documents = []
                for link, source in links[:500]:
                    try:
                        resolved, params = ctx.scope.normalize(link, url)
                    except DiagnosticError:
                        continue
                    self._observe(run_id, ctx, resolved, source, evidence, parameters=params, parent_url=url, relation=source)
                    if depth < 3 and resolved not in visited:
                        if OPENAPI_DOCUMENT_PATH.search(urllib.parse.urlsplit(resolved).path):
                            priority_documents.append((resolved, depth + 1, url, 'openapi_document_link'))
                        elif tool == 'surface_map' and relation == 'common_path':
                            pending.appendleft((resolved, depth + 1, url, source))
                        else:
                            pending.append((resolved, depth + 1, url, source))
                for lead in reversed(priority_documents):
                    pending.appendleft(lead)
                if documented is not None and depth < 3:
                    eligible = [row['url'] for row in documented if row.get('auto_probe_eligible')]
                    # Reserve most of the run for independent discovery. The
                    # selected read-only leads are still subject to transport
                    # scope, request-rate and distinct-URL budgets.
                    for lead in reversed(eligible[:min(24, max(1, ctx.max_urls // 3))]):
                        if lead not in visited:
                            pending.appendleft((lead, depth + 1, url, 'openapi_get'))
            except DiagnosticError as exc:
                if exc.kind in ('cancelled', 'budget_exhausted') or time.monotonic() >= ctx.deadline:
                    raise
                errors.append(exc.kind)
                self._warning(run_id, f'{tool}: {exc.kind}; one or more paths could not be inspected.')
        if not artifacts:
            raise DiagnosticError(errors[0] if errors else 'parse_error', 'No HTTP response evidence was obtained.')
        if errors:
            raise DiagnosticError('partial_collection', 'Some discovery requests failed; successful observations were retained.')
        if pending:
            self._warning(run_id, 'Discovery reached the URL or depth limit; unexplored links remain inferred candidates.')
        return artifacts

    def cancel(self, run_id):
        with self.lock:
            run = self._load(run_id)
            active = self.active.get(run_id)
            if active:
                active['cancel'].set()
                process = active.get('process')
                if process:
                    self._kill(process)
            if run['status'] in ACTIVE:
                run.update(status='cancelled', finished_at=now(), summary='Cancelled. Partial evidence is retained.')
                for execution in run['executions']:
                    if execution['status'] in ACTIVE:
                        execution.update(status='cancelled', finished_at=now(), error_kind='cancelled')
            if run['followup']['status'] in ('pending', 'available', 'launching'):
                run['followup'] = {'status': 'cancelled'}
            self._save(run)
            return run

    def bind(self, run_id, body):
        if not isinstance(body, dict) or set(body) - {'status', 'task_id', 'error'}:
            raise ValueError('Invalid follow-up binding.')
        statuses = {'available', 'launching', 'running', 'completed', 'failed', 'needs_model', 'cancelled'}
        status, task_id = body.get('status'), body.get('task_id')
        if status not in statuses or (task_id is not None and (not isinstance(task_id, str) or (task_id != '' and not re.fullmatch(r'[1-9][0-9]{0,18}', task_id)))):
            raise ValueError('Invalid follow-up status or task ID.')
        error = body.get('error', '')
        if not isinstance(error, str) or len(error) > 2000:
            raise ValueError('Invalid follow-up error.')
        with self.lock:
            run = self._load(run_id)
            previous = run['followup']
            if previous.get('task_id') and task_id and previous['task_id'] != task_id:
                raise RuntimeError('A different ARTEX task is already bound to this run.')
            if run['status'] not in ('completed', 'partial') and status not in ('cancelled', 'available', 'failed'):
                raise RuntimeError('Discovery must finish before an ARTEX follow-up can be attached.')
            run['followup'] = {'status': status}
            if task_id or previous.get('task_id'):
                run['followup']['task_id'] = task_id or previous['task_id']
            if error:
                run['followup']['error'] = redact(error)[:2000]
            self._save(run)
            return run

    @staticmethod
    def _kill(process):
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=2)

    def _work(self, run_id, scope, token, cancel):
        ctx = RequestContext(scope, token, time.monotonic() + self.get(run_id)['timeout_seconds'], cancel, self.get(run_id)['max_urls'])
        try:
            ctx.check()
            self._mutate(run_id, lambda run: run.update(status='running', started_at=now(), summary='Discovering scoped HTTP evidence.'))
            for tool in self.get(run_id)['tools']:
                ctx.check()
                started = time.monotonic()
                binary = {'http_probe': 'httpx', 'surface_map': None, 'crawl': 'katana', 'nuclei': 'nuclei'}[tool]
                cli = bool(binary and self.tools[binary]['path']) and scope.origin.startswith('http://') and (tool == 'nuclei' or len(scope.scope_urls) == 1)
                backend = binary if cli else ('native_http' if tool != 'nuclei' else 'unavailable')
                self._execution(run_id, tool, status='running', started_at=now(), backend=backend, version=self.tools[binary]['version'] if cli else 'stdlib-v1')
                before = {a['name'] for a in self.get(run_id)['artifacts']}
                try:
                    if tool == 'nuclei' and not cli:
                        raise DiagnosticError('tool_unavailable', 'Nuclei binary is unavailable, or the HTTPS target cannot use the scope-enforcing HTTP CLI broker. No scanner result was fabricated.')
                    if cli:
                        self._cli(run_id, tool, ctx)
                    else:
                        if binary and self.tools[binary]['path'] and scope.origin.startswith('https://'):
                            self._warning(run_id, 'HTTPS discovery uses the native TLS-verifying backend; external CLI HTTP proxy tunnelling is deliberately unavailable.')
                        self._native(run_id, tool, ctx)
                    ctx.check()
                    self._execution(run_id, tool, status='completed', summary='Tool completed. Matches are candidates, not confirmed vulnerabilities.')
                except DiagnosticError as exc:
                    status = {'cancelled': 'cancelled', 'execution_timeout': 'timed_out', 'tool_unavailable': 'unavailable'}.get(exc.kind, 'failed')
                    self._execution(run_id, tool, status=status, error_kind=exc.kind, error=redact(str(exc), (token,)))
                    if exc.kind in ('cancelled', 'budget_exhausted') or time.monotonic() >= ctx.deadline:
                        raise
                finally:
                    names = [a['name'] for a in self.get(run_id)['artifacts'] if a['name'] not in before]
                    self._execution(run_id, tool, finished_at=now(), elapsed_ms=int((time.monotonic()-started)*1000), artifact_names=names)
                    self._replan(run_id, ctx)
            def finish(run):
                if run['status'] == 'cancelled' or cancel.is_set():
                    return
                succeeded = any(e['status'] == 'completed' for e in run['executions']) or any(o['confidence'] == 'observed' for o in run['observations'])
                failed = any(e['status'] != 'completed' for e in run['executions'])
                status = 'partial' if succeeded and failed else ('failed' if failed else 'completed')
                run.update(status=status, finished_at=now(), summary=f'{len(run["observations"])} observations, {len(run["candidates"])} scanner candidates; {ctx.requests} bounded HTTP requests.')
                if status == 'failed' and run['followup']['status'] == 'pending':
                    run['followup'] = {'status': 'failed', 'error': 'No completed discovery evidence to investigate.'}
            self._mutate(run_id, finish)
        except DiagnosticError as exc:
            def failed(run):
                status = 'cancelled' if exc.kind == 'cancelled' else ('partial' if any(o['confidence'] == 'observed' for o in run['observations']) else 'failed')
                run.update(status=status, finished_at=now(), error=redact(str(exc), (token,)), summary='Execution stopped; existing observations and evidence are retained.')
                for execution in run['executions']:
                    if execution['status'] in ACTIVE:
                        execution.update(status='cancelled' if status == 'cancelled' else 'timed_out', finished_at=now(), error_kind=exc.kind, error=redact(str(exc), (token,)))
                if run['followup']['status'] == 'pending' and status not in ('partial',):
                    run['followup'] = {'status': 'cancelled' if status == 'cancelled' else 'failed', 'error': 'Discovery did not complete.'}
            self._mutate(run_id, failed)
        except Exception:
            def internal_failure(run):
                run.update(status='failed', finished_at=now(), error='Internal execution failure; inspect retained artifacts.', summary='Run failed. No success was inferred.')
                if run['followup']['status'] == 'pending':
                    run['followup'] = {'status': 'failed', 'error': 'Discovery did not complete.'}
            self._mutate(run_id, internal_failure)
            for execution in self.get(run_id)['executions']:
                if execution['status'] in ACTIVE:
                    self._execution(run_id, execution['tool'], status='failed', finished_at=now(), error_kind='internal_error', error='Internal execution failure.')
        finally:
            self._refresh_coverage(run_id, ctx)
            with self.lock:
                active = self.active.pop(run_id, None)
                if active and active.get('process'):
                    self._kill(active['process'])
            ctx.token = ''

    def _cli(self, run_id, tool, ctx):
        # Implemented below: all tool HTTP traffic passes through the same scoped,
        # pinned transport used by native discovery. No CONNECT / external redirects.
        return run_cli(self, run_id, tool, ctx)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'AegisLoopDiagnostics/1'
    def log_message(self, *args):
        pass

    def send_json(self, code, value):
        data = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def dispatch(self):
        runner = self.server.runner
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.query or parsed.fragment or urllib.parse.unquote(parsed.path) != parsed.path:
            raise ValueError('Invalid route.')
        parts = parsed.path.strip('/').split('/')
        if self.command == 'GET' and parts == ['health']:
            return self.send_json(200, {'status': 'ok', 'service': 'integrated-diagnostics'})
        if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + runner.token):
            return self.send_json(401, {'error': 'Authentication required.'})
        body = {}
        if self.command == 'POST':
            if self.headers.get('Transfer-Encoding'):
                raise ValueError('Chunked bodies are unsupported.')
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 <= length <= 32768:
                raise ValueError('Request exceeds 32 KiB.')
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('Incomplete request body.')
            body = json.loads(raw or b'{}')
        if parts == ['diagnostics', 'catalog'] and self.command == 'GET':
            return self.send_json(200, runner.catalog())
        if parts == ['diagnostics', 'runs']:
            if self.command == 'GET':
                return self.send_json(200, {'runs': runner.list()})
            if self.command == 'POST':
                return self.send_json(202, runner.create(body))
        if len(parts) >= 3 and parts[:2] == ['diagnostics', 'runs']:
            if len(parts) == 3 and self.command == 'GET':
                return self.send_json(200, runner.get(parts[2]))
            if len(parts) == 4 and self.command == 'POST':
                if parts[3] == 'cancel':
                    return self.send_json(200, runner.cancel(parts[2]))
                if parts[3] == 'followup':
                    return self.send_json(200, runner.bind(parts[2], body))
            if len(parts) == 5 and parts[3] == 'artifacts' and self.command == 'GET':
                data = runner.artifact(parts[2], parts[4])
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Content-Disposition', 'attachment; filename="' + parts[4] + '"')
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                return self.wfile.write(data)
        return self.send_json(404, {'error': 'Route not found.'})

    def handle_method(self):
        self.connection.settimeout(15)
        try:
            self.dispatch()
        except (ValueError, TypeError, json.JSONDecodeError, DiagnosticError) as exc:
            self.send_json(400, {'error': str(exc)[:300]})
        except LookupError:
            self.send_json(404, {'error': 'Run or artifact not found.'})
        except RuntimeError as exc:
            self.send_json(409, {'error': str(exc)[:300]})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except OSError:
            self.send_json(500, {'error': 'Runner storage operation failed.'})

    do_GET = handle_method
    do_POST = handle_method


def main():
    server = http.server.ThreadingHTTPServer(('0.0.0.0', int(os.getenv('OFFENSIVE_PORT', '8090'))), Handler)
    server.daemon_threads = True
    server.runner = Runner()
    def stop(signum, frame):
        def shutdown():
            for run_id in list(server.runner.active):
                server.runner.cancel(run_id)
            server.shutdown()
        threading.Thread(target=shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


# The CLI adapter is defined before the main entry point below.

NUCLEI_TEMPLATES = {
    'directory-listing.yaml': '''id: aegis-directory-listing
info:
  name: Directory listing response
  author: aegisloop
  severity: low
  description: Directory index content is a candidate exposure requiring context validation.
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    redirects: false
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: regex
        part: body
        regex:
          - '(?i)<title>[[:space:]]*(Index of|listing directory|directory listing for)([[:space:]]|<)'
          - '(?i)<h1>Index of'
''',
    'debug-trace.yaml': '''id: aegis-debug-trace
info:
  name: Server diagnostic trace exposed in response
  author: aegisloop
  severity: low
  description: A stack trace marker was observed; information sensitivity requires further verification.
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    redirects: false
    matchers:
      - type: word
        part: body
        words:
          - "Traceback (most recent call last)"
          - "Exception in thread"
          - "Microsoft.AspNetCore.Diagnostics.DeveloperExceptionPageMiddleware"
''',
    'credentialed-cors.yaml': '''id: aegis-credentialed-cors
info:
  name: Reflected origin with credentialed CORS
  author: aegisloop
  severity: medium
  description: Reflected cross-origin permission needs authentication and sensitive-response validation.
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: https://aegisloop-origin.invalid
    redirects: false
    matchers-condition: and
    matchers:
      - type: word
        part: header
        case-insensitive: true
        words: ["access-control-allow-origin: https://aegisloop-origin.invalid"]
      - type: word
        part: header
        case-insensitive: true
        words: ["access-control-allow-credentials: true"]
''',
}


class Broker(http.server.BaseHTTPRequestHandler):
    """CLI HTTP proxy: no CONNECT, no mutation methods, no caller credentials.

    The actual connection is made by RequestContext, which validates and pins DNS
    and never follows redirects. Only fixed Origin test headers are forwarded.
    """
    def log_message(self, *args):
        pass

    def do_GET(self):
        ctx, runner, run_id, tool = self.server.context
        try:
            if not self.path.startswith('http://'):
                raise DiagnosticError('policy_denied', 'CLI broker accepts absolute HTTP URLs only.')
            ctx.scope.normalize(self.path)
            result = runner._fetch(ctx, self.path, {'Origin': self.headers.get('Origin', '')})
            evidence = runner._response_evidence(run_id, ctx, result, tool + '-http')
            runner._observe(run_id, ctx, self.path, tool + '_http_response', evidence, 'observed', result['status'], technologies(result), kind='service' if tool == 'http_probe' else 'endpoint')
            documented = runner._record_openapi(run_id, ctx, result, evidence)
            for link, source in ([] if documented is not None else extract_links(result)):
                try:
                    discovered, names = ctx.scope.normalize(link, result['url'])
                except DiagnosticError:
                    continue
                runner._observe(run_id, ctx, discovered, source, evidence, parameters=names, parent_url=result['url'], relation=source)
            with self.server.guard:
                self.server.successes += 1
            # send_response() adds this Python broker's Server/Date headers and
            # makes technology detectors fingerprint the proxy as the target.
            # Relay the upstream status and headers without synthetic identity.
            self.send_response_only(result['status'])
            # Cookies from target are intentionally not given to a tool. The supplied
            # bearer credential is injected by the broker only inside fixed scope.
            for key, value in result['headers'].items():
                if key not in ('set-cookie', 'connection', 'transfer-encoding', 'content-length', 'content-encoding', 'proxy-authenticate') and '\n' not in value and '\r' not in value:
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(result['body'])))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(result['body'])
        except DiagnosticError as exc:
            with self.server.guard:
                if len(self.server.failures) < 100:
                    self.server.failures.append(exc.kind)
            with contextlib.suppress(OSError):
                self.send_error(403 if exc.kind == 'policy_denied' else 502, exc.kind)
        except (OSError, ValueError):
            with self.server.guard:
                self.server.failures.append('transient_dependency_error')

    def denied(self):
        with self.server.guard:
            self.server.failures.append('policy_denied')
        self.send_error(403, 'Only scoped HTTP GET is permitted; tunnelling is unavailable.')

    do_CONNECT = denied
    do_POST = denied
    do_PUT = denied
    do_DELETE = denied
    do_PATCH = denied
    do_HEAD = denied
    do_OPTIONS = denied


def cli_arguments(tool, binary, scope, proxy, scratch, duration, max_urls=100):
    """Only typed arguments; no strings supplied by a user become command flags."""
    if tool == 'http_probe':
        return [binary, '-u', scope.target, '-j', '-silent', '-sc', '-title', '-td', '-server', '-nfs', '-no-stdin', '-duc', '-timeout', '8', '-retries', '0', '-t', '1', '-rl', '2', '-rstr', str(MAX_BODY), '-proxy', proxy]
    if tool == 'crawl':
        return [binary, '-u', scope.target, '-j', '-silent', '-nc', '-duc', '-or', '-ob', '-mdp', str(max_urls), '-d', '3', '-jc', '-dr', '-iqp', '-retry', '0', '-timeout', '8', '-ct', str(duration) + 's', '-c', '1', '-p', '1', '-rl', '2', '-mrs', str(MAX_BODY), '-cs', '^' + re.escape(scope.origin + scope.prefix) + r'(?:/|$|\?)', '-proxy', proxy]
    return [binary, '-l', str(Path(scratch) / 'targets.txt'), '-t', str(Path(scratch) / 'templates'), '-jsonl', '-silent', '-nc', '-duc', '-nh', '-pi', '-mt', str(duration) + 's', '-ni', '-dr', '-or', '-ot', '-no-stdin', '-timeout', '8', '-retries', '0', '-c', '1', '-bs', '1', '-rl', '2', '-rsr', str(MAX_BODY), '-proxy', proxy]


def run_cli(runner, run_id, tool, ctx):
    ctx.check()
    binary_name = {'http_probe': 'httpx', 'crawl': 'katana', 'nuclei': 'nuclei'}[tool]
    binary = runner.tools[binary_name]['path']
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Broker)
    server.daemon_threads = True
    server.context = (ctx, runner, run_id, tool)
    server.guard, server.successes, server.failures = threading.Lock(), 0, []
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
    thread.start()
    process, output, errors = None, bytearray(), bytearray()
    overflow = threading.Event()
    try:
        with tempfile.TemporaryDirectory(prefix='aegis-tool-') as scratch:
            # Input is reconstructed from normalized scoped observations, never from
            # a caller-provided CLI command, template, file path, or raw scanner output.
            urls = [o['url'] for o in runner.get(run_id)['observations'] if o['confidence'] == 'observed']
            urls = list(dict.fromkeys([ctx.scope.target] + urls))[:ctx.max_urls]
            (Path(scratch) / 'targets.txt').write_text('\n'.join(urls) + '\n')
            templates = Path(scratch) / 'templates'
            templates.mkdir()
            for name, text in NUCLEI_TEMPLATES.items():
                (templates / name).write_text(text)
            proxy = 'http://127.0.0.1:' + str(server.server_port)
            argv = cli_arguments(tool, binary, ctx.scope, proxy, scratch, max(1, int(ctx.deadline - time.monotonic())), ctx.max_urls)
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, start_new_session=True, cwd=scratch, env=runner.tool_env(scratch))
            with runner.lock:
                active = runner.active.get(run_id)
                if active:
                    active['process'] = process
            def read(pipe, buffer, maximum):
                while True:
                    data = pipe.read(8192)
                    if not data:
                        return
                    room = maximum - len(buffer)
                    buffer.extend(data[:max(0, room)])
                    if len(data) > room:
                        overflow.set()
                        return
            readers = [threading.Thread(target=read, args=(process.stdout, output, MAX_ARTIFACT // 2), daemon=True), threading.Thread(target=read, args=(process.stderr, errors, 65536), daemon=True)]
            for reader in readers:
                reader.start()
            failure = None
            while process.poll() is None:
                try:
                    ctx.check()
                    if overflow.is_set():
                        raise DiagnosticError('budget_exhausted', 'Tool output exceeded its bounded capture limit.')
                    if 'budget_exhausted' in server.failures:
                        raise DiagnosticError('budget_exhausted', 'Tool reached the scoped HTTP request/byte limit.')
                    if 'url_limit' in server.failures:
                        raise DiagnosticError('collection_limit', 'Tool reached the distinct URL limit; following stages can use the collected URLs.')
                except DiagnosticError as exc:
                    failure = exc
                    runner._kill(process)
                    break
                ctx.cancel.wait(0.05)
            for reader in readers:
                reader.join(timeout=2)
            stdout, stderr = output.decode('utf-8', 'replace'), errors.decode('utf-8', 'replace')
            raw_ref = runner._artifact(run_id, binary_name + '-output-' + uuid.uuid4().hex[:8] + '.json', {'tool': binary_name, 'stdout': stdout, 'stderr': stderr, 'exit_code': process.returncode, 'truncated': overflow.is_set(), 'redacted': True, 'broker_successful_requests': server.successes, 'broker_rejections': dict(collections.Counter(server.failures))}, (ctx.token,))
            runner._execution(run_id, tool, exit_code=process.returncode)
            parsed, invalid = [], 0
            for line in stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError('not an object')
                    parsed.append(row)
                except ValueError:
                    invalid += 1
            for row in parsed[:1000]:
                if tool == 'http_probe':
                    url = row.get('url', '')
                    runner._observe(run_id, ctx, url, 'httpx', raw_ref, 'observed' if server.successes else 'inferred', row.get('status_code'), row.get('tech', []) if isinstance(row.get('tech', []), list) else [], kind='service')
                elif tool == 'crawl':
                    request = row.get('request', {})
                    response = row.get('response', {})
                    if isinstance(request, dict) and request.get('method', 'GET').upper() == 'GET':
                        url = request.get('endpoint', request.get('url', ''))
                        runner._observe(run_id, ctx, url, 'katana', raw_ref, 'inferred')
                        # Actual responses are observed only by the broker; a tool
                        # claiming a status is not independently trusted here.
                elif tool == 'nuclei':
                    url = row.get('matched-at', row.get('url', ''))
                    try:
                        scoped_url, _ = ctx.scope.normalize(url)
                    except DiagnosticError:
                        continue
                    template_id = row.get('template-id')
                    if template_id not in {'aegis-directory-listing', 'aegis-debug-trace', 'aegis-credentialed-cors'}:
                        continue
                    info = row.get('info', {})
                    title = str(info.get('name', template_id))[:200]
                    severity = info.get('severity', 'info')
                    if severity not in ('info', 'low', 'medium', 'high', 'critical'):
                        severity = 'info'
                    candidate = {'id': str(uuid.uuid4()), 'title': redact(title, (ctx.token,)), 'severity': severity, 'url': scoped_url, 'method': 'GET', 'description': redact(str(info.get('description', 'Scanner match; actual exploitability is not verified.'))[:1000], (ctx.token,)), 'evidence_refs': [raw_ref], 'verification': 'candidate', 'template_id': template_id}
                    def add(run):
                        observed = next((o for o in run['observations'] if o['url'] == scoped_url and o['confidence'] == 'observed'), None)
                        if observed and not any(c.get('template_id') == template_id and c['url'] == scoped_url for c in run['candidates']) and len(run['candidates']) < 100:
                            candidate['evidence_refs'].append(observed['evidence_ref'])
                            run['candidates'].append(candidate)
                    runner._mutate(run_id, add)
            if failure:
                raise failure
            ctx.check()
            if process.returncode != 0:
                raise DiagnosticError('tool_execution_failed', f'{binary_name} exited with status {process.returncode}; bounded output is retained.')
            if invalid:
                raise DiagnosticError('parse_error', f'{binary_name} produced {invalid} non-JSON output lines; partial parsed evidence is retained.')
            if not server.successes:
                raise DiagnosticError('tool_execution_failed', f'{binary_name} completed without any scoped HTTP response; no successful inspection is claimed.')
            if any(kind not in ('policy_denied',) for kind in server.failures):
                raise DiagnosticError('partial_collection', 'Some tool requests failed; successful evidence is retained.')
            if server.failures:
                runner._warning(run_id, f'{binary_name}: out-of-scope or non-GET requests were blocked by the transport broker.')
    except OSError as exc:
        raise DiagnosticError('tool_unavailable', f'{binary_name} could not be launched.') from exc
    finally:
        if process:
            runner._kill(process)
            with contextlib.suppress(Exception):
                process.stdout.close()
                process.stderr.close()
        with runner.lock:
            if run_id in runner.active:
                runner.active[run_id]['process'] = None
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


if __name__ == '__main__':
    main()
