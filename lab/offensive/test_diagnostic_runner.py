"""Behavioral tests for scoped discovery, execution durability and tool integration."""
import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid

import diagnostic_runner as d

TOKEN = 'test-shared-token-' + 'x' * 32
BASE = 'http://lab.example.test:3000'


def response(url, body=b'<html>ok</html>', status=200, **headers):
    return {'url': url, 'status': status, 'headers': {'content-type': 'text/html', **headers}, 'body': body, 'truncated': False}


class Fixture(http.server.BaseHTTPRequestHandler):
    calls = []
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.calls.append((self.path, self.headers.get('Authorization')))
        body = b'<html><a href="/list?item=2">listing</a><a href="/serve-index">alternate index</a><script src="/app.js"></script><a href="http://out-of-scope.invalid/">external</a></html>'
        headers = {'Content-Type': 'text/html', 'Server': 'Fixture-Origin/1.0', 'X-Powered-By': 'Express'}
        if self.path == '/list':
            body = b'<html><title>Index of /list</title><h1>Index of /list</h1><a href="/file.txt">file</a></html>'
        elif self.path == '/serve-index':
            body = b'<html><title>listing directory /serve-index</title><h1>Directory</h1><a href="/file.txt">file</a></html>'
        elif self.path == '/app.js':
            headers['Content-Type'] = 'application/javascript'
            body = b'fetch("/api/items?sort=newest"); fetch("/api/other");'
        elif self.path.startswith('/api/'):
            headers['Content-Type'] = 'application/json'
            body = b'{"message":"ok","access_token":"do-not-persist-fixture-secret"}'
        if self.headers.get('Origin'):
            headers['Access-Control-Allow-Origin'] = self.headers['Origin']
            headers['Access-Control-Allow-Credentials'] = 'true'
        self.send_response_only(200)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header('Set-Cookie', 'session=never-persist-fixture-cookie')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ScopeTests(unittest.TestCase):
    def test_swagger_ui_literal_spec_link_is_recognized_without_script_execution(self):
        page = response(BASE + '/api/docs/',
                        b'<script>SwaggerUIBundle({url: "/service/api-docs-v2.json"})</script>')
        self.assertIn(('/service/api-docs-v2.json', 'openapi_document_link'), d.extract_links(page))

    def test_openapi_inventory_keeps_methods_and_never_resolves_template_or_other_origin(self):
        document = {'openapi': '3.0.3', 'servers': [{'url': '/'}], 'paths': {
            '/api/accounts': {'get': {'summary': 'List accounts'}, 'post': {'summary': 'Create account'}},
            '/api/accounts/{id}': {'get': {'summary': 'Read account'}},
            '/api/../admin': {'get': {'summary': 'Unsafe path'}},
        }}
        result = response(BASE + '/static/openapi.json', json.dumps(document).encode(),
                          **{'content-type': 'application/json'})
        operations, truncated, recognized = d.openapi_operations(result, d.Scope(BASE), 'response.json')
        self.assertTrue(recognized)
        self.assertFalse(truncated)
        self.assertEqual({(row['method'], row['path']) for row in operations},
                         {('GET', '/api/accounts'), ('POST', '/api/accounts'), ('GET', '/api/accounts/{id}')})
        self.assertEqual(next(row for row in operations if '{id}' in row['path'])['url'], '')
        self.assertTrue(all(row['verification'] == 'documented_unverified' for row in operations))
        outside = {**document, 'servers': [{'url': 'https://other.example.test/'}]}
        mapped, _, recognized = d.openapi_operations(response(result['url'], json.dumps(outside).encode(),
                         **{'content-type': 'application/json'}), d.Scope(BASE), 'response.json')
        self.assertTrue(recognized)
        self.assertTrue(all(row['server_origin_mismatch'] for row in mapped))
        self.assertTrue(all(not row['url'] or row['url'].startswith(BASE + '/') for row in mapped))

    def test_sitemap_and_robots_are_bounded_leads(self):
        sitemap = response(BASE + '/sitemap.xml', b'<urlset><url><loc>http://lab.example.test:3000/reports</loc></url></urlset>', **{'content-type': 'application/xml'})
        robots = response(BASE + '/robots.txt', b'User-agent: *\nDisallow: /private\nSitemap: http://lab.example.test:3000/sitemap.xml\n', **{'content-type': 'text/plain'})
        self.assertIn((BASE + '/reports', 'sitemap_entry'), d.extract_links(sitemap))
        self.assertIn(('/private', 'robots_hint'), d.extract_links(robots))

    def test_frozen_multi_url_scope_never_authorizes_discovered_siblings(self):
        allowed = d.ScopeSet(BASE + '/app', [BASE + '/', 'http://other.example.test:3000/internal'])
        self.assertEqual(allowed.normalize('http://other.example.test:3000/internal/logs')[0], 'http://other.example.test:3000/internal/logs')
        for url in ('http://other.example.test:3000/public', 'http://new.example.test:3000/', 'http://lab.example.test:3001/'):
            with self.subTest(url=url), self.assertRaises(d.DiagnosticError):
                allowed.normalize(url)
        with self.assertRaises(ValueError):
            d.ScopeSet(BASE + '/app', [BASE + '/admin'])

    def test_rejects_management_metadata_encoded_traversal_and_credentials(self):
        invalid = ['http://127.0.0.1/', 'http://[::1]/', 'http://169.254.169.254/latest', 'http://host.docker.internal/', 'http://artex:8787/', 'http://u:p@host/', 'file:///etc/passwd', 'http://good/a/%252e%252e/b', 'http://good/a?token=abc', 'http://good/%5cfoo', 'http://good/evil\nheader']
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(ValueError):
                d.Scope(url)

    def test_exact_origin_path_boundary_and_parameter_names(self):
        scope = d.Scope(BASE + '/api')
        self.assertEqual(scope.normalize(BASE + '/api/users?id=12&token=secret'), (BASE + '/api/users', ['id']))
        for url in [BASE + '/api2', BASE.replace('3000', '3001') + '/api', 'https://lab.example.test:3000/api', '//evil/path', '/api/%2e%2e/private', BASE + '/api/%252f%252fevil']:
            with self.subTest(url=url), self.assertRaises(d.DiagnosticError):
                scope.normalize(url)

    def test_dns_rebinding_blocks_any_forbidden_resolution(self):
        ctx = d.RequestContext(d.Scope(BASE), '', time.monotonic()+1, threading.Event(), 10)
        with mock.patch.object(d.socket, 'getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 3000))]):
            with self.assertRaises(d.DiagnosticError) as err:
                ctx.fetch(BASE)
        self.assertEqual(err.exception.kind, 'policy_denied')

    def test_expired_deadline_and_cancel_make_no_request(self):
        for cancelled, deadline in [(False, time.monotonic()-1), (True, time.monotonic()+10)]:
            stop = threading.Event()
            if cancelled:
                stop.set()
            ctx = d.RequestContext(d.Scope(BASE), '', deadline, stop, 10)
            with mock.patch.object(d.socket, 'getaddrinfo') as resolve, self.assertRaises(d.DiagnosticError):
                ctx.fetch(BASE)
            resolve.assert_not_called()

    def test_real_transport_stops_slow_response_on_cancel_and_deadline(self):
        class Slow(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length','100')
                self.end_headers()
                with contextlib.suppress(OSError):
                    self.wfile.write(b'x')
                    self.wfile.flush()
                    time.sleep(0.7)
                    self.wfile.write(b'x' * 99)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Slow)
        server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            for mode in ('cancelled','execution_timeout'):
                stop=threading.Event()
                ctx=d.RequestContext(d.Scope(f'http://allowed.test:{server.server_port}'),'',time.monotonic()+(0.2 if mode=='execution_timeout' else 10),stop,5)
                timer=threading.Timer(0.2,stop.set) if mode=='cancelled' else None
                if timer:
                    timer.start()
                start=time.monotonic()
                addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',server.server_port))]
                with mock.patch.object(d.socket,'getaddrinfo',return_value=addresses),mock.patch.object(d,'check_address'),self.assertRaises(d.DiagnosticError) as failure:
                    ctx.fetch(ctx.scope.target)
                if timer:
                    timer.cancel()
                self.assertEqual(failure.exception.kind,mode)
                self.assertLess(time.monotonic()-start,0.65)
        finally:
            server.shutdown();server.server_close();thread.join(2)

    def test_secret_redaction_and_query_value_removal(self):
        value = {'Authorization': 'Bearer private-key', 'body': 'password="abc def" token=zzz https://host/a?id=123&secret=a', 'data': {'access_token': 'secret-secret'}, 'cookie': 'secretcookie'}
        text = json.dumps(d.redact(value, ('private-key',)))
        for secret in ('private-key', 'abc def', 'zzz', '?id=123', 'secret-secret', 'secretcookie'):
            self.assertNotIn(secret, text)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.calls = []
        def fetch(ctx, url, headers=None):
            ctx.check()
            self.calls.append(url)
            if url == BASE + '/':
                return response(url, b'<a href="/api/items?sort=x">one</a><a href="/api/items?page=2">two</a><script src="/app.js"></script><a href="http://evil.invalid/">external</a>')
            if url.endswith('.js'):
                return response(url, b'fetch("/api/items?filter=x"); fetch("/api/other");', **{'content-type':'application/javascript'})
            return response(url, b'{"access_token":"private-body-value","ok":true}', **{'content-type':'application/json'})
        self.runner = d.Runner(self.temp.name, TOKEN, fetcher=fetch, binaries={})
    def tearDown(self):
        for run in self.runner.list():
            if run['status'] in d.ACTIVE:
                self.runner.cancel(run['id'])
        time.sleep(0.03)
        self.temp.cleanup()
    def wait(self, run, timeout=8):
        end = time.monotonic()+timeout
        while time.monotonic()<end:
            result = self.runner.get(run['id'])
            if result['status'] not in d.ACTIVE and run['id'] not in self.runner.active:
                return result
            time.sleep(0.01)
        self.fail('Run did not finish')
    def create(self, **fields):
        return self.runner.create({'target_url': BASE, 'goal': '점검 대상의 노출 경로 확인', 'tools': ['http_probe','crawl'], **fields})

    def test_goal_is_required(self):
        with self.assertRaises(ValueError):
            self.create(goal='   ')

    def test_openapi_gets_are_prioritized_without_executing_post_or_template_paths(self):
        document = {'openapi': '3.0.3', 'servers': [{'url': '/'}], 'paths': {
            '/api/accounts': {'get': {'summary': 'List accounts'}},
            '/api/transactions': {'get': {'summary': 'List transactions'}, 'post': {'summary': 'Create transaction'}},
            '/api/accounts/{id}': {'get': {'summary': 'Read account'}},
            '/api/transfer': {'get': {'summary': 'Trigger transfer'}},
        }}
        def fetch(ctx, url, headers=None):
            ctx.check()
            self.calls.append(url)
            if url == BASE + '/':
                return response(url, b'<a href="/static/openapi.json">API</a>')
            if url == BASE + '/static/openapi.json':
                return response(url, json.dumps(document).encode(), **{'content-type': 'application/json'})
            return response(url, b'{"ok":true}', **{'content-type': 'application/json'})
        self.runner.fetcher = fetch
        run = self.wait(self.create(tools=['http_probe', 'surface_map', 'crawl'], max_urls=32))
        operations = run['api_operations']
        self.assertEqual(len(operations), 5)
        self.assertEqual({o['method'] for o in operations}, {'GET', 'POST'})
        self.assertTrue(any(o['path'] == '/api/transactions' and o['method'] == 'POST' and
                            o['verification'] == 'documented_unverified' for o in operations))
        self.assertTrue(any(o['path'] == '/api/accounts/{id}' and not o['url'] for o in operations))
        self.assertNotIn(BASE + '/api/accounts/{id}', self.calls)
        self.assertNotIn(BASE + '/api/transfer', self.calls)
        self.assertIn(BASE + '/api/accounts', self.calls)
        self.assertIn(BASE + '/api/transactions', self.calls)
        self.assertEqual(run['coverage']['documented_operations'], 5)
        self.assertGreaterEqual(run['coverage']['observed_documented_get_operations'], 2)
        self.assertFalse(run['coverage']['exhaustive'])
        self.assertEqual(run['coverage']['scanner_candidates'], 0)

    def test_openapi_document_and_safe_gets_precede_generic_links_under_url_budget(self):
        spec_url = BASE + '/service/api-docs-v2.json'
        document = {'openapi': '3.0.3', 'servers': [{'url': 'https://production.example.invalid/'}],
                    'paths': {'/api/accounts': {'get': {'operationId': 'listAccounts'}},
                              '/api/withdraw': {'get': {'operationId': 'withdrawFunds'}},
                              '/api/status': {'get': {'operationId': 'runStatusCheck'}},
                              '/api/transactions': {'get': {'operationId': 'listTransactions'}}}}
        def fetch(ctx, url, headers=None):
            ctx.check()
            self.calls.append(url)
            if url == BASE + '/':
                links = ''.join(f'<a href="/ordinary-{n}">item</a>' for n in range(30))
                return response(url, (links + '<a href="/service/api-docs-v2.json">spec</a>').encode())
            if url == spec_url:
                return response(url, json.dumps(document).encode(), **{'content-type': 'application/json'})
            return response(url)
        self.runner.fetcher = fetch
        run = self.wait(self.create(tools=['surface_map'], max_urls=20))
        self.assertEqual(self.calls[:3], [BASE + '/', spec_url, BASE + '/api/accounts'])
        self.assertIn(BASE + '/api/transactions', self.calls)
        self.assertNotIn(BASE + '/api/withdraw', self.calls)
        self.assertNotIn(BASE + '/api/status', self.calls)
        self.assertEqual(run['coverage']['documented_operations'], 4)
        self.assertEqual(run['coverage']['observed_documented_get_operations'], 2)
        self.assertTrue(all(row['server_origin_mismatch'] for row in run['api_operations']))

    def test_unexpected_failure_does_not_leave_followup_pending(self):
        self.runner._native = lambda *_args: (_ for _ in ()).throw(RuntimeError('unexpected fixture error'))
        run = self.wait(self.create(tools=['http_probe'], auto_followup=True))
        self.assertEqual(run['status'], 'failed')
        self.assertEqual(run['followup']['status'], 'failed')

    def test_multi_scope_probe_reports_partial_when_one_seed_fails(self):
        other = 'http://other.example.test:3000'
        def fetch(ctx, url, headers=None):
            if url == BASE + '/':
                raise d.DiagnosticError('transient_dependency_error', 'first target unavailable')
            return response(url)
        self.runner.fetcher = fetch
        run = self.wait(self.create(tools=['http_probe'], scope_urls=[BASE, other]))
        self.assertEqual(run['status'], 'partial')
        self.assertEqual(run['executions'][0]['error_kind'], 'partial_collection')
        self.assertIn(other + '/', [o['url'] for o in run['observations']])

    def test_stages_merge_sources_and_parameters_without_cross_scope_requests(self):
        run = self.wait(self.create())
        self.assertEqual(run['status'], 'completed')
        item = next(o for o in run['observations'] if o['url'].endswith('/api/items'))
        self.assertEqual(item['parameters'], ['filter','page','sort'])
        self.assertEqual(item['confidence'], 'observed')
        self.assertIn('html_link', item['sources'])
        self.assertIn('javascript_literal', item['sources'])
        self.assertTrue(all(url.startswith(BASE) for url in self.calls))
        self.assertEqual(len({o['url'] for o in run['observations']}), len(run['observations']))
        self.assertTrue(all(e['artifact_names'] for e in run['executions']))
        self.assertFalse(run['candidates'])

    def test_surface_map_finds_unlinked_route_and_keeps_path_unverified(self):
        run = self.wait(self.create(goal='익명 접근 가능한 문서가 있는지 확인', tools=['http_probe', 'surface_map']))
        ftp = BASE + '/ftp'
        self.assertIn(ftp, self.calls)
        path = next(path for path in run['attack_paths'] if path['target_url'] == ftp)
        self.assertEqual(path['status'], 'verification_required')
        self.assertEqual([step['url'] for step in path['steps']], [BASE + '/', ftp])
        self.assertEqual(path['steps'][-1]['relation'], 'common_path')
        self.assertTrue(path['evidence_refs'])
        self.assertEqual(run['scope_urls'], [BASE + '/'])
        self.assertFalse(any('evil.invalid' in call for call in self.calls))

    def test_attack_path_uses_shortest_root_provenance_even_with_cycle(self):
        def observed(url):
            return {'id': url, 'url': url, 'confidence': 'observed', 'status_code': 200,
                    'evidence_ref': 'evidence.json', 'sources': ['native_http_response']}
        root, directory, document = BASE + '/', BASE + '/ftp', BASE + '/ftp/file.md'
        run = {'target_url': root, 'scope_urls': [root], 'goal': '문서 접근 확인',
               'observations': [observed(url) for url in (root, directory, document)],
               'candidates': [], 'surface_edges': [
                   {'from': root, 'to': directory, 'relation': 'common_path'},
                   {'from': directory, 'to': document, 'relation': 'html_link'},
                   {'from': document, 'to': directory, 'relation': 'html_link'},
                   {'from': document, 'to': root, 'relation': 'html_link'}]}
        path = next(path for path in d.build_attack_paths(run) if path['target_url'] == document)
        self.assertEqual([step['url'] for step in path['steps']], [root, directory, document])
        self.assertIn('입력한 목표와 관련된 경로', path['priority_basis'])

    def test_spa_fallback_is_not_ranked_as_an_attack_path(self):
        common = b'<html>same client app shell</html>'
        def fetch(ctx, url, headers=None):
            ctx.check()
            return response(url, b'<html>ftp directory</html>' if url.endswith('/ftp') else common)
        self.runner.fetcher = fetch
        run = self.wait(self.create(tools=['surface_map']))
        self.assertIn(BASE + '/ftp', [path['target_url'] for path in run['attack_paths']])
        self.assertNotIn(BASE + '/admin', [path['target_url'] for path in run['attack_paths']])

    def test_document_goal_prefers_documents_over_unrelated_downloads(self):
        root = BASE + '/'
        urls = [root, BASE + '/ftp', BASE + '/ftp/', BASE + '/ftp/readme.md', BASE + '/ftp/tool.url', BASE + '/robots.txt', BASE + '/.well-known/security.txt']
        run = {'target_url': root, 'scope_urls': [root], 'goal': '비공개 문서 노출 조사',
               'observations': [{'url': url, 'confidence': 'observed', 'status_code': 200,
                                 'evidence_ref': 'evidence.json', 'sources': ['native_http_response']} for url in urls],
               'surface_edges': [{'from': root, 'to': url, 'relation': 'common_path'} for url in urls[1:]],
               'candidates': []}
        paths = d.build_attack_paths(run)
        targets = [path['target_url'] for path in paths]
        self.assertLess(targets.index(BASE + '/ftp/readme.md'), targets.index(BASE + '/ftp/tool.url'))
        self.assertEqual(sum(url.rstrip('/') == BASE + '/ftp' for url in targets), 1)
        self.assertNotIn(BASE + '/robots.txt', targets)

    def test_auth_secret_never_persisted_and_context_is_distinct(self):
        run = self.wait(self.create(bearer_token='sample-credential-value'))
        self.assertEqual(run['auth_context'], 'provided_bearer')
        for path in Path(self.temp.name).rglob('*'):
            if path.is_file():
                text = path.read_text()
                self.assertNotIn('sample-credential-value', text)
                self.assertNotIn('private-body-value', text)
        self.assertTrue(all(o['auth_context'] == 'provided_bearer' for o in run['observations']))

    def test_missing_nuclei_is_visible_partial_not_no_findings_success(self):
        run = self.wait(self.create(tools=['http_probe','nuclei']))
        self.assertEqual(run['status'], 'partial')
        self.assertEqual(run['executions'][1]['status'], 'unavailable')
        self.assertEqual(run['executions'][1]['error_kind'], 'tool_unavailable')

    def test_out_of_scope_redirect_is_observed_but_never_followed(self):
        def redirect(ctx,url,headers=None):
            self.calls.append(url)
            return response(url,b'',302,location='http://169.254.169.254/latest/meta-data/')
        self.runner.fetcher=redirect
        run=self.wait(self.create(tools=['crawl']))
        self.assertEqual(run['status'],'completed')
        self.assertEqual(self.calls,[BASE+'/'])
        self.assertEqual(len(run['observations']),1)

    def test_failed_http_does_not_become_success(self):
        def failed(*args):
            raise d.DiagnosticError('transient_dependency_error','Target unavailable')
        self.runner.fetcher = failed
        run = self.wait(self.create(auto_followup=True))
        self.assertEqual(run['status'], 'failed')
        self.assertFalse(run['observations'])
        self.assertEqual(run['followup']['status'], 'failed')

    def test_cancel_retains_completed_evidence(self):
        initial = self.runner.fetcher
        entered = threading.Event()
        def blocked(ctx, url, headers=None):
            if len(self.calls) >= 1:
                entered.set()
                ctx.cancel.wait(3)
                ctx.check()
            return initial(ctx,url,headers)
        self.runner.fetcher = blocked
        run = self.create()
        self.assertTrue(entered.wait(2))
        self.runner.cancel(run['id'])
        result = self.wait(run)
        self.assertEqual(result['status'], 'cancelled')
        self.assertTrue(result['observations'])
        self.assertEqual(result['executions'][0]['status'], 'completed')
        self.assertEqual(result['executions'][1]['status'], 'cancelled')

    def test_restart_marks_running_unknown_without_replay(self):
        run = self.wait(self.create())
        run['status'] = 'running'
        run['executions'][0]['status'] = 'running'
        self.runner._save(run)
        fetch = mock.Mock()
        reopened = d.Runner(self.temp.name, TOKEN, fetcher=fetch, binaries={})
        result = reopened.get(run['id'])
        self.assertEqual(result['status'], 'interrupted')
        self.assertEqual(result['executions'][0]['error_kind'], 'unknown_execution_state')
        fetch.assert_not_called()

    def test_artifact_path_and_integrity_enforced(self):
        run = self.wait(self.create())
        name = run['artifacts'][0]['name']
        self.assertTrue(self.runner.artifact(run['id'], name))
        with self.assertRaises(LookupError):
            self.runner.artifact(run['id'], '../run.json')
        (Path(self.temp.name)/run['id']/name).write_text('tampered')
        with self.assertRaises(RuntimeError):
            self.runner.artifact(run['id'], name)

    def test_followup_binding_idempotent_and_no_second_task(self):
        run = self.wait(self.create(auto_followup=True, llm_profile_ids=[2]))
        result = self.runner.bind(run['id'], {'status':'needs_model','task_id':''})
        self.assertNotIn('task_id',result['followup'])
        result = self.runner.bind(run['id'], {'status':'running','task_id':'123'})
        self.assertEqual(result['followup']['task_id'],'123')
        result = self.runner.bind(run['id'], {'status':'completed'})
        self.assertEqual(result['followup']['task_id'],'123')
        with self.assertRaises(RuntimeError):
            self.runner.bind(run['id'], {'status':'running','task_id':'124'})

    def test_invalid_tool_and_arbitrary_command_fields_rejected(self):
        for fields in [{'tools':['shell']},{'tools':['http_probe','http_probe']},{'command':'id'},{'max_urls':True},{'timeout_seconds':9999},{'bearer_token':'abc\nHeader: evil'}]:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.create(**fields)

    def test_inferred_links_are_not_observed_when_url_budget_exhausted(self):
        original_fetch = self.runner.fetcher
        def count_transport(ctx, url, headers=None):
            # The injected fixture bypasses RequestContext.fetch, so account
            # for its request to test the real transport's budget reporting.
            ctx.seen.add(url)
            ctx.requests += 1
            return original_fetch(ctx, url, headers)
        self.runner.fetcher = count_transport
        run = self.wait(self.create(max_urls=1))
        links = [o for o in run['observations'] if o['url'].endswith('/api/items')]
        self.assertEqual(links[0]['confidence'],'inferred')
        self.assertTrue(any('URL' in w for w in run['warnings']))
        self.assertFalse(run['coverage']['exhaustive'])
        self.assertIn('url_budget_reached', run['coverage']['limits'])
        self.assertEqual(run['coverage']['max_distinct_urls'], 1)

    def test_list_is_compact_and_keeps_detail_artifacts_unchanged(self):
        run = self.wait(self.create())
        before = (Path(self.temp.name)/run['id']/'run.json').read_bytes()
        summary = next(item for item in self.runner.list() if item['id'] == run['id'])
        self.assertTrue(summary['is_summary'])
        for field in ('observations','candidates','artifacts'):
            self.assertEqual(summary[field], [])
            self.assertEqual(summary['counts'][field], len(run[field]))
        self.assertTrue(all(execution['artifact_names'] == [] for execution in summary['executions']))
        self.assertEqual(self.runner.get(run['id']), run)
        self.assertEqual((Path(self.temp.name)/run['id']/'run.json').read_bytes(), before)
        self.assertTrue(self.runner.artifact(run['id'], run['artifacts'][0]['name']))

    def test_list_keeps_old_active_and_pending_followups_beyond_history_limit(self):
        base = self.wait(self.create())
        records = []
        for index, (status, followup) in enumerate([
            ('completed','completed'), ('running','available'), ('queued','available'),
            ('completed','pending'), ('completed','launching'), ('partial','running'),
            ('completed','available'), ('completed','completed')]):
            run = {**base, 'id': str(uuid.uuid4()), 'status': status,
                   'created_at': f'2020-01-01T00:00:{index:02d}Z',
                   'followup': {'status': followup}}
            self.runner._save(run)
            records.append(run)
        with mock.patch.object(d,'MAX_RUNS',2):
            summaries = self.runner.list()
        retained = {run['id'] for run in summaries}
        self.assertIn(base['id'],retained)  # latest real record
        self.assertIn(records[-1]['id'],retained)  # second latest record
        for run in records[1:6]:
            self.assertIn(run['id'],retained)
        self.assertNotIn(records[0]['id'],retained)
        self.assertNotIn(records[6]['id'],retained)
        self.assertEqual([r['created_at'] for r in summaries],
                         sorted([r['created_at'] for r in summaries],reverse=True))

    def test_large_evidence_history_does_not_exceed_proxy_response_budget(self):
        base = self.wait(self.create())
        for _ in range(d.MAX_RUNS-1):
            (Path(self.temp.name)/str(uuid.uuid4())).mkdir()
        heavy = {**base, 'observations': [{'summary':'x'*100000}],
                 'candidates': [{'description':'x'*100000}],
                 'artifacts': [{'name':'artifact.json','extra':'x'*100000}]}
        with mock.patch.object(self.runner,'_load',side_effect=lambda run_id:{**heavy,'id':run_id}):
            result = self.runner.list()
        self.assertEqual(len(result),d.MAX_RUNS)
        # The old response would exceed 60 MiB; summaries remain well below the
        # Go proxy/monitor 16 MiB limit without losing observation counts.
        self.assertLess(len(json.dumps({'runs':result}).encode()),1024*1024)
        self.assertTrue(all(run['counts']['observations'] == 1 for run in result))

    def test_typed_cli_args_disable_updates_redirects_and_external_callbacks(self):
        scope = d.Scope(BASE)
        args = d.cli_arguments('nuclei','/tools/nuclei',scope,'http://127.0.0.1:1234','/tmp/fixed',20)
        for flag in ['-ni','-dr','-duc','-or','-ot','-no-stdin','-proxy','-mt']:
            self.assertIn(flag,args)
        self.assertNotIn('-code', args)
        self.assertNotIn('-headless', args)
        env = self.runner.tool_env('/tmp/fixed')
        self.assertNotIn('AWS_SECRET_ACCESS_KEY',env)
        self.assertNotIn('OPENAI_API_KEY',env)

    def test_api_auth_create_poll_and_artifact_download(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1',0),d.Handler)
        server.runner=self.runner
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        def request(method,path,body=None,auth=True):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
            headers={'Authorization':'Bearer '+TOKEN} if auth else {}
            conn.request(method,path,json.dumps(body) if body is not None else None,headers)
            response=conn.getresponse(); data=response.read(); code=response.status; conn.close()
            return code,json.loads(data)
        try:
            self.assertEqual(request('GET','/health',auth=False)[0],200)
            self.assertEqual(request('GET','/diagnostics/catalog',auth=False)[0],401)
            self.assertEqual(request('GET','/diagnostics/catalog')[0],200)
            code,run=request('POST','/diagnostics/runs',{'target_url':BASE,'goal':'허용 대상의 노출 경로 확인','tools':['http_probe']})
            self.assertEqual(code,202)
            result=self.wait(run)
            self.assertEqual(request('GET','/diagnostics/runs/'+run['id'])[1]['status'],'completed')
            path='/diagnostics/runs/'+run['id']+'/artifacts/'+result['artifacts'][0]['name']
            self.assertEqual(request('GET',path)[0],200)
            self.assertEqual(request('GET','/diagnostics/runs/not-a-uuid')[0],404)
            self.assertEqual(request('GET',path+'?raw=1')[0],400)
        finally:
            server.shutdown();server.server_close();thread.join(2)

    def test_cli_broker_preserves_only_upstream_server_and_date_headers(self):
        run = self.wait(self.create(tools=['http_probe']))
        upstream = {'server': 'origin-test-server/4.2', 'date': 'Thu, 01 Jan 1970 00:00:00 GMT'}
        self.runner.fetcher = lambda ctx,url,headers=None: response(url,**upstream)
        ctx=d.RequestContext(d.Scope(BASE),'',time.monotonic()+5,threading.Event(),5)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),d.Broker)
        server.context=(ctx,self.runner,run['id'],'http_probe')
        server.guard,server.successes,server.failures=threading.Lock(),0,[]
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            for expected in (True,False):
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
                conn.request('GET',BASE+'/')
                received=conn.getresponse()
                headers=received.getheaders()
                received.read();conn.close()
                self.assertEqual(received.status,200)
                for name in ('server','date'):
                    values=[value for key,value in headers if key.lower()==name]
                    self.assertEqual(values,[upstream[name]] if expected else [])
                self.assertFalse(any('Python/' in value or 'BaseHTTP/' in value for _,value in headers))
                upstream.clear()
        finally:
            server.shutdown();server.server_close();thread.join(2)

    def test_subprocess_group_cancel_stops_execution(self):
        process=subprocess.Popen(['python3','-c','import time; time.sleep(20)'], start_new_session=True)
        start=time.monotonic()
        self.runner._kill(process)
        self.assertIsNotNone(process.poll())
        self.assertLess(time.monotonic()-start,3)


@unittest.skipUnless(os.getenv('AEGIS_TEST_REAL_CLI') == '1','Opt-in real httpx/Katana/Nuclei local fixture integration')
class RealCLITests(unittest.TestCase):
    def test_real_tools_produce_observations_candidates_and_redacted_evidence(self):
        host=socket.gethostbyname(socket.gethostname())
        d.check_address(host)
        server=http.server.ThreadingHTTPServer(('0.0.0.0',0),Fixture)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as data:
                runner=d.Runner(data,TOKEN)
                self.assertTrue(all(tool['path'] for tool in runner.tools.values()))
                run=runner.create({'target_url':f'http://{host}:{server.server_port}/','goal':'허용 대상의 노출 경로 확인','tools':['http_probe','crawl','nuclei'],'timeout_seconds':90,'max_urls':20,'bearer_token':'fixture-memory-only-token'})
                end=time.monotonic()+95
                while time.monotonic()<end:
                    result=runner.get(run['id'])
                    if result['status'] not in d.ACTIVE and run['id'] not in runner.active:
                        break
                    time.sleep(0.1)
                else:
                    runner.cancel(run['id']);self.fail('Real CLI run timed out')
                print(json.dumps({'real_cli_status':result['status'],'executions':result['executions'],'observations':len(result['observations']),'candidates':len(result['candidates'])},ensure_ascii=False))
                for item in result['executions']:
                    if item['status'] != 'completed':
                        for name in item['artifact_names']:
                            if '-output-' in name:
                                print(runner.artifact(run['id'],name).decode())
                self.assertEqual(result['status'],'completed')
                self.assertEqual([e['backend'] for e in result['executions']],['httpx','katana','nuclei'])
                tech = [technology for observation in result['observations'] for technology in observation['technologies']]
                self.assertFalse(any('python' in value.lower() or 'basehttp' in value.lower() for value in tech))
                self.assertTrue(any('Express' in value for value in tech))
                self.assertTrue(any(o['url'].endswith('/api/items') for o in result['observations']))
                directory_urls = {c['url'] for c in result['candidates'] if c['template_id']=='aegis-directory-listing'}
                self.assertTrue(any(url.endswith('/list') for url in directory_urls))
                self.assertTrue(any(url.endswith('/serve-index') for url in directory_urls))
                self.assertTrue(all(c['verification']=='candidate' for c in result['candidates']))
                for path in Path(data).rglob('*'):
                    if path.is_file():
                        text=path.read_text()
                        for secret in ('fixture-memory-only-token','do-not-persist-fixture-secret','never-persist-fixture-cookie'):
                            self.assertNotIn(secret,text)
                self.assertTrue(Fixture.calls)
                self.assertTrue(all(auth=='Bearer fixture-memory-only-token' for _,auth in Fixture.calls))
        finally:
            server.shutdown();server.server_close();thread.join(2)


if __name__=='__main__':
    unittest.main()
