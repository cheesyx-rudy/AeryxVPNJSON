import os
import json
import tempfile
import unittest
import base64
from pathlib import Path
from unittest.mock import patch

from aeryx_json_parser.fetch import Fetcher, redact_url
from aeryx_json_parser.models import FetchResult
from aeryx_json_parser.pipeline import load_sources


class FakeResponse:
    def __init__(self, content=None, status_code=200, content_type='text/plain; charset=utf-8', url=None):
        self.status_code = status_code
        self.url = url or 'https://panel.example/api/subscription?token=SECRET'
        self.headers = {'Content-Type': content_type}
        self._content = content if content is not None else b'vless://11111111-1111-4111-8111-111111111111@node.example:443#node\n'

    def __enter__(self): return self
    def __exit__(self, *args): return False
    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f'HTTP {self.status_code}')
    def iter_content(self, chunk_size=65536):
        yield self._content


class FetchTests(unittest.TestCase):
    def test_all_query_values_are_redacted(self):
        result=redact_url('https://example.test/sub?id=public&anything=SECRET&x=1#frag')
        self.assertNotIn('SECRET',result)
        self.assertNotIn('public',result)
        self.assertNotIn('frag',result)
        self.assertIn('id=%2A%2A%2A',result)
        path_result=redact_url('https://example.test/sub/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN')
        self.assertNotIn('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN',path_result)
        self.assertIn('/sub/***',path_result)

    def test_custom_headers_and_env_values_are_preserved(self):
        with patch.dict(os.environ, {'PANEL_TOKEN':'token-value'}):
            with patch('requests.Session.get', return_value=FakeResponse()) as get:
                result=Fetcher({'retries':0}).fetch({
                    'name':'private-panel',
                    'url':'https://panel.example/api/subscription?token=SECRET',
                    'headers':{'Authorization':'Bearer ${PANEL_TOKEN}','X-Client':'Android','X-App-Version':'4.7.1','User-Agent':'Happ/4.7.1'}
                })
        self.assertEqual(result.status,'ok')
        sent=get.call_args.kwargs['headers']
        self.assertEqual(sent['Authorization'],'Bearer token-value')
        self.assertEqual(sent['X-Client'],'Android')
        self.assertEqual(sent['X-App-Version'],'4.7.1')
        self.assertEqual(sent['User-Agent'],'Happ/4.7.1')
        self.assertNotIn('SECRET',result.url)
        self.assertNotIn('SECRET',result.final_url)

    def test_url_can_use_env_token_and_provider_headers_list(self):
        with patch.dict(os.environ, {'SUB_TOKEN':'url-secret'}):
            with patch('requests.Session.get', return_value=FakeResponse()) as get:
                result=Fetcher({'retries':0}).fetch({'name':'source','url':'https://panel.example/api?token=${SUB_TOKEN}',
                                                     'headers':{'User-Agent':['Happ/4.7.1','fallback']}})
        self.assertEqual(result.status,'ok')
        self.assertNotIn('url-secret',result.url)
        self.assertEqual(get.call_args.kwargs['headers']['User-Agent'],'Happ/4.7.1')

    def test_plain_txt_source_list_and_comments(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'sources.txt'
            src.write_text('# comment\n\nhttps://example.org/subscription\n; ignored\nhttps://example.org/subscription\n',encoding='utf-8')
            sources=load_sources(src)
        self.assertEqual(len(sources),1)
        self.assertEqual(sources[0]['url'],'https://example.org/subscription')
        self.assertEqual(sources[0]['name'],'example.org')

    def test_txt_source_headers_and_env_placeholder(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'sources.txt'
            src.write_text('https://panel.example/api/sub?key=secret | User-Agent: Happ/4.7.1/Android | Authorization: Bearer ${PANEL_TOKEN} | X-App-Version: 4.7.1\n',encoding='utf-8')
            sources=load_sources(src)
        self.assertEqual(len(sources),1)
        self.assertEqual(sources[0]['headers']['User-Agent'],'Happ/4.7.1/Android')
        self.assertEqual(sources[0]['headers']['Authorization'],'Bearer ${PANEL_TOKEN}')
        self.assertEqual(sources[0]['headers']['X-App-Version'],'4.7.1')
        self.assertNotIn('secret',sources[0]['name'])

    def test_sources_txt_accepts_full_url_environment_secret_reference(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / 'sources.txt'
            src.write_text('${WEP_SOURCE_URL}\n', encoding='utf-8')
            values = load_sources(src)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]['url'], '${WEP_SOURCE_URL}')
        self.assertEqual(values[0]['name'], 'secret-source-1')

    def test_txt_source_rejects_malformed_header_line(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'sources.txt'
            src.write_text('https://panel.example/sub | broken-header-without-colon\n',encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'header must use'):
                load_sources(src)


    def test_happ_compatibility_fallback_parses_client_only_provider_response(self):
        url = 'https://panel.example/bypass-hwid-lock-example-token-that-is-long-enough-to-redact?payload=opaque'
        landing = 'А вот эту ссылку надо вставлять в клиент, а не по ней переходить.'.encode('utf-8')
        xray = {
            'outbounds': [
                {'protocol': 'vless', 'tag': 'node-DE',
                 'settings': {'vnext': [{'address': 'node.example', 'port': 443,
                                         'users': [{'id': '11111111-1111-4111-8111-111111111111', 'encryption': 'none'}]}]},
                 'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {'serverName': 'node.example'}}},
                {'protocol': 'freedom', 'tag': 'direct'},
            ]
        }
        responses = [
            FakeResponse(content=landing, url=url),
            FakeResponse(content=json.dumps(xray).encode(), content_type='application/json', url=url),
        ]
        with patch.dict(os.environ, {'HAPP_HWID': ''}):
            with patch('requests.Session.get', side_effect=responses) as get:
                result = Fetcher({'retries': 0}).fetch({'name': 'wrapped-source', 'url': url})
        self.assertEqual(get.call_count, 2)
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.client_profile, 'happ-compat')
        self.assertIn('client-only page', result.compatibility_note)
        sent = get.call_args_list[1].kwargs['headers']
        self.assertEqual(sent['User-Agent'], 'Happ/3.23.0')
        self.assertEqual(sent['X-Device-OS'], 'Android')
        self.assertEqual(sent['X-Device-Model'], 'AeryxJSON-Parser')
        self.assertNotIn('X-HWID', sent)
        self.assertEqual(sent['X-Device-Locale'], 'ru_RU')
        self.assertIn('No HWID was fabricated or sent', result.compatibility_note)
        self.assertNotIn('opaque', result.url)
        self.assertNotIn('example-token-that-is-long-enough-to-redact', result.url)

    def test_happ_compatibility_fallback_uses_only_explicit_authorized_hwid(self):
        url = 'https://panel.example/bypass-hwid-lock-private-token-not-committed?payload=opaque'
        landing = 'А вот эту ссылку надо вставлять в клиент, а не по ней переходить.'.encode('utf-8')
        xray = {
            'outbounds': [{
                'protocol': 'vless', 'tag': 'node-DE',
                'settings': {'vnext': [{'address': 'node.example', 'port': 443,
                                        'users': [{'id': '11111111-1111-4111-8111-111111111111', 'encryption': 'none'}]}]},
                'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {'serverName': 'node.example'}},
            }]
        }
        responses = [
            FakeResponse(content=landing, url=url),
            FakeResponse(content=json.dumps(xray).encode(), content_type='application/json', url=url),
        ]
        with patch.dict(os.environ, {'HAPP_HWID': 'authorized-hwid-from-secret'}):
            with patch('requests.Session.get', side_effect=responses) as get:
                result = Fetcher({'retries': 0}).fetch({'name': 'wrapped-source', 'url': url})
        self.assertEqual(result.status, 'ok')
        sent = get.call_args_list[1].kwargs['headers']
        self.assertEqual(sent['User-Agent'], 'Happ/3.23.0')
        self.assertEqual(sent['X-HWID'], 'authorized-hwid-from-secret')
        self.assertIn('explicitly configured device ID was sent', result.compatibility_note)
        self.assertNotIn('private-token-not-committed', result.url)

    def test_happ_fallback_resolves_source_url_from_github_secret(self):
        url = 'https://panel.example/bypass-hwid-lock-url-from-secret-do-not-log?payload=opaque'
        landing = 'А вот эту ссылку надо вставлять в клиент, а не по ней переходить.'.encode('utf-8')
        xray = {
            'outbounds': [{
                'protocol': 'vless', 'tag': 'node-DE',
                'settings': {'vnext': [{'address': 'node.example', 'port': 443,
                                        'users': [{'id': '11111111-1111-4111-8111-111111111111', 'encryption': 'none'}]}]},
                'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {'serverName': 'node.example'}},
            }]
        }
        with patch.dict(os.environ, {'WEP_SOURCE_URL': url, 'HAPP_HWID': ''}):
            with patch('requests.Session.get', side_effect=[
                FakeResponse(content=landing, url=url),
                FakeResponse(content=json.dumps(xray).encode(), content_type='application/json', url=url),
            ]) as get:
                result = Fetcher({'retries': 0}).fetch({'name': 'secret-source', 'url': '${WEP_SOURCE_URL}'})
        self.assertEqual(get.call_count, 2)
        self.assertEqual(result.client_profile, 'happ-compat')
        self.assertEqual(result.status, 'ok')
        self.assertNotIn('url-from-secret-do-not-log', result.url)
        self.assertNotIn('url-from-secret-do-not-log', result.final_url)

    def test_client_compatibility_report_sanitizes_failure_for_unrecognized_response(self):
        url = 'https://panel.example/bypass-hwid-lock-another-long-token-value?payload=opaque'
        landing = 'А вот эту ссылку надо вставлять в клиент, а не по ней переходить.'.encode('utf-8')
        responses = [
            FakeResponse(content=landing, url=url),
            FakeResponse(content=b'No subscription payload', status_code=404, url=url),
        ]
        with patch.dict(os.environ, {'HAPP_HWID': ''}):
            with patch('requests.Session.get', side_effect=responses):
                result = Fetcher({'retries': 0}).fetch({'url': url})
        self.assertEqual(result.status_code, 404)
        self.assertIn('Happ-compatible retry returned no recognized proxy data', result.error)
        self.assertNotIn('another-long-token-value', result.error)
        self.assertNotIn('opaque', result.url)

    def test_ordinary_valid_subscription_is_not_fetched_twice(self):
        with patch('requests.Session.get', return_value=FakeResponse()) as get:
            result = Fetcher({'retries': 0}).fetch({'url': 'https://panel.example/sub'})
        self.assertEqual(result.status, 'ok')
        self.assertEqual(result.client_profile, 'default')
        self.assertEqual(get.call_count, 1)

    def test_local_file_source_load_and_fetch(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); src=root/'subscription.txt'
            src.write_text('vless://11111111-1111-4111-8111-111111111111@node.example:443',encoding='utf-8')
            yaml_path=root/'sources.yaml'
            yaml_path.write_text(f'sources:\n  - name: local\n    file: {src.as_posix()}\n',encoding='utf-8')
            sources=load_sources(yaml_path)
            self.assertEqual(len(sources),1)
            self.assertEqual(sources[0]['url'],'')
            result=Fetcher({}).fetch(sources[0])
            self.assertEqual(result.status,'ok')
            self.assertIn('vless://',result.content)

if __name__=='__main__': unittest.main()
