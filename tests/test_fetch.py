import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aeryx_json_parser.fetch import Fetcher, redact_url
from aeryx_json_parser.models import FetchResult
from aeryx_json_parser.pipeline import load_sources


class FakeResponse:
    status_code = 200
    url = 'https://panel.example/api/subscription?token=SECRET'
    headers = {'Content-Type': 'text/plain; charset=utf-8'}

    def __enter__(self): return self
    def __exit__(self, *args): return False
    def raise_for_status(self): return None
    def iter_content(self, chunk_size=65536):
        yield b'vless://11111111-1111-4111-8111-111111111111@node.example:443#node\n'


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

    def test_txt_source_rejects_malformed_header_line(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'sources.txt'
            src.write_text('https://panel.example/sub | broken-header-without-colon\n',encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'header must use'):
                load_sources(src)

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
