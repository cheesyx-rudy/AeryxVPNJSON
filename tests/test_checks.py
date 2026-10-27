import base64,json,unittest
from aeryx_json_parser.checks import (build_singbox_outbound,build_xray_config,_request_through_socks,PROBE_URLS)

UUID='11111111-1111-4111-8111-111111111111'
class CheckConfigTests(unittest.TestCase):
    def test_vless_reality_outbound(self):
        uri=f'vless://{UUID}@node.example:443?encryption=none&security=reality&pbk=publickey&sid=abcd&sni=www.example.org&fp=chrome&type=tcp#n'
        out=build_singbox_outbound(uri)
        self.assertEqual(out['type'],'vless')
        self.assertEqual(out['tls']['reality']['public_key'],'publickey')
        self.assertEqual(out['tls']['server_name'],'www.example.org')
    def test_vless_ws_outbound(self):
        uri=f'vless://{UUID}@node.example:443?security=tls&sni=cdn.example.org&type=ws&path=%2Fws&host=cdn.example.org#n'
        out=build_singbox_outbound(uri)
        self.assertEqual(out['transport']['type'],'ws')
        self.assertEqual(out['transport']['path'],'/ws')
        self.assertEqual(out['transport']['headers']['Host'],'cdn.example.org')
    def test_hysteria2_outbound(self):
        out=build_singbox_outbound('hysteria2://secret@node.example:443?sni=cdn.example.org&obfs=salamander&obfs-password=pass#n')
        self.assertEqual(out['type'],'hysteria2')
        self.assertEqual(out['obfs']['password'],'pass')
        self.assertTrue(out['tls']['enabled'])
    def test_hysteria_v1_uses_auth_str(self):
        out=build_singbox_outbound('hysteria://secret@node.example:443?sni=cdn.example.org#n')
        self.assertEqual(out['type'],'hysteria')
        self.assertEqual(out['auth_str'],'secret')
        self.assertNotIn('password',out)

    def test_xray_config_has_real_socks_inbound(self):
        out=build_xray_config(f'vless://{UUID}@node.example:443?security=tls&sni=cdn.example.org&type=ws&path=%2Fws&host=cdn.example.org#n',1080)
        self.assertEqual(out['inbounds'][0]['port'],1080)
        self.assertEqual(out['outbounds'][0]['streamSettings']['wsSettings']['path'],'/ws')
    def test_unsupported_xray_protocol_fails_explicitly(self):
        with self.assertRaisesRegex(ValueError,'does not support'):
            build_xray_config('hysteria2://secret@node.example:443?sni=node.example',1080)


class _FakeResponse:
    def __init__(self, status_code, body=b""):
        self.status_code=status_code
        self._body=body if isinstance(body,bytes) else str(body).encode()
        self.closed=False
    def __enter__(self): return self
    def __exit__(self,*args): self.close(); return False
    def iter_content(self,chunk_size=256):
        for i in range(0,len(self._body),chunk_size): yield self._body[i:i+chunk_size]
    def close(self): self.closed=True

class _FakeSession:
    def __init__(self,responses):
        self.responses=responses; self.trust_env=True; self.proxies={}
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def get(self,url,**kwargs):
        self.last_kwargs=kwargs
        value=self.responses.get(url)
        if isinstance(value,list):
            return value.pop(0) if value else _FakeResponse(599)
        if value is None: return _FakeResponse(599)
        return value

class StrictProbePolicyTests(unittest.TestCase):
    def run_probe(self,responses,targets=PROBE_URLS,**kwargs):
        from unittest.mock import patch
        session=_FakeSession(responses)
        with patch('aeryx_json_parser.checks.requests.Session',return_value=session):
            return _request_through_socks(12345,targets=targets,**kwargs)

    def test_single_exact_success_is_retried_and_included_at_lower_confidence(self):
        from unittest.mock import patch
        calls=[]
        def fake_probe(port,url,accepted,deadline=None):
            calls.append(url)
            if url == PROBE_URLS[0][0]:
                return 'www.gstatic.com', '204:ok', True
            return (url.split('/')[2]), '403:status_403', False
        with patch('aeryx_json_parser.checks._probe_one_through_socks', side_effect=fake_probe):
            ok,reason=_request_through_socks(12345,targets=PROBE_URLS)
        self.assertTrue(ok)
        self.assertIn('verified_repeat:',reason)
        self.assertEqual(calls.count(PROBE_URLS[0][0]),2)

    def test_single_success_once_is_accepted_as_low_confidence_not_called_high_confidence(self):
        from unittest.mock import patch
        call_counts={}
        def fake_probe(port,url,accepted,deadline=None):
            call_counts[url]=call_counts.get(url,0)+1
            if url == PROBE_URLS[0][0] and call_counts[url] == 1:
                return 'www.gstatic.com', '204:ok', True
            return (url.split('/')[2]), '403:status_403', False
        with patch('aeryx_json_parser.checks._probe_one_through_socks', side_effect=fake_probe):
            ok,reason=_request_through_socks(12345,targets=PROBE_URLS)
        self.assertTrue(ok)
        self.assertIn('verified_single:',reason)
        self.assertIn('low_confidence_but_tunnel_proven',reason)

    def test_retry_single_success_setting_disables_second_request(self):
        from unittest.mock import patch
        calls=[]
        def fake_probe(port,url,accepted,deadline=None):
            calls.append(url)
            if url == PROBE_URLS[0][0]:
                return 'www.gstatic.com', '204:ok', True
            return (url.split('/')[2]), '403:status_403', False
        with patch('aeryx_json_parser.checks._probe_one_through_socks', side_effect=fake_probe):
            ok,reason=_request_through_socks(12345,targets=PROBE_URLS,retry_single_success=False)
        self.assertTrue(ok)
        self.assertIn('repeat=disabled_or_no_budget', reason)
        self.assertEqual(calls.count(PROBE_URLS[0][0]), 1)

    def test_vote_score_is_a_literal_stage_majority(self):
        from aeryx_json_parser.checks import _record_validation_votes
        from aeryx_json_parser.models import ProxyNode
        node=ProxyNode(uri='vless://11111111-1111-4111-8111-111111111111@x.example:443',
                       scheme='vless',host='x.example',port=443,structural_ok=True,tcp_precheck='refused')
        score=_record_validation_votes(node,'verified_single:successes=1/5; repeat=failed',PROBE_URLS)
        self.assertEqual(score,2)  # 4 positive stages, 2 negative stages
        self.assertGreater(score,0)
        self.assertEqual(node.validation_confidence,'low')

    def test_two_exact_successes_from_independent_providers_pass(self):
        responses={
            PROBE_URLS[0][0]:_FakeResponse(204),
            PROBE_URLS[1][0]:_FakeResponse(204),
            PROBE_URLS[2][0]:_FakeResponse(200,b"portal content"),
        }
        ok,reason=self.run_probe(responses)
        self.assertTrue(ok)
        self.assertIn('providers=cloudflare,google',reason)
        self.assertIn('verified_multi:successes=2/5',reason)

    def test_msft_probe_requires_exact_expected_body(self):
        responses={
            PROBE_URLS[0][0]:_FakeResponse(403,b"Forbidden"),
            PROBE_URLS[1][0]:_FakeResponse(500,b"error"),
            PROBE_URLS[2][0]:_FakeResponse(200,b"fake portal"),
        }
        ok,reason=self.run_probe(responses)
        self.assertFalse(ok)
        self.assertIn('unexpected_msft_payload',reason)

    def test_any_4xx_never_counts_as_success(self):
        responses={url:_FakeResponse(403,b"Forbidden") for url,_ in PROBE_URLS}
        ok,reason=self.run_probe(responses)
        self.assertFalse(ok)
        self.assertIn('status_403',reason)

    def test_4xx_still_fails_if_a_custom_target_has_broad_accepted_set(self):
        target=[('https://health.example.com/check',set(range(200,500)))]
        ok,reason=self.run_probe({target[0][0]:_FakeResponse(404,b"Not Found")},targets=target,minimum_successes=1,require_independent_providers=False)
        self.assertFalse(ok)
        self.assertIn('status_404',reason)

    def test_redirect_does_not_count_as_health(self):
        target=[('https://health.example.com/check',{200})]
        ok,reason=self.run_probe({target[0][0]:_FakeResponse(302,b"login portal")},targets=target,minimum_successes=1,require_independent_providers=False)
        self.assertFalse(ok)
        self.assertIn('status_302',reason)

    def test_generate_204_must_not_have_a_response_body(self):
        from aeryx_json_parser.checks import _probe_response_ok
        self.assertEqual(_probe_response_ok('https://www.gstatic.com/generate_204',204,b'',{204}), (True,'expected_204'))
        self.assertEqual(_probe_response_ok('https://www.gstatic.com/generate_204',204,b'portal',{204}), (False,'invalid_generate_204_response'))

    def test_ipify_requires_a_valid_public_ip_payload(self):
        url='https://api.ipify.org'
        from aeryx_json_parser.checks import _probe_response_ok
        self.assertEqual(_probe_response_ok(url,200,b'1.1.1.1\n',{200}), (True,'expected_public_ip'))
        self.assertEqual(_probe_response_ok(url,200,b'not an ip',{200}), (False,'invalid_public_ip_payload'))

    def test_amazon_checkip_requires_a_valid_public_ip_payload(self):
        url='https://checkip.amazonaws.com'
        from aeryx_json_parser.checks import _probe_response_ok
        self.assertEqual(_probe_response_ok(url,200,b'8.8.8.8\n',{200}), (True,'expected_public_ip'))
        self.assertEqual(_probe_response_ok(url,200,b'<html>login</html>',{200}), (False,'invalid_public_ip_payload'))

    def test_same_provider_is_retried_but_not_mislabeled_high_confidence(self):
        targets=[('https://a.example.com/health',{200}),('https://b.example.com/health',{200}),('https://status.other.net/health',{200})]
        responses={targets[0][0]:_FakeResponse(200),targets[1][0]:_FakeResponse(200),targets[2][0]:_FakeResponse(503)}
        ok,reason=self.run_probe(responses,targets=targets)
        self.assertTrue(ok)
        self.assertIn('verified_repeat:',reason)
        self.assertIn('independent_providers=1',reason)
        self.assertIn('quorum=not_met',reason)

class ValidationProgressTests(unittest.TestCase):
    def test_progress_reports_each_completed_node_incrementally(self):
        from aeryx_json_parser.checks import validate_nodes
        from aeryx_json_parser.models import ProxyNode
        nodes = [
            ProxyNode(uri=f'vless://{UUID}@node{i}.example:443',scheme='vless',host=f'node{i}.example',port=443)
            for i in range(3)
        ]
        progress=[]
        counts=validate_nodes(nodes,{},'none',workers=2,progress_callback=lambda done,total,statuses: progress.append((done,total)))
        self.assertEqual(counts,{'not_checked':3})
        self.assertEqual([x[0] for x in progress],[1,2,3])
        self.assertTrue(all(x[1] == 3 for x in progress))

if __name__=='__main__': unittest.main()
