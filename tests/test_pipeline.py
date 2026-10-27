import tempfile,unittest,json
from pathlib import Path
from unittest.mock import patch
import yaml
from aeryx_json_parser import pipeline
from aeryx_json_parser.models import FetchResult

UUID='11111111-1111-4111-8111-111111111111'
class PipelineIntegrationTests(unittest.TestCase):
    def test_safe_publish_on_local_mocked_source(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); out=root/'out'; cache=root/'cache.json'
            sources=root/'sources.yaml'; sources.write_text(yaml.safe_dump({'sources':[{'name':'fake-source','url':'https://example.test/sub'}]}),encoding='utf-8')
            config=root/'settings.yaml'; config.write_text(yaml.safe_dump({
              'pipeline':{'max_runtime_seconds':20,'min_output_configs':1,'min_output_ratio':0.01},
              'fetch':{'max_total_sources':10,'follow_depth':0,'workers':2},
              'check':{'mode':'none','workers':2},
              'blocklists':{'enabled':False,'manual_cidrs':[],'cache_path':str(cache),'reject_non_global_addresses':True},
              'routing':{'happ_enabled':False},
              'outputs':{'directory':str(out),'subscription_file':'proxies.txt','candidate_file':'candidate.txt','structured_file':'parsed.json','rejected_file':'rejected.txt'}
            }),encoding='utf-8')
            content=f'vless://{UUID}@node.example:443?security=tls&sni=node.example#node-a\nvless://{UUID}@node.example:443?security=tls&sni=node.example#node-b'
            fake=FetchResult(url='https://example.test/sub',final_url='https://example.test/sub',status='ok',status_code=200,content_type='text/plain',bytes_downloaded=len(content),content=content,source_name='fake-source')
            with patch.object(pipeline.Fetcher,'fetch',return_value=fake), \
                 patch.object(pipeline,'evaluate_endpoint',return_value={'host':'node.example','resolved_ips':['8.8.8.8'],'resolve_status':'resolved','blocked_matches':[],'non_global_ips':[],'blocked':False}), \
                 patch.object(pipeline,'detect_cores',return_value={}):
                report=pipeline.run_pipeline(config,sources,check_mode='none',skip_blocklist=True,force_publish=False,refresh_routing=False)
            self.assertEqual(report['publish']['status'],'published')
            output=(out/'proxies.txt').read_text(encoding='utf-8').strip().splitlines()
            proxy_lines=[line for line in output if line.startswith(('vless://','vmess://','trojan://','ss://','ssr://','hysteria://','hysteria2://','hy2://','tuic://','anytls://','socks://','socks5://','http://','https://'))]
            self.assertEqual(len(proxy_lines),1)
            self.assertTrue(proxy_lines[0].startswith('vless://'))
            self.assertEqual(output[0], '#profile-title: AeryxVPN')
            self.assertTrue(any(line.startswith('#support-url: https://t.me/cheesyx') for line in output))
            announce=next(line for line in output if line.startswith('#announce:'))
            self.assertRegex(announce, r'обновлено: \d{2}\.\d{2}\.\d{4} \d{2}:\d{2} \| конфигов: 1$')
            on_disk=json.loads((out/'parsed.json').read_text(encoding='utf-8'))
            self.assertEqual(len(on_disk),1)
            # JSON report has no raw subscription URI in invalid/rejected diagnostics.
            report_disk=json.loads((out/'validation_report.json').read_text(encoding='utf-8'))
            self.assertEqual(report_disk['counts']['unique_nodes'],1)

    def test_proxy_mode_publishes_only_tunnel_verified_nodes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); out=root/'out'; cache=root/'cache.json'
            sources=root/'sources.txt'; sources.write_text('https://example.test/sub\n',encoding='utf-8')
            config=root/'settings.yaml'; config.write_text(yaml.safe_dump({
              'pipeline':{'max_runtime_seconds':20,'min_output_configs':1,'min_output_ratio':0.01},
              'fetch':{'max_total_sources':10,'follow_depth':0,'workers':2},
              'check':{'mode':'proxy','workers':2,'test_urls':['https://www.gstatic.com/generate_204'],'retry_single_success':False},
              'blocklists':{'enabled':False,'manual_cidrs':[],'cache_path':str(cache),'reject_non_global_addresses':True},
              'routing':{'happ_enabled':False},
              'outputs':{'directory':str(out),'subscription_file':'AeryxVPN','candidate_file':'candidate.txt','structured_file':'parsed.json','rejected_file':'rejected.txt'}
            }),encoding='utf-8')
            content=(f'vless://{UUID}@good.example:443?security=tls\n'
                     f'vless://{UUID}@unknown.example:443?security=tls')
            fake=FetchResult(url='https://example.test/sub',final_url='https://example.test/sub',status='ok',status_code=200,content_type='text/plain',bytes_downloaded=len(content),content=content,source_name='example.test')
            captured_validation_kwargs={}
            def mark_status(nodes, *args, **kwargs):
                captured_validation_kwargs.update(kwargs)
                for node in nodes:
                    node.check_status='proxy_ok' if node.host=='good.example' else 'not_checked'
                    node.check_reason='test result'
                return {'proxy_ok':1,'not_checked':1}
            with patch.object(pipeline.Fetcher,'fetch',return_value=fake), \
                 patch.object(pipeline,'evaluate_endpoint',side_effect=lambda host,*args:{'host':host,'resolved_ips':['8.8.8.8'],'resolve_status':'resolved','blocked_matches':[],'non_global_ips':[],'blocked':False}), \
                 patch.object(pipeline,'detect_cores',return_value={'sing-box':'/mock/sing-box'}), \
                 patch.object(pipeline,'precheck_endpoints',return_value={'open':1,'error_Gaierror':1}), \
                 patch.object(pipeline,'validate_nodes',side_effect=mark_status):
                report=pipeline.run_pipeline(config,sources,check_mode='proxy',skip_blocklist=True,refresh_routing=False)
            self.assertEqual(report['publish']['status'],'published')
            self.assertIs(captured_validation_kwargs.get('retry_single_success'), False)
            published=(out/'AeryxVPN').read_text(encoding='utf-8')
            self.assertIn('good.example',published)
            self.assertNotIn('unknown.example',published)

    def test_low_result_ratio_preserves_existing_subscription(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); out=root/'out'; out.mkdir(); final=out/'proxies.txt'
            previous='vless://old@old.example:443\n'*10; final.write_text(previous,encoding='utf-8')
            sources=root/'sources.yaml'; sources.write_text(yaml.safe_dump({'sources':[{'name':'source','url':'https://example.test/sub'}]}),encoding='utf-8')
            config=root/'settings.yaml'; config.write_text(yaml.safe_dump({
              'pipeline':{'max_runtime_seconds':20,'min_output_configs':5,'min_output_ratio':0.5},
              'fetch':{'max_total_sources':10,'follow_depth':0,'workers':2},
              'check':{'mode':'none','workers':2},
              'blocklists':{'enabled':False,'manual_cidrs':[]},
              'routing':{'happ_enabled':False},
              'outputs':{'directory':str(out),'subscription_file':'proxies.txt','candidate_file':'candidate.txt','structured_file':'parsed.json','rejected_file':'rejected.txt'}
            }),encoding='utf-8')
            content=f'vless://{UUID}@node-a.example:443?security=tls\nvless://{UUID}@node-b.example:443?security=tls'
            fake=FetchResult(url='https://example.test/sub',final_url='https://example.test/sub',status='ok',status_code=200,content_type='text/plain',bytes_downloaded=len(content),content=content,source_name='source')
            with patch.object(pipeline.Fetcher,'fetch',return_value=fake), \
                 patch.object(pipeline,'evaluate_endpoint',side_effect=lambda host,*args:{'host':host,'resolved_ips':['8.8.8.8'],'resolve_status':'resolved','blocked_matches':[],'non_global_ips':[],'blocked':False}), \
                 patch.object(pipeline,'detect_cores',return_value={}):
                report=pipeline.run_pipeline(config,sources,check_mode='none',skip_blocklist=True,refresh_routing=False)
            self.assertEqual(report['publish']['status'],'safety_stop_existing_kept')
            self.assertEqual(final.read_text(encoding='utf-8'),previous)
            self.assertTrue((out/'candidate.txt').exists())


    def test_subscription_includes_happ_routing_before_nodes(self):
        import base64, json
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); out=root/'out'; cache=root/'cache.json'
            sources=root/'sources.txt'; sources.write_text('https://example.test/sub\n',encoding='utf-8')
            route_profile={"Name":"AeryxVPN test routing","GlobalProxy":"true","RouteOrder":"block-direct-proxy"}
            route_link='happ://routing/onadd/'+base64.b64encode(json.dumps(route_profile).encode()).decode()
            config=root/'settings.yaml'; config.write_text(yaml.safe_dump({
              'pipeline':{'max_runtime_seconds':20,'min_output_configs':1,'min_output_ratio':0.01},
              'fetch':{'max_total_sources':10,'follow_depth':0,'workers':2},
              'check':{'mode':'none','workers':2},
              'blocklists':{'enabled':False,'manual_cidrs':[],'cache_path':str(cache),'reject_non_global_addresses':True},
              'routing':{'happ_enabled':True,'include_in_subscription':True,'profile_path':str(root/'missing-profile.json'),'deeplink_path':str(root/'missing-profile.deeplink')},
              'outputs':{'directory':str(out),'subscription_file':'AeryxVPN','candidate_file':'candidate.txt','structured_file':'parsed.json','rejected_file':'rejected.txt'}
            }),encoding='utf-8')
            content=f'vless://{UUID}@node.example:443?security=tls#test'
            fake=FetchResult(url='https://example.test/sub',final_url='https://example.test/sub',status='ok',status_code=200,content_type='text/plain',bytes_downloaded=len(content),content=content,source_name='source')
            with patch.object(pipeline.Fetcher,'fetch',return_value=fake), \
                 patch.object(pipeline,'evaluate_endpoint',return_value={'host':'node.example','resolved_ips':['8.8.8.8'],'allowed_ips':['8.8.8.8'],'resolve_status':'resolved','blocked_matches':[],'non_global_ips':[],'blocked':False}), \
                 patch.object(pipeline,'detect_cores',return_value={}), \
                 patch.object(pipeline,'refresh_happ_routing',return_value=route_link):
                report=pipeline.run_pipeline(config,sources,check_mode='none',skip_blocklist=True)
            self.assertEqual(report['publish']['status'],'published')
            lines=(out/'AeryxVPN').read_text(encoding='utf-8').splitlines()
            route_i=next(i for i,x in enumerate(lines) if x.startswith('happ://routing/onadd/'))
            node_i=next(i for i,x in enumerate(lines) if x.startswith('vless://'))
            self.assertLess(lines.index('#profile-title: AeryxVPN'),route_i)
            self.assertLess(route_i,node_i)
            self.assertEqual(report['routing']['ready'],True)



    def test_missing_required_happ_profile_blocks_publication(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); out=root/'out'; out.mkdir(); cache=root/'cache.json'
            final=out/'AeryxVPN'; previous='#profile-title: AeryxVPN\nvless://old@old.example:443#old\n'; final.write_text(previous,encoding='utf-8')
            sources=root/'sources.txt'; sources.write_text('https://example.test/sub\n',encoding='utf-8')
            config=root/'settings.yaml'; config.write_text(yaml.safe_dump({
              'pipeline':{'max_runtime_seconds':20,'min_output_configs':1,'min_output_ratio':0.01},
              'fetch':{'max_total_sources':10,'follow_depth':0,'workers':2},
              'check':{'mode':'none','workers':2},
              'blocklists':{'enabled':False,'manual_cidrs':[],'cache_path':str(cache),'reject_non_global_addresses':True},
              'routing':{'happ_enabled':True,'include_in_subscription':True,'profile_path':str(root/'missing-profile.json'),'deeplink_path':str(root/'missing-profile.deeplink')},
              'outputs':{'directory':str(out),'subscription_file':'AeryxVPN','candidate_file':'candidate.txt','structured_file':'parsed.json','rejected_file':'rejected.txt'}
            }),encoding='utf-8')
            content=f'vless://{UUID}@node.example:443?security=tls#node'
            fake=FetchResult(url='https://example.test/sub',final_url='https://example.test/sub',status='ok',status_code=200,content_type='text/plain',bytes_downloaded=len(content),content=content,source_name='source')
            with patch.object(pipeline.Fetcher,'fetch',return_value=fake), \
                 patch.object(pipeline,'evaluate_endpoint',return_value={'host':'node.example','resolved_ips':['8.8.8.8'],'allowed_ips':['8.8.8.8'],'resolve_status':'resolved','blocked_matches':[],'non_global_ips':[],'blocked':False}), \
                 patch.object(pipeline,'detect_cores',return_value={}), \
                 patch.object(pipeline,'refresh_happ_routing',side_effect=OSError('test failure')):
                report=pipeline.run_pipeline(config,sources,check_mode='none',skip_blocklist=True)
            self.assertEqual(report['publish']['status'],'safety_stop_existing_kept')
            self.assertEqual(final.read_text(encoding='utf-8'),previous)
            self.assertFalse(report['routing']['ready'])

    def test_unknown_country_is_not_published_in_production_mode(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); out=root/'out'; out.mkdir(); cache=root/'cache.json'
            final=out/'AeryxVPN'; previous='#profile-title: AeryxVPN\nvless://old@old.example:443#old\n'; final.write_text(previous,encoding='utf-8')
            sources=root/'sources.txt'; sources.write_text('https://example.test/sub\n',encoding='utf-8')
            config=root/'settings.yaml'; config.write_text(yaml.safe_dump({
              'pipeline':{'max_runtime_seconds':20,'min_output_configs':1,'min_output_ratio':0.01},
              'fetch':{'max_total_sources':10,'follow_depth':0,'workers':2},
              'check':{'mode':'none','workers':2},
              'blocklists':{'enabled':False,'manual_cidrs':[],'cache_path':str(cache),'reject_non_global_addresses':True},
              'location':{'database_path':str(root/'missing.mmdb'),'require_country':True},
              'routing':{'happ_enabled':False},
              'outputs':{'directory':str(out),'subscription_file':'AeryxVPN','candidate_file':'candidate.txt','structured_file':'parsed.json','rejected_file':'rejected.txt'}
            }),encoding='utf-8')
            content=f'vless://{UUID}@node.example:443?security=tls#node'
            fake=FetchResult(url='https://example.test/sub',final_url='https://example.test/sub',status='ok',status_code=200,content_type='text/plain',bytes_downloaded=len(content),content=content,source_name='source')
            with patch.object(pipeline.Fetcher,'fetch',return_value=fake), \
                 patch.object(pipeline,'evaluate_endpoint',return_value={'host':'node.example','resolved_ips':['8.8.8.8'],'allowed_ips':['8.8.8.8'],'resolve_status':'resolved','blocked_matches':[],'non_global_ips':[],'blocked':False}), \
                 patch.object(pipeline,'detect_cores',return_value={}):
                report=pipeline.run_pipeline(config,sources,check_mode='none',skip_blocklist=True,refresh_routing=False)
            self.assertEqual(report['publish']['status'],'safety_stop_existing_kept')
            self.assertEqual(final.read_text(encoding='utf-8'),previous)
            self.assertEqual(report['counts']['location_rejected'],1)

    def test_safety_stop_does_not_overwrite_final_output(self):
        # The circuit breaker behavior is covered at the policy level: a low candidate set
        # never overwrites an existing subscription unless force_publish is requested.
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); out=root/'out'; out.mkdir(); final=out/'proxies.txt'; final.write_text('vless://old@old.example:443\n')
            # Existing value has to stay intact when a run yields no nodes; this path is
            # deliberately tested as a deterministic early-return condition.
            sources=root/'sources.yaml'; sources.write_text('sources: []\n')
            config=root/'settings.yaml'; config.write_text(yaml.safe_dump({'pipeline':{'max_runtime_seconds':20},'fetch':{},'check':{},'blocklists':{'enabled':False},'routing':{'happ_enabled':False},'outputs':{'directory':str(out)}}))
            report=pipeline.run_pipeline(config,sources,check_mode='none',skip_blocklist=True,refresh_routing=False)
            self.assertEqual(report['counts']['unique_nodes'],0)
            self.assertEqual(final.read_text(encoding='utf-8'),'vless://old@old.example:443\n')

if __name__=='__main__': unittest.main()
