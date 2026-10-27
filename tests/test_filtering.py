import tempfile, unittest, ipaddress
from pathlib import Path
from unittest.mock import patch
from aeryx_json_parser.filtering import parse_networks, NetworkIndex, evaluate_endpoint, load_blocklists

class FilterTests(unittest.TestCase):
    def test_ipv4_ipv6_and_cidr_parser(self):
        nets=parse_networks('# comment\n8.8.8.8\n1.1.1.0/24\n2606:4700::/32\ninvalid\n')
        self.assertEqual({x.with_prefixlen for x in nets},{'8.8.8.8/32','1.1.1.0/24','2606:4700::/32'})
        self.assertEqual(parse_networks('0.0.0.0/0\n::/0'), [])
    def test_prefix_index_matches_both_families(self):
        ix=NetworkIndex(parse_networks('8.8.8.0/24\n2606:4700::/32\n'))
        self.assertEqual(ix.match('8.8.8.8'),'8.8.8.0/24')
        self.assertEqual(ix.match('9.9.9.9'),None)
        self.assertEqual(ix.match('2606:4700::1111'),'2606:4700::/32')
    def test_custom_feed_parser_handles_json_like_lines(self):
        nets=parse_networks('"cidr": "1.2.3.0/24"\nip=2001:db8::/32\n')
        self.assertEqual({x.with_prefixlen for x in nets},{'1.2.3.0/24','2001:db8::/32'})

    def test_external_feed_broad_ranges_are_ignored_but_precise_ranges_kept(self):
        with tempfile.TemporaryDirectory() as td:
            feeds=[{"name":"test","url":"https://feed.example/list","format":"text"}]
            fake_info={"name":"test","url":"https://feed.example/list","status":"ok","network_count":2,"bytes":32,"elapsed_ms":1,"sha256":"x"}
            with patch('aeryx_json_parser.filtering._feed_get', return_value=([ipaddress.ip_network('203.0.112.0/24'),ipaddress.ip_network('198.51.0.0/16')],fake_info)):
                nets,report=load_blocklists({"enabled":True,"feeds":feeds,"cache_hours":72,"max_feed_bytes":1000,
                    "minimum_external_prefix_v4":24,"minimum_external_prefix_v6":48},Path(td)/'cache.json')
        self.assertEqual({n.with_prefixlen for n in nets},{'203.0.112.0/24'})
        self.assertEqual(report['raw_network_count'],2)
        self.assertEqual(report['ignored_broad_prefix_count'],1)

    def test_mixed_dns_addresses_are_not_rejected_if_one_is_unblocked(self):
        index=NetworkIndex(parse_networks('1.2.3.0/24'))
        with patch('aeryx_json_parser.filtering.resolve_ips', return_value=(['1.2.3.7','8.8.8.8'],'resolved')):
            result=evaluate_endpoint('multi.example',index,{'reject_non_global_addresses':True})
        self.assertFalse(result['blocked'])
        self.assertEqual(len(result['blocked_matches']),1)

if __name__=='__main__': unittest.main()
