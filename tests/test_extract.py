import base64
import unittest
from aeryx_json_parser.extract import decode_layers, extract_uri_strings, extract_html_links
from aeryx_json_parser.models import parse_endpoint
from aeryx_json_parser.adapters import extract_structured_nodes, clash_proxy_to_uri

UUID="11111111-1111-4111-8111-111111111111"

class ExtractTests(unittest.TestCase):
    def test_plain_links_and_fragment_dedupe_is_elsewhere(self):
        text=f"vless://{UUID}@example.org:443?security=tls#one\n\ntrojan://secret@example.net:443#two"
        values=extract_uri_strings(text)
        self.assertEqual(len(values),2)
        self.assertTrue(values[0].startswith("vless://"))
        self.assertNotIn('https://panel.example/api/subscription?token=secret', extract_uri_strings('https://panel.example/api/subscription?token=secret'))
        self.assertIn('http://proxy.example:8080', extract_uri_strings('http://proxy.example:8080'))

    def test_base64_subscription_is_decoded(self):
        raw=f"vless://{UUID}@example.org:443?security=tls#hello\nss://YWVzLTI1Ni1nY206cGFzcw@example.net:8443#ss"
        encoded=base64.b64encode(raw.encode()).decode()
        values=extract_uri_strings(encoded)
        self.assertEqual(len(values),2)
        self.assertTrue(any(x.startswith("ss://") for x in values))

    def test_vmess_endpoint_payload_is_validated(self):
        import json
        payload={"v":"2","ps":"n","add":"node.example","port":"8443","id":UUID,"aid":"0","net":"tcp","tls":"tls"}
        uri="vmess://"+base64.b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        self.assertEqual(parse_endpoint(uri),("node.example",8443,"vmess"))

    def test_ss_endpoint_legacy_and_sip002(self):
        self.assertEqual(parse_endpoint("ss://YWVzLTI1Ni1nY206cGFzcw@example.org:8388#node")[:2],("example.org",8388))
        legacy="ss://"+base64.urlsafe_b64encode(b"aes-256-gcm:pass@example.org:8388").decode().rstrip("=")
        self.assertEqual(parse_endpoint(legacy)[:2],("example.org",8388))

    def test_bad_port_rejected(self):
        with self.assertRaises(ValueError): parse_endpoint(f"vless://{UUID}@example.org:70000#bad")

    def test_html_interface_discovers_same_host_subscription_endpoints(self):
        text='<a href="/dashboard">Home</a><a href="/api/subscription?format=clash">Get config</a><a href="https://other.example/sub">other</a>'
        got=extract_html_links(text,"https://panel.example/portal")
        self.assertIn("https://panel.example/api/subscription?format=clash",got)
        self.assertNotIn("https://panel.example/dashboard",got)
        # Cross-host candidates can be extracted here; Fetcher enforces same-host for HTML crawl.
        self.assertIn("https://other.example/sub",got)

    def test_clash_vless_websocket_and_shadowsocks(self):
        y='''proxies:\n  - name: Test VLESS\n    type: vless\n    server: node.example\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    tls: true\n    servername: example.org\n    network: ws\n    ws-opts:\n      path: /proxy\n      headers:\n        Host: cdn.example.org\n  - name: Test SS\n    type: ss\n    server: ss.example\n    port: 8388\n    cipher: aes-256-gcm\n    password: hello\n'''
        links,providers=extract_structured_nodes(y)
        self.assertEqual(len(links),2)
        self.assertEqual(providers,[])
        self.assertTrue(any(x.startswith("vless://") and "cdn.example.org" in x for x in links))
        self.assertTrue(any(x.startswith("ss://") for x in links))

    def test_xray_json_vless_outbound_with_reality(self):
        import json
        obj={"outbounds":[{"protocol":"vless","tag":"xray-node","settings":{"vnext":[{"address":"node.example","port":443,"users":[{"id":UUID,"encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.org","fingerprint":"chrome","publicKey":"abc","shortId":"12ab"}}},{"protocol":"freedom","tag":"direct"}]}
        links,_=extract_structured_nodes(json.dumps(obj))
        self.assertEqual(len(links),1)
        self.assertTrue(links[0].startswith(f'vless://{UUID}@node.example:443'))
        self.assertIn('security=reality',links[0])
        self.assertIn('pbk=abc',links[0])

    def test_sip008_json_export(self):
        import json
        obj=[{"server":"ss.example","server_port":8388,"method":"aes-256-gcm","password":"secret","remarks":"sip008-node"}]
        links,_=extract_structured_nodes(json.dumps(obj))
        self.assertEqual(len(links),1)
        self.assertTrue(links[0].startswith('ss://'))
        self.assertIn('sip008-node',links[0])

    def test_singbox_outbounds(self):
        import json
        obj={"outbounds":[{"type":"hysteria2","tag":"H2","server":"h2.example","server_port":443,"password":"pass","tls":{"enabled":True,"server_name":"h2.example"}},
                          {"type":"direct","tag":"direct"}]}
        links,_=extract_structured_nodes(json.dumps(obj))
        self.assertEqual(len(links),1)
        self.assertTrue(links[0].startswith("hysteria2://"))


    def test_base64_wrapped_xray_json_is_parsed_as_structured_config(self):
        import json, base64
        from aeryx_json_parser.pipeline import _parse_document
        obj = {
            "outbounds": [{
                "protocol": "vless", "tag": "wrapped-node",
                "settings": {"vnext": [{"address": "node.example", "port": 443,
                                          "users": [{"id": UUID, "encryption": "none"}]}]},
                "streamSettings": {"network": "tcp", "security": "reality",
                                   "realitySettings": {"serverName": "www.example.org", "publicKey": "pubkey", "shortId": "a1"}},
            }, {"protocol": "freedom", "tag": "direct"}],
        }
        wrapped = base64.b64encode(json.dumps(obj).encode()).decode()
        links, providers = _parse_document(wrapped)
        self.assertEqual(len(links), 1)
        self.assertTrue(links[0].startswith(f"vless://{UUID}@node.example:443"))
        self.assertIn("security=reality", links[0])
        self.assertEqual(providers, [])

    def test_uri_redact_fragment_not_in_identity(self):
        from aeryx_json_parser.models import ProxyNode
        a=ProxyNode(uri=f"vless://{UUID}@example.org:443?security=tls#a",scheme="vless",host="example.org",port=443)
        b=ProxyNode(uri=f"vless://{UUID}@example.org:443?security=tls#b",scheme="vless",host="example.org",port=443)
        self.assertEqual(a.identity,b.identity)
        c=ProxyNode(uri=f'vless://{UUID}@example.org:443?type=ws&security=tls#a',scheme='vless',host='example.org',port=443)
        d=ProxyNode(uri=f'vless://{UUID}@example.org:443?security=tls&type=ws#b',scheme='vless',host='example.org',port=443)
        self.assertEqual(c.identity,d.identity)

if __name__=="__main__": unittest.main()
