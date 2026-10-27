import base64
import json
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from aeryx_json_parser.geolocation import Country, CountryResolver, country_from_label, flag_for_code, set_node_name
from aeryx_json_parser.models import ProxyNode
from aeryx_json_parser.pipeline import _parse_link


class FakeReader:
    def get(self, ip):
        return {"country": {"iso_code": "LK", "names": {"en": "Sri Lanka"}}} if ip == "8.8.8.8" else {}

    def close(self):
        pass


class GeolocationTests(unittest.TestCase):
    def test_database_ip_lookup_beats_label(self):
        resolver = CountryResolver()
        resolver.reader = FakeReader()
        result = resolver.resolve(["8.8.8.8"], ["Germany node"], "node.example")
        self.assertEqual((result.code, result.name, result.method), ("LK", "Sri Lanka", "ip"))

    def test_country_label_can_fallback_to_existing_flag(self):
        result = country_from_label("🇱🇰 Sri Lanka • old group")
        self.assertIsNotNone(result)
        self.assertEqual((result.code, result.name), ("LK", "Sri Lanka"))


    def test_country_code_in_existing_label_is_a_fallback(self):
        result = country_from_label("SG-01 | Legacy node")
        self.assertIsNotNone(result)
        self.assertEqual((result.code, result.name), ("SG", "Singapore"))

    def test_country_tld_is_last_resort(self):
        result = CountryResolver().resolve([], [], "host.example.de")
        self.assertEqual((result.code, result.name, result.method), ("DE", "Germany", "hostname_tld"))


    def test_vmess_embedded_ps_is_rewritten(self):
        original = {"v":"2", "ps":"old", "add":"node.example", "port":"443", "id":"uuid", "aid":"0", "net":"tcp", "tls":"tls"}
        payload = base64.urlsafe_b64encode(json.dumps(original).encode()).decode().rstrip("=")
        node = ProxyNode(uri="vmess://"+payload, scheme="vmess", host="node.example", port=443, name="")
        label = set_node_name(node, Country("LK", "Sri Lanka", "ip", "8.8.8.8"))
        encoded = urlsplit(node.uri).netloc + urlsplit(node.uri).path
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        self.assertEqual(json.loads(decoded)["ps"], label)

    def test_ssr_embedded_remarks_are_rewritten(self):
        raw = "node.example:443:origin:aes-256-cfb:plain:password/?remarks=old&obfsparam=example.com"
        payload = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        node = ProxyNode(uri="ssr://"+payload, scheme="ssr", host="node.example", port=443, name="")
        label = set_node_name(node, Country("GD", "Grenada", "ip", "8.8.8.8"))
        encoded = urlsplit(node.uri).netloc + urlsplit(node.uri).path
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()
        params = parse_qs(decoded.partition("/?")[2])
        remarks = base64.urlsafe_b64decode(params["remarks"][0] + "=" * (-len(params["remarks"][0]) % 4)).decode()
        self.assertEqual(remarks, label)


    def test_embedded_vmess_and_ssr_names_are_read_for_fallback(self):
        vmess_data = {"v":"2", "ps":"🇱🇰 Sri Lanka old", "add":"node.example", "port":"443", "id":"uuid", "aid":"0", "net":"tcp", "tls":"tls"}
        vmess_payload = base64.urlsafe_b64encode(json.dumps(vmess_data).encode()).decode().rstrip("=")
        vmess = _parse_link("vmess://" + vmess_payload, "source")
        self.assertIn("Sri Lanka", vmess.name)

        remark = base64.urlsafe_b64encode("🇬🇩 Grenada node".encode()).decode().rstrip("=")
        ssr_data = "node.example:443:origin:aes-256-cfb:plain:password/?remarks=" + remark
        ssr_payload = base64.urlsafe_b64encode(ssr_data.encode()).decode().rstrip("=")
        ssr = _parse_link("ssr://" + ssr_payload, "source")
        self.assertIn("Grenada", ssr.name)

    def test_generated_name_contains_flag_country_and_project(self):
        node = ProxyNode(uri="vless://uuid@node.example:443?security=tls#old", scheme="vless", host="node.example", port=443, name="old")
        label = set_node_name(node, Country("LK", "Sri Lanka", "ip", "8.8.8.8"))
        self.assertEqual(label, "🇱🇰 Sri Lanka • AeryxVPN")
        self.assertEqual(unquote(urlsplit(node.uri).fragment), label)
        self.assertEqual(flag_for_code("EU"), "🇪🇺")
        self.assertTrue(urlsplit(node.uri).fragment)


if __name__ == "__main__":
    unittest.main()
