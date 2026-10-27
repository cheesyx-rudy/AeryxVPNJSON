import base64
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit
from zoneinfo import ZoneInfo

from aeryx_json_parser.models import ProxyNode
from aeryx_json_parser.pipeline import _subscription_metadata, _write_subscription, _count_proxy_lines
from aeryx_json_parser.routing import refresh_happ_routing


class RoutingMetadataTests(unittest.TestCase):
    def test_metadata_uses_actual_count_and_configured_timezone(self):
        settings = {"subscription": {
            "profile_title": "AeryxVPN",
            "support_url": "https://t.me/cheesyx",
            "profile_web_page_url": "https://t.me/AeryxVPN",
            "profile_update_interval_hours": 1,
            "timezone": "Europe/Moscow",
        }}
        moment = datetime(2026, 10, 26, 15, 6, tzinfo=ZoneInfo("Europe/Moscow"))
        lines = _subscription_metadata(settings, 374, moment)
        self.assertEqual(lines[0], "#profile-title: AeryxVPN")
        self.assertEqual(lines[1], "#support-url: https://t.me/cheesyx")
        self.assertEqual(lines[2], "#profile-web-page-url: https://t.me/AeryxVPN")
        self.assertEqual(lines[3], "#profile-update-interval: 1")
        self.assertEqual(lines[4], "#announce: AeryxVPN · Новости: @AeryxVPN · Разработчики: @cheesyx · обновлено: 26.10.2026 15:06 | конфигов: 374")


    def test_count_proxy_lines_ignores_metadata_and_happ_link(self):
        text = "\n".join([
            "#profile-title: AeryxVPN",
            "#support-url: https://t.me/cheesyx",
            "#profile-web-page-url: https://t.me/AeryxVPN",
            "#announce: updated | configs: 1",
            "happ://routing/onadd/eyJOYW1lIjoieCJ9",
            "vless://uuid@node.example:443",
        ])
        self.assertEqual(_count_proxy_lines(text), 1)

    def test_happ_routing_profile_is_embedded_before_proxy_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_file = root / "profile.json"
            link_file = root / "profile.deeplink"
            profile_file.write_text(json.dumps({"Name": "AeryxVPN RU + Whitelist", "GlobalProxy": "true", "RouteOrder": "block-direct-proxy", "DirectSites": ["geosite:private"]}), encoding="utf-8")
            link = refresh_happ_routing(profile_file, link_file)
            self.assertTrue(link.startswith("happ://routing/onadd/"))
            payload = link.removeprefix("happ://routing/onadd/")
            decoded = json.loads(base64.b64decode(payload).decode("utf-8"))
            self.assertEqual(decoded["Name"], "AeryxVPN RU + Whitelist")
            self.assertIn("LastUpdated", decoded)

            node = ProxyNode(uri="vless://uuid@node.example:443#label", scheme="vless", host="node.example", port=443)
            meta = _subscription_metadata({"subscription": {"timezone": "UTC"}}, 1)
            subscription = root / "AeryxVPN"
            _write_subscription(subscription, [node], link, meta)
            lines = subscription.read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines[0], "#profile-title: AeryxVPN")
            route_index = next(i for i, line in enumerate(lines) if line.startswith("happ://routing/onadd/"))
            node_index = next(i for i, line in enumerate(lines) if line.startswith("vless://"))
            self.assertLess(route_index, node_index)
            self.assertEqual(unquote(urlsplit(lines[node_index]).fragment), "label")


if __name__ == "__main__":
    unittest.main()
