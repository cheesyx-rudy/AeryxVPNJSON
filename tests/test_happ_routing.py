import base64
import json

from aeryx_core.routing import refresh_happ_routing


def test_happ_routing_profile_is_updated_and_deeplink_written(tmp_path) -> None:
    profile_path = tmp_path / "routing.json"
    deeplink_path = tmp_path / "routing.deeplink"
    profile_path.write_text(
        json.dumps(
            {
                "Name": "AeryxVPN RU + Whitelist",
                "GlobalProxy": "true",
                "RouteOrder": "block-direct-proxy",
                "DirectSites": ["geosite:private"],
            }
        ),
        encoding="utf-8",
    )

    link = refresh_happ_routing(profile_path, deeplink_path)

    assert link.startswith("happ://routing/onadd/")
    encoded = link.removeprefix("happ://routing/onadd/")
    decoded = json.loads(base64.b64decode(encoded).decode("utf-8"))
    assert decoded["Name"] == "AeryxVPN RU + Whitelist"
    assert "LastUpdated" in decoded
    assert deeplink_path.read_text(encoding="utf-8").strip() == link
    assert json.loads(profile_path.read_text(encoding="utf-8"))["LastUpdated"]
