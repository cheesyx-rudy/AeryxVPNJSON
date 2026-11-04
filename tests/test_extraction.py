import base64

from aeryx_core.extraction import decode_layers, extract_html_links, extract_uri_strings

UUID = "11111111-1111-4111-8111-111111111111"


def test_extracts_plain_share_links_and_ignores_subscription_http_urls() -> None:
    text = (
        f"vless://{UUID}@node.example:443?security=tls#one\n"
        "trojan://secret@other.example:443#two\n"
        "https://panel.example/api/subscription?token=not-a-node"
    )

    values = extract_uri_strings(text)

    assert len(values) == 2
    assert values[0].startswith("vless://")
    assert values[1].startswith("trojan://")


def test_decodes_base64_subscription_layers() -> None:
    raw = f"vless://{UUID}@node.example:443#node"
    wrapped = base64.b64encode(raw.encode()).decode()

    assert extract_uri_strings(wrapped) == [raw]
    assert decode_layers(wrapped)[-1] == raw


def test_extracts_same_and_cross_host_html_subscription_links() -> None:
    html = (
        '<a href="/dashboard">Home</a>'
        '<a href="/api/subscription?format=clash">Config</a>'
        '<a href="https://other.example/sub">Other</a>'
    )

    links = extract_html_links(html, "https://panel.example/portal")

    assert "https://panel.example/api/subscription?format=clash" in links
    assert "https://other.example/sub" in links
    assert "https://panel.example/dashboard" not in links
