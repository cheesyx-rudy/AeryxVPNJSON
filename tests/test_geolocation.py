from aeryx_core.geolocation import (
    Country,
    CountryResolver,
    country_from_label,
    country_label,
    flag_for_code,
)


class FakeReader:
    def get(self, ip: str) -> dict[str, object]:
        if ip == "8.8.8.8":
            return {"country": {"iso_code": "LK", "names": {"en": "Sri Lanka"}}}
        return {}

    def close(self) -> None:
        return None


def test_ip_database_result_precedes_country_label() -> None:
    resolver = CountryResolver()
    resolver.reader = FakeReader()

    country = resolver.resolve(["8.8.8.8"], ["Germany node"], "node.example")

    assert country == Country("LK", "Sri Lanka", "ip", "8.8.8.8")


def test_existing_flag_label_is_recognized() -> None:
    country = country_from_label("🇱🇰 Sri Lanka • previous group")

    assert country is not None
    assert (country.code, country.name) == ("LK", "Sri Lanka")


def test_standalone_iso_code_is_recognized() -> None:
    country = country_from_label("SG-01 | Legacy node")

    assert country is not None
    assert (country.code, country.name) == ("SG", "Singapore")


def test_country_tld_is_last_fallback() -> None:
    country = CountryResolver().resolve([], [], "host.example.de")

    assert country is not None
    assert (country.code, country.name, country.method) == ("DE", "Germany", "hostname_tld")


def test_country_label_and_eu_flag() -> None:
    country = Country("LK", "Sri Lanka", "ip", "8.8.8.8")

    assert country_label(country) == "🇱🇰 Sri Lanka • AeryxVPN"
    assert flag_for_code("EU") == "🇪🇺"
