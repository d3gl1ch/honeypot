from honeypot.enrich import count_by, enrich_events, enrich_ip, lookup, reverse_dns


def test_lookup_known():
    r = lookup("185.10.1.5")
    assert r["country"] == "RU"
    assert r["asn"] == "AS49505"
    assert r["org"] == "Selectel"


def test_lookup_unknown_and_bad():
    assert lookup("8.8.8.8")["country"] == "??"
    assert lookup("not-an-ip")["country"] == "??"


def test_reverse_dns_injected():
    def fake(ip):
        return (f"host-{ip.replace('.', '-')}.example", [], [ip])

    assert reverse_dns("1.2.3.4", resolver=fake) == "host-1-2-3-4.example"


def test_reverse_dns_error():
    def boom(ip):
        raise OSError("нет ptr")

    assert reverse_dns("1.2.3.4", resolver=boom) == ""


def test_enrich_ip():
    r = enrich_ip("45.33.2.9")
    assert r["country"] == "US"
    assert r["ptr"] == ""


def test_enrich_events_does_not_change_source():
    events = [{"src_ip": "185.10.1.5"}, {"src_ip": "8.8.8.8"}]
    out = list(enrich_events(events))
    assert out[0]["enrich"]["country"] == "RU"
    assert out[1]["enrich"]["country"] == "??"
    assert "enrich" not in events[0]


def test_count_by():
    events = [{"src_ip": "185.10.1.5"}] * 3 + [{"src_ip": "8.8.8.8"}]
    assert count_by(events)["RU"] == 3
    assert count_by(events)["??"] == 1
    assert count_by(events, "org")["unknown"] == 1
