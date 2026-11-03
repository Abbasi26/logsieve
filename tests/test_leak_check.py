from logsieve.pseudo import Session, find_leaks


class TestLeakCheckBoundaries:
    """Leak check uses word boundaries; substrings in version strings or host prefixes do not trigger."""

    def test_ip_not_leaked_in_build_number(self):
        session = Session()
        session.redact("10.0.0.1")
        # Build number contains the IP as prefix
        leaks = find_leaks("version 10.0.0.12345", session.mapping)
        assert leaks == [], "10.0.0.1 inside 10.0.0.12345 should not leak"

    def test_host_not_leaked_in_compound_token(self):
        session = Session()
        session.redact("laptop-07.northwind.example")
        # Host prefix inside a longer token
        leaks = find_leaks("service laptop-07setup started", session.mapping)
        assert leaks == [], "laptop-07 inside laptop-07setup should not leak"

    def test_sid_not_leaked_in_longer_sid(self):
        session = Session()
        session.redact("S-1-5-21-1000-2000-3000-1001")
        # Truncated/extended SID — hyphen is a valid boundary, so the redacted SID IS visible
        leaks = find_leaks("S-1-5-21-1000-2000-3000-1001-extended", session.mapping)
        assert "S-1-5-21-1000-2000-3000-1001" in leaks, "SID inside longer SID-like string should leak (hyphen is boundary)"

    def test_email_not_leaked_in_longer_localpart(self):
        session = Session()
        session.redact("ada.example@northwind.example")
        leaks = find_leaks("ada.example.extra@northwind.example", session.mapping)
        assert leaks == [], "email local-part prefix should not leak"

    def test_real_leak_still_caught(self):
        session = Session()
        session.redact("laptop-07.northwind.example")
        # Whole token left unredacted
        leaks = find_leaks("host laptop-07.northwind.example failed", session.mapping)
        assert "laptop-07.northwind.example" in leaks, "unredacted whole token should leak"

    def test_real_ip_leak_still_caught(self):
        session = Session()
        session.redact("203.0.113.25")
        leaks = find_leaks("server 203.0.113.25 responded", session.mapping)
        assert "203.0.113.25" in leaks, "unredacted IP should leak"

    def test_punctuation_boundaries_allowed(self):
        session = Session()
        session.redact("host.example.com")
        # Token followed by punctuation — punctuation is a valid boundary, so token IS visible → leak
        leaks = find_leaks("host host.example.com. failed", session.mapping)
        assert "host.example.com" in leaks, "token with trailing period should leak (punctuation is boundary)"
        leaks = find_leaks("host (host.example.com) failed", session.mapping)
        assert "host.example.com" in leaks, "token in parentheses should leak (punctuation is boundary)"
        leaks = find_leaks("host [host.example.com] failed", session.mapping)
        assert "host.example.com" in leaks, "token in brackets should leak (punctuation is boundary)"

    def test_host_label_with_trailing_dot_detected(self):
        session = Session()
        session.redact("dc01.example.com")
        session.redact("laptop-07.example.com")
        # Short host label with trailing dot should be detected
        leaks = find_leaks("host dc01. failed", session.mapping)
        assert "dc01" in leaks, "dc01 with trailing dot should be detected"
        leaks = find_leaks("host laptop-07. failed", session.mapping)
        assert "laptop-07" in leaks, "laptop-07 with trailing dot should be detected"

    def test_host_label_in_compound_token_not_detected(self):
        session = Session()
        session.redact("laptop-07.example.com")
        # Host label inside a longer compound token should NOT be detected
        leaks = find_leaks("service laptop-07setup started", session.mapping)
        assert "laptop-07" not in leaks, "laptop-07 inside laptop-07setup should not leak"

    def test_ipv6_full_address_detected(self):
        session = Session()
        session.redact("fe80::1ff:fe23:4567:890a")
        leaks = find_leaks("server fe80::1ff:fe23:4567:890a responded", session.mapping)
        assert "fe80::1ff:fe23:4567:890a" in leaks, "full IPv6 address should be detected"

    def test_ipv6_compressed_address_detected(self):
        session = Session()
        session.redact("2001:db8::1")
        leaks = find_leaks("server 2001:db8::1 responded", session.mapping)
        assert "2001:db8::1" in leaks, "compressed IPv6 address should be detected"