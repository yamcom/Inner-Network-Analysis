from dhcp_monitor import decode_client_fqdn, extract_hostname


def test_option12_has_priority():
    hostname, source = extract_hostname({"hostname": b"pc-12", "client_FQDN": b"\x04\x00\x00\x05pc-81\x00"})
    assert hostname == "pc-12"
    assert source == "option12"


def test_option81_wire_format_is_decoded():
    value = b"\x04\x00\x00\x05pc-81\x07example\x00"
    assert decode_client_fqdn(value) == "pc-81.example"
    assert extract_hostname({"client_FQDN": value}) == ("pc-81.example", "option81")


def test_missing_hostname_is_explicit():
    assert extract_hostname({}) == ("", "none")

