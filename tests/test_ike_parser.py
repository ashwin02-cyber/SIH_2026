"""Unit tests for ike_parser. Fixtures are SYNTHETIC (see tests/fixtures/README.md)."""
import pytest

from ike_parser import classify_ike_header, parse_ike_handshake
import synth_ike as s


def test_selected_proposal_from_response(fixture_path):
    r = parse_ike_handshake(fixture_path("SYNTHETIC_ike_sa_init_gcm256_dh19.pcap"))
    assert r["ike_version"] == "2.0"
    # The responder chose the GCM/DH19 proposal, not the AES-128-CBC/DH2 one that was also offered.
    assert r["ike_sa"]["cipher"] == "AES-GCM-16"
    assert r["ike_sa"]["key_length_bits"] == 256
    assert r["ike_sa"]["dh_group"] == 19
    assert r["ike_sa"]["prf"] == "PRF-HMAC-SHA2-256"
    assert r["handshake"]["sa_source"] == "responder-selected"
    assert r["handshake"]["ike_sa_init_seen"] is True
    assert r["handshake"]["truncated"] is False


def test_nat_t_marker_and_weak_group(fixture_path):
    r = parse_ike_handshake(fixture_path("SYNTHETIC_ike_sa_init_cbc128_dh2_natt.pcap"))
    assert r["ike_sa"]["cipher"] == "AES-CBC"
    assert r["ike_sa"]["key_length_bits"] == 128
    assert r["ike_sa"]["integrity"] == "HMAC-SHA2-256-128"
    assert r["ike_sa"]["dh_group"] == 2
    assert "1024" in r["ike_sa"]["dh_group_label"]


def test_mode_is_unknown_not_tunnel(fixture_path):
    """Mode is only visible inside the encrypted IKE_AUTH, so it must not be defaulted to 'tunnel'."""
    for name in ("SYNTHETIC_ike_sa_init_gcm256_dh19.pcap", "SYNTHETIC_esp_only.pcap"):
        r = parse_ike_handshake(fixture_path(name))
        assert r["mode"] == "unknown"
        assert any("mode" in w.lower() for w in r["warnings"])


def test_esp_pfs_unknown_when_not_observed(fixture_path):
    r = parse_ike_handshake(fixture_path("SYNTHETIC_ike_sa_init_gcm256_dh19.pcap"))
    assert r["esp_sa"] is None


def test_request_only_is_flagged_as_offer(fixture_path):
    r = parse_ike_handshake(fixture_path("SYNTHETIC_ike_sa_init_request_only.pcap"))
    assert r["handshake"]["sa_source"] == "initiator-offered"
    assert r["ike_sa"]["dh_group"] == 14
    assert any("OFFERED" in w for w in r["warnings"])


def test_esp_only_gives_unknown_version(fixture_path):
    r = parse_ike_handshake(fixture_path("SYNTHETIC_esp_only.pcap"))
    assert r["ike_version"] == "unknown"
    assert r["ike_sa"] is None
    assert r["handshake"]["esp_packets"] == 5


def test_esp_in_udp4500_is_not_mistaken_for_ike(fixture_path):
    r = parse_ike_handshake(fixture_path("SYNTHETIC_udp4500_esp_not_ike.pcap"))
    assert r["ike_version"] == "unknown"
    assert r["handshake"]["ike_packets"] == 0
    assert r["handshake"]["esp_packets"] == 1


def test_ikev1_detected_but_not_decoded(fixture_path):
    r = parse_ike_handshake(fixture_path("SYNTHETIC_ikev1_main_mode.pcap"))
    assert r["ike_version"] == "1.0"
    assert r["ike_sa"] is None
    assert any("IKEv1" in w for w in r["warnings"])


def test_truncated_packet_does_not_crash(fixture_path):
    r = parse_ike_handshake(fixture_path("SYNTHETIC_ike_sa_init_truncated_packet.pcap"))
    assert r["handshake"]["truncated"] is True
    assert any("truncated" in w.lower() for w in r["warnings"])


def test_truncated_file_returns_partial_result(fixture_path):
    r = parse_ike_handshake(fixture_path("SYNTHETIC_truncated_file.pcap"))
    # First packet (the request) is intact, the response record is cut off.
    assert r["handshake"]["truncated"] is True
    assert r["ike_sa"] is not None
    assert r["ike_sa"]["dh_group"] == 19


def test_not_a_pcap_raises_value_error(fixture_path):
    with pytest.raises(ValueError):
        parse_ike_handshake(fixture_path("SYNTHETIC_not_a_pcap.pcap"))


def test_missing_file_raises_value_error(tmp_path):
    with pytest.raises(ValueError):
        parse_ike_handshake(str(tmp_path / "nope.pcap"))


# ---- header validation -----------------------------------------------------

def _msg(**kw):
    return s.ike_message(s.proposal(1, s.AES256_GCM_DH19), response=True, dh_group=19, **kw)


def test_header_accepts_valid_ikev2():
    h = classify_ike_header(_msg())
    assert h and h["version"] == "2.0" and h["exchange"] == 34 and h["is_response"] is True


def test_header_rejects_bad_version_exchange_and_lengths():
    good = bytearray(_msg())
    bad_ver = bytearray(good); bad_ver[17] = 0x30
    bad_exch = bytearray(good); bad_exch[18] = 99
    zero_spi = bytearray(good); zero_spi[0:8] = b"\x00" * 8
    short_len = bytearray(good); short_len[24:28] = (10).to_bytes(4, "big")
    reserved_flags = bytearray(good); reserved_flags[19] = 0x01
    for b in (bad_ver, bad_exch, zero_spi, short_len, reserved_flags):
        assert classify_ike_header(bytes(b)) is None
    assert classify_ike_header(b"\x01" * 10) is None


def test_header_marks_snaplen_truncation():
    full = _msg()
    h = classify_ike_header(full[:60])
    assert h is not None and h["truncated"] is True
