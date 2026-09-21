# Test fixtures — SYNTHETIC, not real captures

Every `SYNTHETIC_*.pcap` file in this folder was **hand-built by
`tests/make_fixtures.py`** from the RFC 7296 wire format. **They are not
captures of a real VPN and must never be presented as real data.**

Why they exist: the real testbed captures do not contain the cleartext IKE
negotiation (`IKE_SA_INIT`) — only encrypted IKE keep-alives and ESP — so the
IKE parser could not otherwise be tested on the one exchange it is designed
for. Regenerate them with `python tests/make_fixtures.py`.

| File | What it is |
|---|---|
| `SYNTHETIC_ike_sa_init_gcm256_dh19.pcap` | request offering 2 proposals + response selecting AES-256-GCM / DH 19 |
| `SYNTHETIC_ike_sa_init_cbc128_dh2_natt.pcap` | same on UDP/4500 with NAT-T marker; AES-128-CBC / DH 2 |
| `SYNTHETIC_ike_sa_init_request_only.pcap` | only the initiator request (offer, unconfirmed) |
| `SYNTHETIC_ike_sa_init_truncated_packet.pcap` | response cut inside the SA payload |
| `SYNTHETIC_truncated_file.pcap` | pcap file cut mid-record |
| `SYNTHETIC_esp_only.pcap` | ESP packets only |
| `SYNTHETIC_ikev1_main_mode.pcap` | IKEv1-looking header |
| `SYNTHETIC_udp4500_esp_not_ike.pcap` | ESP-in-UDP that must NOT be read as IKE |
| `SYNTHETIC_not_a_pcap.pcap` | a text file with a .pcap name |

## SYNTHETIC ESP sequence / SPI fixtures (Stage 2)

Also **hand-built** (by `tests/make_esp_fixtures.py`, with Scapy) with a *known* sequence-number / SPI behaviour.
**They are not real captures.** The real testbed captures contain no rekey, no duplicates and no gaps, so the
SPI/sequence analysis could not otherwise be tested on those situations.

| File | Known behaviour |
|---|---|
| `SYNTHETIC_esp_clean_two_sas.pcap` | two SAs (one per direction), strictly increasing sequence numbers starting at 1 |
| `SYNTHETIC_esp_anomalies.pcap` | one SA with a gap (11-14), two duplicates (20, 21) and one late arrival (12) |
| `SYNTHETIC_esp_rekey_observed.pcap` | both directions rekey after 25 s; the old SAs start at sequence 1 |
| `SYNTHETIC_esp_rekey_start_not_observed.pcap` | capture starts mid-SA (sequence ~5000), then a rekey: only a lower bound is possible |
| `SYNTHETIC_esp_parallel_sas.pcap` | two SPIs overlapping for a long time in one direction: parallel SAs, not a rekey |

## SYNTHETIC IPv6 / AH / NAT-T fixtures (Stage 8)

Also **hand-built** (by `tests/make_ipv6_ah_fixtures.py`, with Scapy, from the RFC 4303 / RFC 4302 / RFC 8200 layouts).
**They are not real captures.** The real testbed captures are IPv4 ESP only, so IPv6 and AH support could not otherwise
be tested. The "encrypted" payload is filler bytes; only the headers and sizes are meaningful.

| File | What it is |
|---|---|
| `SYNTHETIC_ipv6_esp.pcap` | IPv6 ESP, two SAs (one per direction), 40 packets each, varied lengths |
| `SYNTHETIC_ipv6_esp_ext_header.pcap` | IPv6 ESP behind a destination-options extension header (its 8 bytes must not count as ESP length) |
| `SYNTHETIC_ipv4_ah.pcap` / `SYNTHETIC_ipv6_ah.pcap` | AH only: authenticated but NOT encrypted (the payload is readable) |
| `SYNTHETIC_ipv4_esp_and_ah.pcap` | ESP one way, AH the other, on IPv4 |
| `SYNTHETIC_natt_esp_udp4500.pcap` | ESP inside UDP/4500 (NAT traversal) |
| `SYNTHETIC_ipv6_ike_sa_init.pcap` | cleartext IKE_SA_INIT over IPv6 / UDP 500 (AES-256-GCM, group 19) |
