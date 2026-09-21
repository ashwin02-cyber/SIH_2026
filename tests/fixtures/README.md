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
