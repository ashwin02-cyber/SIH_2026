# Traffic Dataset — IPsec VPN Analyzer (SIH 2026)

## Contents
- 180 pcap files: 36 VPN configs × 5 traffic classes, 1 run each
- manifest.csv: ground-truth labels for every pcap

## manifest.csv columns
- filename: exact pcap filename in this folder
- combo_name: the VPN config identifier (matches Testbed Lead's generated_configs/)
- cipher: aes128 / aes256 / aes128gcm16
- mode: tunnel / transport
- dh_group: dh2 / dh14 / dh19
- pfs: on / off
- traffic_class: icmp / file_transfer / web / video / voip
- timestamp: when the capture was taken
- notes: run number (all "run 1" — no repeats yet)

## How each capture was generated
- icmp: 10 ICMP echo requests (ping)
- file_transfer: 10MB file via scp
- web: 30 HTTP GET requests via curl, random 0.3-1.0s delays
- video: synthetic 30s test video (ffmpeg testsrc), streamed in 50KB range-request chunks
- voip: 5 simulated SIP calls via SIPp (signaling only, no RTP media)

## Known limitations
- 1 run per config (no repeats yet) — may want more samples per class for robustness
- VoIP captures contain SIP signaling only, no RTP audio payload
- All traffic generated between peer-a (10.10.0.10) and peer-b (10.10.0.20) inside Docker