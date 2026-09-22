# 3-minute demo video — script and shot list

**Length:** exactly 3:00 · **Narration:** about 320 words (roughly 1.8 words per second), which leaves pauses while you click · **Format:** screen recording + voice-over, 1920×1080

## Before you record (10 minutes)
1. Start the app locally (`README.md` → Quick start) **or** open your deployed site; wait until the header says **● Analysis engine ready**.
2. Set the browser zoom to 100 %, close other tabs, hide bookmarks. Windows key + **Shift+S** is not needed — record with **OBS Studio** (Display Capture) or **Xbox Game Bar** (Windows key + G).
3. Have these files ready in a folder (from `data/samples/`):
   `aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap` (strong) and `aes128-dh2-transport-pfs-off__icmp_run1.pcap` (weak).
4. Open the **Defence what-if** panel once beforehand so it is not computing live on camera. Optional extras if you have time (they do not fit the 3:00 script): `docs/sample_reports/sample-executive.pdf`, `ml-engineer/confusion_matrix.png`, the **Replay** checkbox (labelled not live sniffing), and the self-check / no-shortcuts findings in `FINAL_STATUS.md`.
5. Read the narration once out loud with a timer. If a row runs long, cut words, not the timing.

## Shot list

| # | Time | Shot (what is on screen) | Narration (say exactly this) | On-screen text |
|---|---|---|---|---|
| 1 | 0:00-0:15 | Title card, then the empty dashboard | Companies use IPsec VPNs to protect their traffic. But how do you know a VPN is configured well, and what is really flowing through it, when everything is encrypted? This tool answers both from a single packet capture. | IPsec VPN Traffic Analyzer |
| 2 | 0:15-0:35 | Drag `aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap` onto the upload box, click **Analyze capture** | You upload a capture. The backend reads the VPN handshake to rate the security, and a machine-learning model classifies the encrypted traffic, without decrypting a single packet. | Upload → analyse in seconds |
| 3 | 0:35-1:05 | Results appear. Point at the gauge (64 MEDIUM), the **Assessment completeness** bar, then the **Threat matrix** and the yellow **from file name** badges | The risk gauge shows a score out of one hundred. Notice it reads sixty-four, medium, not a hundred. This capture has no readable handshake, so the tool says which values come from the file name, and a completeness bar shows how much it could really establish. Unknown items stay unknown, and they cap the score. | Observed / inferred / declared / unknown |
| 4 | 1:05-1:30 | Upload `aes128-dh2-transport-pfs-off__icmp_run1.pcap`; gauge goes to 30 HIGH; point at the fingerprint finding | Now a weak setup: a small ten-twenty-four-bit key exchange drops the score to thirty, high risk. And because every packet here is the same size, the passive fingerprint honestly says undetermined instead of guessing a cipher. | Weak DH group 2 → HIGH · fingerprint: undetermined |
| 5 | 1:30-2:00 | Switch back to the strong capture; scroll to the cipher-family and mode findings, each with an **inferred** badge and a confidence number, then **Traffic classification** | Switch back to the strong capture. From packet sizes alone, never file names, the tool infers the cipher family and tunnel mode, each tagged inferred with a confidence number. It also classifies what is inside the tunnel, video, voice, or web, or says unrecognised when traffic does not match anything it has seen, and checks sequence numbers for replay evidence. | inferred · confidence 97 % · sizes only |
| 6 | 2:00-2:25 | Scroll to **Recommendations**, open the generated strongSwan snippet, point at the red **Verified: No** badge | The tool lists prioritised fixes and even generates a starter strongSwan configuration. Notice the red badge: verified, no. We were honest that this was never tested against a live strongSwan, so treat it as a draft, not a guarantee. | Verified: No · generated, not tested |
| 7 | 2:25-2:50 | Open the **Defence what-if** panel; point at the naive-attacker and adaptive-attacker columns for "pad to full size" | Finally, a defence what-if simulator. Padding every packet to full size fools a naive attacker, dropping accuracy to forty-three percent, but an attacker who retrains on defended traffic still gets it right nearly every time. We show both numbers, because a defence that only fools a naive observer is not real security. | Naive 43 % vs adaptive ~100 % · simulation |
| 8 | 2:50-3:00 | `architecture.png`, then the title card | React, FastAPI, and machine learning, all tested, and honest about what a passive capture can and cannot see. Thank you. | IPsec VPN Traffic Analyzer |
