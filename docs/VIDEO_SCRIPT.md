# 3-minute demo video — script and shot list

**Length:** exactly 3:00 · **Narration:** about 300 words (roughly 1.7 words per second), which leaves pauses while you click · **Format:** screen recording + voice-over, 1920×1080

## Before you record (10 minutes)
1. Start the app locally (`README.md` → Quick start) **or** open your deployed site; wait until the header says **● Analysis engine ready**.
2. Set the browser zoom to 100 %, close other tabs, hide bookmarks. Windows key + **Shift+S** is not needed — record with **OBS Studio** (Display Capture) or **Xbox Game Bar** (Windows key + G).
3. Have these files ready in a folder (from `data/samples/`):
   `aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap` (strong) and `aes128-dh2-transport-pfs-off__icmp_run1.pcap` (weak).
4. Open these in extra browser tabs / windows, ready to show: `docs/sample_reports/sample-executive.pdf`, `ml-engineer/confusion_matrix.png`, `docs/architecture.png`.
5. Read the narration once out loud with a timer. If a row runs long, cut words, not the timing.

## Shot list

| # | Time | Shot (what is on screen) | Narration (say exactly this) | On-screen text |
|---|---|---|---|---|
| 1 | 0:00-0:15 | Title card, then the empty dashboard | Companies use IPsec VPNs to protect their traffic. But how do you know a VPN is configured well, and what is really flowing through it, when everything is encrypted? This tool answers both from a single packet capture. | IPsec VPN Traffic Analyzer |
| 2 | 0:15-0:35 | Drag `aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap` onto the upload box, click **Analyze capture** | You upload a capture. The backend reads the VPN handshake to rate the security, and a machine-learning model classifies the encrypted traffic, without decrypting a single packet. | Upload → analyse in seconds |
| 3 | 0:35-1:05 | Results appear. Point at the gauge (100 LOW), then the **Threat matrix**, then the yellow **from file name** badges | The risk gauge shows a score out of one hundred. The threat matrix rates each setting: cipher, key exchange, forward secrecy and mode. Notice the badges. This capture does not contain the readable handshake, so the tool tells you these values come from the file name, not from the traffic. Unknown items stay unknown; they are never counted as weak. | Observed / declared / unknown |
| 4 | 1:05-1:35 | Upload `aes128-dh2-transport-pfs-off__icmp_run1.pcap`; gauge goes to 30 HIGH; click the **Technical terms** toggle to Plain English | Now a weak setup. A small 1024-bit key exchange and an older cipher drop the score to thirty, high risk. The plain-English switch rewrites every finding for a non-expert, so a manager can read it too. | Weak DH group 2 → HIGH |
| 5 | 1:35-2:05 | Scroll to **Traffic classification**, **Traffic timeline** (hover a bar), **Why this result** (SHAP lines) | The model recognises what is inside the tunnel: web browsing, video, voice, file transfer or ping. The timeline shows the prediction for every one-second window, and the explanation, built with SHAP, tells you which traffic features drove the decision. | Timeline · SHAP explanation |
| 6 | 2:05-2:25 | Click **Download report → Executive summary (PDF)**; open the PDF, scroll the first page | One click gives a real report, generated as an executive summary for decision makers, or a full technical report for engineers, with recommendations and the limits of the analysis. | Executive + technical PDF |
| 7 | 2:25-2:50 | Show `confusion_matrix.png`, then a quick scroll of `FINAL_STATUS.md` findings | We also checked our own work. Our first model looked perfect, but it was cheating: the packet count alone gave the class away. We rebuilt it on one-second windows and tested on VPN configurations it had never seen. It still scores very high, but we say clearly that this is a lab dataset, not real-world proof. | No shortcuts · honest results |
| 8 | 2:50-3:00 | `architecture.png`, then the title card | React dashboard, FastAPI backend, machine learning, and reports, all tested and ready to deploy. Thank you. | IPsec VPN Traffic Analyzer |
