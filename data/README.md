# data/

| Path | What |
|---|---|
| `samples/` | 10 small **real** captures from the Docker testbed, used by the app's "Try a sample" buttons, the tests and the docs |
| `manifest.csv` | ground-truth row for every sample (same columns as the root `manifest.csv`) |

The full dataset (216 pcaps, about 500 MB, plus the original zip) is **not in this repository** — it is
too big for git. Keep it in a normal folder and point the ML scripts at it:

```powershell
cd ml-engineer
python batch_extract.py --pcap-dir "D:\path\to\the\216\pcaps"
python train_model.py
```

Notes on the samples
* They are copied unmodified from the full set, except `aes128-dh2-transport-pfs-off__file_transfer_run1.pcap`:
  the original is ~4 MB, so it holds packets 1000–1299 of it (the bulk-transfer phase). The **first**
  300 packets are mostly ssh/scp negotiation and are classified as *video* by the model — a real
  limitation: the classifier expects a reasonably complete capture. The manifest marks this file as an excerpt.
* They were captured with the first version of the testbed (`config_version=v1-pfs-identical`): the
  `pfs` column does not describe the capture, and the "handshake" files contain only encrypted keep-alives.
  See `traffic-engineer/readme.MD`.
* Rebuild them with `python tools/make_data_samples.py --pcap-dir <folder with the 216 pcaps>`.
