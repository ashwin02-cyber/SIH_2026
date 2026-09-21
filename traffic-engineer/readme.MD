# Traffic Engineer — testbed and dataset generation

Two strongSwan peers in Docker (`docker/strongswan/`), 36 VPN configurations
(3 ciphers × 3 DH groups × tunnel/transport × PFS on/off), 5 traffic classes
(ICMP, file transfer, web, video, VoIP) plus one IKE-handshake capture per config.

## Run it (needs Docker Desktop running)

```powershell
cd docker\strongswan
docker compose up -d --build          # start peer-a and peer-b
cd ..\..
python docker\strongswan\scripts\generate_configs.py     # only if you edit the template
python traffic-engineer\scripts\orchestrate.py --list
python traffic-engineer\scripts\orchestrate.py --combo aes128-dh14-tunnel-pfs-on   # test ONE config first
python traffic-engineer\scripts\orchestrate.py --all      # everything: ~40 minutes per 15 configs
```
Captures go to `real_captures/` (never committed) and `manifest.csv` is updated in place.
Then retrain: `cd ml-engineer; python batch_extract.py; python train_model.py`.

## What changed from the first dataset (and why)

| Problem in the first version | Fix |
|---|---|
| `pfs-on` and `pfs-off` configs were **byte-identical** (template ignored PFS), so the `pfs` column in the old manifest is meaningless | `esp=` now carries a DH group when PFS is on (`esp=aes128-sha256-modp2048!`); `keylife=25s` forces a child-SA rekey inside the capture so the PFS exchange really happens |
| `aes128gcm16` ESP line was `aes128gcm16-!` | `aes128gcm16!` / `aes128gcm16-modp2048!` |
| tcpdump ran inside the container that was then `docker restart`-ed, so it died with it; "handshake" files hold only later encrypted keep-alives | containers are not restarted; tcpdump starts first, then `ipsec down` + `ipsec reload` |
| captures stopped by packet count (`-c 20` … `-c 5000`), which made packet count predict the class | every capture stops by time: `timeout 30 tcpdump` (handshake: 20 s) |
| manifest appended duplicates | rows are upserted per filename; new columns `capture_stop`, `capture_seconds`, `config_version` |

Existing captures are marked `config_version=v1-pfs-identical` and `capture_stop=packet-count` in `manifest.csv`.

## Not verified

The updated scripts were **not run against real containers** (Docker was unavailable when they were written).
`tests/test_orchestrate.py` checks the command order with a fake Docker, and `tests/test_testbed_configs.py`
checks the generated configs. Run `--combo` once for real before launching `--all`, and confirm with
`docker exec peer-a ipsec statusall` that the child SA shows the DH group when PFS is on.
