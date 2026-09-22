# Accuracy addendum - the newer models

Companion to [ACCURACY_REPORT.md](ACCURACY_REPORT.md), which audits the traffic classifier. This file covers what was added later: the passive ESP fingerprint, the calibrated open-set rejection and the defence simulator. **Every number below is read from a metrics file that is produced from the raw pcaps** (`tools/accuracy_addendum.py` only formats them).

## Reproducibility check

After the last code change (IPv6 / AH support rewrote the packet reader), `train_esp_fingerprint.py`, `train_open_set.py` and `evaluate_defences.py` were re-run from the 180 raw pcaps. The metrics files and the model files came out **byte-for-byte identical** to the committed ones (`git status` showed no change), so the IPv4 results did not move.

## Read this first

* All of it is **lab data**: 180 captures (36 VPN configurations x 5 scripted traffic types) from one strongSwan version, one capture per (config, class).
* Cross-validation is **grouped by VPN configuration**, so a test fold only contains configurations the model never saw in training. It is still the same lab, the same traffic generators and the same operating system, so these numbers say nothing about real user traffic.
* A number like 100 % here means "the scripted classes are easy to tell apart", not "the method is perfect".

## 1. Cipher family from packet sizes (CBC-like vs GCM-like)

A rule (no machine learning): the residue of the ESP length modulo 16. Files: `ml-engineer/esp_fingerprint.py`, results `esp_fingerprint_metrics.json`.

| | Value |
|---|---|
| Captures | 180 |
| Rule commits to an answer | 144 (80.0 %) |
| Correct when it commits | 144 / 144 (100.0 %) |
| Abstains ("undetermined") | 36 |
| True 16-byte integrity tag among the candidates (CBC answers) | 96 / 96 |

By traffic type:

| Traffic | Captures | Committed | Correct when committed |
|---|---|---|---|
| file_transfer | 36 | 36 (100 %) | 36 / 36 |
| icmp | 36 | 0 (0 %) | 0 / 0 |
| video | 36 | 36 (100 %) | 36 / 36 |
| voip | 36 | 36 (100 %) | 36 / 36 |
| web | 36 | 36 (100 %) | 36 / 36 |

**Where it abstains, and why that is correct:** ICMP echo packets are all the same size, so no length pattern exists to read; the rule says "undetermined" instead of guessing. The same happens for other constant-size streams. The 100 % is an accuracy *when it commits*, not a claim that every capture can be classified.

Integrity-tag length is reported as **candidates** (the length residue leaves a few possibilities), never as one certain value. AES-128 vs AES-256 cannot be told from sizes and is reported as not observable.

## 2. Tunnel vs transport mode

Random Forest on size-pattern features of the ESP packets, `StratifiedGroupKFold(6)` grouped by VPN configuration.

| | Value |
|---|---|
| Accuracy (all captures, out-of-fold) | 96.7 % |
| Majority-class baseline | 50.0 % |
| Shuffled-label control (5 runs, mean) | 45.4 % (chance 50 %) |
| Confidence threshold to commit | 0.75 |
| Coverage at that threshold | 89.4 % |
| Accuracy when it commits | 100.0 % |

| Traffic | Accuracy | Coverage |
|---|---|---|
| file_transfer | 100.0 % | 97 % |
| icmp | 83.3 % | 50 % |
| video | 100.0 % | 100 % |
| voip | 100.0 % | 100 % |
| web | 100.0 % | 100 % |

Weak spot: ICMP (short constant-size packets carry almost no signal). Below the confidence threshold the answer is "undetermined" and mode stays `unknown`.

## 3. Calibrated confidence and "unrecognised traffic"

* **Calibration:** temperature scaling on out-of-fold probabilities. The unconstrained fit ran to its search bound (0.0500052583326839), which would make every confidence saturate at 100 %, so the temperature is floored at **1.0** (it may only *soften* confidence, never sharpen it). Window-level expected calibration error 0.0023 -> 0.0023: on this data the model was already as well-calibrated as it can be shown to be, because it is almost always right. Calibration never changes which class wins (True).
* **Rejection rule:** answer "unrecognised" when the calibrated confidence is below 0.943 **or** the 5-nearest-neighbour novelty distance exceeds 0.549; thresholds chosen so that 95 % of known captures are accepted.
* **Test:** hold one traffic class out entirely (the model is trained without it, thresholds are chosen without it), then show it those captures as "unknown" traffic:

| Held-out class | Unknown rejected | Known accepted | AUROC (confidence / novelty) | Old rule (raw confidence below a fixed cutoff) flagged |
|---|---|---|---|---|
| file_transfer | 100 % (36 captures) | 94.4 % | 1.00 / 1.00 | 0 % |
| icmp | 100 % (36 captures) | 94.4 % | 1.00 / 1.00 | 53 % |
| video_streaming | 100 % (36 captures) | 95.1 % | 1.00 / 1.00 | 100 % |
| voip | 100 % (36 captures) | 94.4 % | 1.00 / 1.00 | 100 % |
| web_browsing | 100 % (36 captures) | 95.1 % | 1.00 / 1.00 | 81 % |

Mean unknown rejection 100 %; mean known accepted 94.7 % (so about 5 % of genuinely known captures are wrongly called "unrecognised" by design of the 95 % threshold).

**Honest reading:** a class that the lab never produced is easy to reject because the five lab classes are far apart in feature space. A real "unknown" (e.g. a different application that looks a bit like web) will be harder. The rejection result is best read as "the mechanism works on this lab data", not "it will catch everything".

## 4. Defence what-if simulator

Feature-level **simulation** on the 180 captures (not a real defence deployment). Chance level is 20 %. The *naive* attacker keeps the classifier trained on clean traffic; the *adaptive* attacker retrains on defended traffic from other configurations.

| Defence | Naive attacker | Adaptive attacker | Extra bandwidth (median) | Added delay |
|---|---|---|---|---|
| none | 100 % | - | 0 % | 0 ms |
| Pad packets to size buckets | 100.0 % | 100.0 % | +10 % | 0 ms |
| Pad every packet to full size | 42.8 % | 100.0 % | +223 % | 0 ms |
| Constant-rate dummy traffic | 60.0 % | 100.0 % | +72 % | 0 ms |
| Random delay (timing jitter) | 99.4 % | 100.0 % | +0 % | 79 ms |
| Timing shaping | 100.0 % | 100.0 % | +0 % | 60 ms |
| Combined | 60.0 % | 100.0 % | +119 % | 80 ms |

**Honest reading:** padding to full size and dummy traffic fool an attacker who does not adapt, but an attacker who retrains on defended traffic is back to ~100 % on this data. None of these defences reduces the adaptive attacker's accuracy here, and they cost bandwidth or delay. The simulator exists to show that trade-off, not to promise protection.

## 5. What was NOT measured

* Any real-world traffic (browsers, real video services, real VoIP). Every result is on scripted lab traffic.
* IPv6 and AH: only tested for *correct parsing* on hand-built synthetic captures; no accuracy figure exists for them.
* The IKE parser on a real `IKE_SA_INIT` (none of the 216 real captures contains one; only synthetic fixtures were parsed).
* The generated strongSwan configuration against a live strongSwan (Docker was not available).
* Key length, DH group after `IKE_SA_INIT`, PFS and authentication method: not observable from a passive capture, so there is nothing to score.
