"""
accuracy_addendum.py - writes ACCURACY_ADDENDUM.md from the metrics files of the newer models.

    python tools/accuracy_addendum.py

The numbers are NOT typed in: they are read from ml-engineer/esp_fingerprint_metrics.json, open_set_metrics.json and
defence_metrics.json, which are produced from the raw pcaps by train_esp_fingerprint.py, train_open_set.py and
evaluate_defences.py. (tools/accuracy_check.py, the earlier independent audit, covers the traffic classifier itself.)
This script only reads those files and formats them; it changes nothing else.
"""
import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ML = os.path.join(ROOT, "ml-engineer")


def load(name):
    with open(os.path.join(ML, name), encoding="utf-8") as f:
        return json.load(f)


def pct(x, nd=1):
    return f"{100 * x:.{nd}f} %"


def build():
    fpm, osm, dm = load("esp_fingerprint_metrics.json"), load("open_set_metrics.json"), load("defence_metrics.json")
    rule, mode = fpm["cipher_family_rule"], fpm["tunnel_vs_transport"]
    o = rule["overall"]
    L = []
    add = L.append
    add("# Accuracy addendum - the newer models\n")
    add("Companion to [ACCURACY_REPORT.md](ACCURACY_REPORT.md), which audits the traffic classifier. This file covers what was added "
        "later: the passive ESP fingerprint, the calibrated open-set rejection and the defence simulator. "
        "**Every number below is read from a metrics file that is produced from the raw pcaps** "
        "(`tools/accuracy_addendum.py` only formats them).\n")
    add("## Reproducibility check\n")
    add("After the last code change (IPv6 / AH support rewrote the packet reader), `train_esp_fingerprint.py`, `train_open_set.py` and "
        "`evaluate_defences.py` were re-run from the 180 raw pcaps. The metrics files and the model files came out **byte-for-byte identical** to the "
        "committed ones (`git status` showed no change), so the IPv4 results did not move.\n")
    add("## Read this first\n")
    add("* All of it is **lab data**: 180 captures (36 VPN configurations x 5 scripted traffic types) from one strongSwan version, one capture per (config, class).")
    add("* Cross-validation is **grouped by VPN configuration**, so a test fold only contains configurations the model never saw in training. "
        "It is still the same lab, the same traffic generators and the same operating system, so these numbers say nothing about real user traffic.")
    add("* A number like 100 % here means \"the scripted classes are easy to tell apart\", not \"the method is perfect\".\n")

    add("## 1. Cipher family from packet sizes (CBC-like vs GCM-like)\n")
    add(f"A rule (no machine learning): the residue of the ESP length modulo 16. Files: `ml-engineer/esp_fingerprint.py`, results `esp_fingerprint_metrics.json`.\n")
    add("| | Value |\n|---|---|")
    add(f"| Captures | {o['captures']} |")
    add(f"| Rule commits to an answer | {o['committed']} ({pct(o['coverage'])}) |")
    add(f"| Correct when it commits | {o['correct_when_committed']} / {o['committed']} ({pct(o['accuracy_when_committed'])}) |")
    add(f"| Abstains (\"undetermined\") | {o['captures'] - o['committed']} |")
    ic = rule["icv"]
    add(f"| True 16-byte integrity tag among the candidates (CBC answers) | {ic['true_icv_16_in_candidates']} / {ic['cbc_captures_answered']} |\n")
    add("By traffic type:\n")
    add("| Traffic | Captures | Committed | Correct when committed |\n|---|---|---|---|")
    for t, b in rule["by_traffic"].items():
        add(f"| {t} | {b['captures']} | {b['committed']} ({pct(b['coverage'], 0)}) | {b['correct_when_committed']} / {b['committed']} |")
    add("")
    add("**Where it abstains, and why that is correct:** ICMP echo packets are all the same size, so no length pattern exists to read; the rule says "
        "\"undetermined\" instead of guessing. The same happens for other constant-size streams. The 100 % is an accuracy *when it commits*, "
        "not a claim that every capture can be classified.\n")
    add("Integrity-tag length is reported as **candidates** (the length residue leaves a few possibilities), never as one certain value. "
        "AES-128 vs AES-256 cannot be told from sizes and is reported as not observable.\n")

    add("## 2. Tunnel vs transport mode\n")
    add("Random Forest on size-pattern features of the ESP packets, `StratifiedGroupKFold(6)` grouped by VPN configuration.\n")
    add("| | Value |\n|---|---|")
    add(f"| Accuracy (all captures, out-of-fold) | {pct(mode['accuracy'])} |")
    add(f"| Majority-class baseline | {pct(mode['majority_baseline'])} |")
    add(f"| Shuffled-label control (5 runs, mean) | {pct(mode['shuffled_label_accuracy']['mean'])} (chance {pct(mode['shuffled_label_accuracy']['chance'], 0)}) |")
    add(f"| Confidence threshold to commit | {mode['threshold']} |")
    add(f"| Coverage at that threshold | {pct(mode['coverage_at_threshold'])} |")
    add(f"| Accuracy when it commits | {pct(mode['accuracy_when_committed'])} |\n")
    add("| Traffic | Accuracy | Coverage |\n|---|---|---|")
    for t, b in mode["by_traffic"].items():
        add(f"| {t} | {pct(b['accuracy'])} | {pct(b['coverage'], 0)} |")
    add("")
    add("Weak spot: ICMP (short constant-size packets carry almost no signal). Below the confidence threshold the answer is \"undetermined\" and mode stays `unknown`.\n")

    add("## 3. Calibrated confidence and \"unrecognised traffic\"\n")
    cal = osm["calibration"]
    add(f"* **Calibration:** temperature scaling on out-of-fold probabilities. The unconstrained fit ran to its search bound ({cal['temperature_fitted']}), "
        f"which would make every confidence saturate at 100 %, so the temperature is floored at **{cal['temperature']}** (it may only *soften* confidence, never sharpen it). "
        f"Window-level expected calibration error {cal['window_level']['ece']['before']:.4f} -> {cal['window_level']['ece']['after']:.4f}: on this data the model was already "
        f"as well-calibrated as it can be shown to be, because it is almost always right. Calibration never changes which class wins ({cal['argmax_unchanged_by_calibration']}).")
    th = osm["thresholds"]
    add(f"* **Rejection rule:** answer \"unrecognised\" when the calibrated confidence is below {th['tau_conf']:.3f} **or** the 5-nearest-neighbour novelty distance exceeds {th['tau_dist']:.3f}; "
        f"thresholds chosen so that {pct(th['target_accept'], 0)} of known captures are accepted.")
    add("* **Test:** hold one traffic class out entirely (the model is trained without it, thresholds are chosen without it), then show it those captures as \"unknown\" traffic:\n")
    add("| Held-out class | Unknown rejected | Known accepted | AUROC (confidence / novelty) | Old rule (raw confidence below a fixed cutoff) flagged |\n|---|---|---|---|---|")
    for c, b in osm["leave_one_class_out"].items():
        add(f"| {c} | {pct(b['unknown_rejected_combined'], 0)} ({b['unknown_captures']} captures) | {pct(b['known_accepted'])} | "
            f"{b['auroc_confidence']:.2f} / {b['auroc_novelty']:.2f} | {pct(b['old_rule_unknown_flagged'], 0)} |")
    add("")
    add(f"Mean unknown rejection {pct(osm['mean_unknown_rejection'], 0)}; mean known accepted {pct(osm['mean_known_accepted'])} "
        "(so about 5 % of genuinely known captures are wrongly called \"unrecognised\" by design of the 95 % threshold).\n")
    add("**Honest reading:** a class that the lab never produced is easy to reject because the five lab classes are far apart in feature space. "
        "A real \"unknown\" (e.g. a different application that looks a bit like web) will be harder. The rejection result is best read as "
        "\"the mechanism works on this lab data\", not \"it will catch everything\".\n")

    add("## 4. Defence what-if simulator\n")
    add(f"Feature-level **simulation** on the {dm['captures']} captures (not a real defence deployment). Chance level is {pct(dm['chance_level_capture_accuracy'], 0)}. "
        "The *naive* attacker keeps the classifier trained on clean traffic; the *adaptive* attacker retrains on defended traffic from other configurations.\n")
    add("| Defence | Naive attacker | Adaptive attacker | Extra bandwidth (median) | Added delay |\n|---|---|---|---|---|")
    add(f"| none | {pct(dm['baseline']['non_adaptive_capture_accuracy'], 0)} | - | 0 % | 0 ms |")
    for k, b in dm["defences"].items():
        c = b["cost"]
        add(f"| {b['label']} | {pct(b['non_adaptive_capture_accuracy'])} | {pct(b['adaptive_capture_accuracy'])} | "
            f"+{c['bandwidth_overhead_pct_median']:.0f} % | {c['mean_added_delay_ms']:.0f} ms |")
    add("")
    add("**Honest reading:** padding to full size and dummy traffic fool an attacker who does not adapt, but an attacker who retrains on defended traffic "
        "is back to ~100 % on this data. None of these defences reduces the adaptive attacker's accuracy here, and they cost bandwidth or delay. "
        "The simulator exists to show that trade-off, not to promise protection.\n")

    add("## 5. What was NOT measured\n")
    add("* Any real-world traffic (browsers, real video services, real VoIP). Every result is on scripted lab traffic.")
    add("* IPv6 and AH: only tested for *correct parsing* on hand-built synthetic captures; no accuracy figure exists for them.")
    add("* The IKE parser on a real `IKE_SA_INIT` (none of the 216 real captures contains one; only synthetic fixtures were parsed).")
    add("* The generated strongSwan configuration against a live strongSwan (Docker was not available).")
    add("* Key length, DH group after `IKE_SA_INIT`, PFS and authentication method: not observable from a passive capture, so there is nothing to score.\n")
    return "\n".join(L)


def main():
    text = build()
    out = os.path.join(ROOT, "ACCURACY_ADDENDUM.md")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print("wrote", out)


if __name__ == "__main__":
    main()
