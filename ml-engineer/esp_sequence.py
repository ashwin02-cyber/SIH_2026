"""
esp_sequence.py
---------------
Passive analysis of the ESP HEADER fields that are visible without any key: the SPI (which Security
Association a packet belongs to) and the 32-bit sequence number (RFC 4303).

What this can show
    * REPLAY-PROTECTION EVIDENCE: per SA the sender uses a strictly increasing sequence counter (that counter
      is what the receiver's anti-replay window relies on). Gaps, duplicates and out-of-order packets are counted.
    * REKEY EVENTS: a new SPI appearing in the same direction while the old one goes quiet.
    * SA LIFETIME ESTIMATE: only when a rekey is observed AND the previous SA's first packet is inside the capture
      (sequence number starting at 1..2). Otherwise only a lower bound, or "not observable in this capture".

What it can NOT show (stated in every result)
    * Whether the RECEIVER enforces the anti-replay window, or its size (a receiver-side setting).
    * The configured lifetime in seconds/bytes: only the observed interval between successive SAs.
    * The upper 32 bits with Extended Sequence Numbers.

Definitions: a DUPLICATE is a sequence number seen twice (possible replay); an OUT-OF-ORDER packet is a
sequence number that arrives after a higher one but was never seen before (a late arrival: reordering at the
capture point, typical of multi-queue processing at high packet rates, NOT evidence of replay).
"""

from collections import defaultdict

SEQ_START_MAX = 2          # a fresh SA starts at 1; allow 2 for a packet lost before the capture point
ROLLOVER_HIGH = 0xFFFF0000
ROLLOVER_LOW = 0x0000FFFF
PARALLEL_OVERLAP_SEC = 10.0  # old SPI still active this long after a new one appeared => treated as a parallel SA

LIMITS = [
    "Whether the receiver enforces the anti-replay window (and its size) is a receiver-side setting and is not observable.",
    "Only the sender's sequence counter can be checked; a capture point can also see duplicates/reordering that never reached the receiver.",
    "The configured SA lifetime is not observable; only the interval between successive SAs seen in this capture.",
]


def _sa_stats(key, pkts):
    src, dst, spi, proto = key
    seqs = [p["seq"] for p in pkts]
    first_seq, last_seq = seqs[0], seqs[-1]
    seen, dup, ooo, gaps, missing, wraps = set(), 0, 0, 0, 0, 0
    highest = None
    for s in seqs:
        if s in seen:
            dup += 1
            continue
        seen.add(s)
        if highest is None:
            highest = s
            continue
        if s > highest:
            step = s - highest
            if step > 1:
                gaps += 1
                missing += step - 1
            highest = s
        elif highest > ROLLOVER_HIGH and s < ROLLOVER_LOW:
            wraps += 1               # 32-bit rollover: a new SA (or ESN) is required at this point
            highest = s
        else:
            ooo += 1
    return {
        "spi": f"0x{spi:08x}", "spi_int": spi, "protocol": proto, "direction": f"{src} -> {dst}", "packets": len(pkts),
        "first_seq": first_seq, "last_seq": last_seq,
        "starts_at_beginning": first_seq <= SEQ_START_MAX,
        "first_time": pkts[0]["time"], "last_time": pkts[-1]["time"],
        "monotonic": dup == 0 and ooo == 0,
        "duplicates": dup, "out_of_order": ooo, "gap_events": gaps, "rollovers": wraps,
        # a "late arrival" fills a gap that was seen earlier, so it is no longer missing
        "never_seen_sequence_numbers": max(0, missing - ooo),
    }


def _rekey_events(sas, t0):
    by_dir = defaultdict(list)
    for s in sas:
        by_dir[(s["direction"], s["protocol"])].append(s)
    events = []
    for (direction, _proto), lst in by_dir.items():
        lst.sort(key=lambda s: s["first_time"])
        for old, new in zip(lst, lst[1:]):
            parallel = old["last_time"] > new["first_time"] + PARALLEL_OVERLAP_SEC
            events.append({
                "direction": direction, "old_spi": old["spi"], "new_spi": new["spi"],
                "time_offset_sec": round(new["first_time"] - t0, 3),
                "kind": "parallel SA (not a rekey)" if parallel else "probable rekey",
                "old_sa_started_in_capture": old["starts_at_beginning"],
                "old_sa_first_packet_offset_sec": round(old["first_time"] - t0, 3),
                "_old": old, "_new": new,
            })
    events.sort(key=lambda e: e["time_offset_sec"])
    return events


def _lifetime(events, t0, t_end):
    rekeys = [e for e in events if e["kind"] == "probable rekey"]
    if not rekeys:
        return {"observable": False, "estimate_seconds": None, "lower_bound_seconds": None, "basis": None,
                "note": "not observable in this capture (no rekey - a new SPI in the same direction - was seen)"}
    complete = [e for e in rekeys if e["old_sa_started_in_capture"]]
    if complete:
        vals = sorted(e["_new"]["first_time"] - e["_old"]["first_time"] for e in complete)
        est = vals[len(vals) // 2]
        return {"observable": True, "estimate_seconds": round(est, 2), "lower_bound_seconds": None,
                "basis": f"time from the first packet of an SA (sequence number {complete[0]['_old']['first_seq']}) to the first "
                         f"packet of its replacement, {len(complete)} rekey(s) with the start observed",
                "note": "an interval between successive SAs (close to the soft lifetime), not the configured lifetime"}
    e = rekeys[0]
    lb = e["_new"]["first_time"] - t0
    return {"observable": False, "estimate_seconds": None, "lower_bound_seconds": round(lb, 2),
            "basis": "a rekey was seen, but the earlier SA began before the capture (sequence number was already high)",
            "note": f"the SA lived at least {lb:.1f} s; the real lifetime is not observable in this capture"}


def analyze_sequences(packets):
    """packets: reader records of ESP packets (spi, seq, src, dst, time). Returns a JSON-friendly dict."""
    pk = [p for p in packets if p.get("spi") is not None and p.get("seq") is not None]
    if not pk:
        return {"esp_packets": 0, "sas": [], "replay_protection": {"status": "not_observable", "evidence": "no ESP packets with a readable header",
                                                                    "limits": LIMITS},
                "rekey_events": [], "sa_lifetime": {"observable": False, "estimate_seconds": None, "lower_bound_seconds": None,
                                                     "basis": None, "note": "not observable in this capture (no ESP packets)"}}
    groups = defaultdict(list)
    for p in pk:                                   # capture order
        groups[(p["src"], p["dst"], p["spi"], p.get("ipsec_proto", "ESP"))].append(p)
    sas = [_sa_stats(k, v) for k, v in groups.items()]
    sas.sort(key=lambda s: (s["first_time"], s["direction"]))
    t0, t_end = min(p["time"] for p in pk), max(p["time"] for p in pk)
    events = _rekey_events(sas, t0)

    big = [s for s in sas if s["packets"] >= 5]
    dup = sum(s["duplicates"] for s in sas)
    ooo = sum(s["out_of_order"] for s in sas)
    never = sum(s["never_seen_sequence_numbers"] for s in big)
    if not big:
        replay = {"status": "not_observable", "evidence": "fewer than 5 packets per SA - too little to judge the sequence counter"}
    elif dup:
        replay = {"status": "anomalies_observed",
                  "evidence": f"{dup} repeated sequence number(s) seen (and {ooo} out-of-order): possible replayed packets, or duplicates created "
                              "at the capture point - whether the receiver dropped them is not observable"}
    elif ooo:
        replay = {"status": "evidence_present_reordered",
                  "evidence": f"every sequence number is unique (no repeats) and increases per SA, but {ooo} packet(s) arrived out of order at the "
                              f"capture point ({never} sequence numbers never seen); this is reordering, not evidence of replay"}
    else:
        replay = {"status": "evidence_present",
                  "evidence": f"all {len(big)} SA(s) with enough packets use a strictly increasing sequence counter "
                              f"(no duplicates, no out-of-order packets, {never} sequence numbers never seen)"}
    replay["limits"] = LIMITS

    public_events = [{k: v for k, v in e.items() if not k.startswith("_")} for e in events]
    public_sas = [{k: v for k, v in s.items() if k != "spi_int"} for s in sas]
    return {"esp_packets": len(pk), "capture_span_sec": round(t_end - t0, 3), "sas": public_sas,
            "replay_protection": replay, "rekey_events": public_events, "sa_lifetime": _lifetime(events, t0, t_end)}
