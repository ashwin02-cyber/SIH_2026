"""
defence_sim.py
--------------
WHAT-IF SIMULATION of traffic-analysis defences, applied to packet records at the FEATURE level.

    THIS IS A SIMULATION. No packets are re-sent and no real gateway is configured. Each defence rewrites the
    (size, time) of the packet records the classifier sees, then the normal windowing + classifier run on the result.

Defences (fixed parameters, documented in `DEFENCES`)
    pad_buckets   pad every packet up to the next size in (128, 256, 512, 1024, 1500) bytes
    pad_mtu       pad every packet to 1500 bytes (the extreme case)
    dummy         inject constant-rate dummy packets (40 per second, 600 bytes, alternating directions)
    delay         add a random delay to each packet (half-normal, sd 100 ms) - packets are never sent earlier
    shape         hold packets until the next 100 ms time slot (timing shaping)
    combined      pad_buckets + dummy + delay

Every defence reports its COST: bandwidth overhead (% more bytes) and mean added delay (ms).
Padding to real fixed sizes needs a gateway that supports traffic-flow-confidentiality padding; dummy traffic and
shaping need an overlay or gateway support - none of this is a standard ipsec.conf switch.
"""

import math
import random
from collections import OrderedDict

MTU = 1500
BUCKETS = (128, 256, 512, 1024, 1500)
DUMMY_PPS, DUMMY_SIZE = 40, 600
DELAY_SD = 0.100
SLOT = 0.100


def _clone(packets):
    out = []
    for p in packets:
        q = {k: p[k] for k in ("src", "dst", "size", "time")}
        q["t_orig"] = p["time"]
        q["dummy"] = False
        out.append(q)
    return out


def pad_buckets(packets, rng):
    out = _clone(packets)
    for p in out:
        p["size"] = next((b for b in BUCKETS if b >= p["size"]), p["size"])
    return out


def pad_mtu(packets, rng):
    out = _clone(packets)
    for p in out:
        p["size"] = max(p["size"], MTU)
    return out


def dummy(packets, rng):
    out = _clone(packets)
    if len(out) < 2:
        return out
    t0, t1 = min(p["time"] for p in out), max(p["time"] for p in out)
    a, b = out[0]["src"], out[0]["dst"]
    n = int((t1 - t0) * DUMMY_PPS)
    for i in range(n):
        s, d = (a, b) if i % 2 == 0 else (b, a)
        out.append({"src": s, "dst": d, "size": DUMMY_SIZE, "time": t0 + (i + 0.5) / DUMMY_PPS, "t_orig": None, "dummy": True})
    return out


def delay(packets, rng):
    out = _clone(packets)
    for p in out:
        p["time"] += abs(rng.gauss(0.0, DELAY_SD))
    return out


def shape(packets, rng):
    out = _clone(packets)
    if not out:
        return out
    t0 = min(p["time"] for p in out)
    for p in out:
        p["time"] = t0 + math.ceil((p["time"] - t0) / SLOT - 1e-9) * SLOT
    return out


def combined(packets, rng):
    return delay(dummy(pad_buckets(packets, rng), rng), rng)


DEFENCES = OrderedDict([
    ("pad_buckets", {"label": "Pad packets to size buckets", "description": f"every packet padded up to the next of {BUCKETS} bytes", "fn": pad_buckets}),
    ("pad_mtu", {"label": "Pad every packet to full size", "description": f"every packet padded to {MTU} bytes", "fn": pad_mtu}),
    ("dummy", {"label": "Constant-rate dummy traffic", "description": f"{DUMMY_PPS} dummy packets per second of {DUMMY_SIZE} bytes", "fn": dummy}),
    ("delay", {"label": "Random delay (timing jitter)", "description": f"each packet delayed by |N(0, {int(DELAY_SD * 1000)} ms)|", "fn": delay}),
    ("shape", {"label": "Timing shaping", "description": f"packets held until the next {int(SLOT * 1000)} ms slot", "fn": shape}),
    ("combined", {"label": "Combined", "description": "size buckets + dummy traffic + random delay", "fn": combined}),
])


def overhead(before, after):
    b0 = sum(p["size"] for p in before)
    b1 = sum(p["size"] for p in after)
    delays = [p["time"] - p["t_orig"] for p in after if p.get("t_orig") is not None]
    return {"bandwidth_overhead_pct": round(100.0 * (b1 - b0) / b0, 1) if b0 else 0.0,
            "extra_packets": sum(1 for p in after if p.get("dummy")),
            "mean_added_delay_ms": round(1000.0 * sum(delays) / len(delays), 1) if delays else 0.0}


def apply(name, packets, seed=0):
    """Returns (defended_packets, overhead). Deterministic for a given (name, seed)."""
    out = DEFENCES[name]["fn"](packets, random.Random(f"{name}:{seed}"))
    return out, overhead(packets, out)
