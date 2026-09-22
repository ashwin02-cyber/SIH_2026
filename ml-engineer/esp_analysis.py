"""esp_analysis.py - one pass over a capture that returns the passive ESP fingerprint (esp_fingerprint.py) and
the sequence/SPI analysis (esp_sequence.py). Packet headers and sizes only: no file names, no keys."""

import esp_fingerprint as fp
import esp_sequence as es
import traffic_features as tf


def analyze_packets(packets, esp_only=True):
    """`esp_only` is True when the capture holds IPsec packets (ESP and/or AH); `protocols` counts each."""
    ipsec = packets if esp_only else []
    protocols = {"ESP": sum(1 for p in ipsec if p.get("ipsec_proto", "ESP") == "ESP"),
                 "AH": sum(1 for p in ipsec if p.get("ipsec_proto") == "AH"),
                 "IPv6": sum(1 for p in ipsec if p.get("ip_version") == 6)}
    esp = [p for p in ipsec if p.get("ipsec_proto", "ESP") == "ESP"]
    fingerprint = fp.fingerprint_packets(esp) if esp else fp.no_esp_result()
    fingerprint["protocols"] = protocols
    fingerprint["ah_only"] = protocols["AH"] > 0 and protocols["ESP"] == 0
    return {"fingerprint": fingerprint, "sequence": es.analyze_sequences(ipsec)}


def analyze_pcap(path):
    """Raises ValueError if the file is not a readable capture."""
    packets, esp_only, _ = tf.read_packets(path)
    return analyze_packets(packets, esp_only)
