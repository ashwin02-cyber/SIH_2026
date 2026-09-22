import TimelineScrubber from "./TimelineScrubber";
import { trafficClassLabel } from "../data/mockData";
import { StatusChip } from "./AssessmentPanels";
import "./ReplayPanel.css";

const REPLAY_STATUS = {
  evidence_present: "sequence counter increasing (replay evidence)",
  evidence_present_reordered: "sequence numbers unique, some reordering",
  anomalies_observed: "repeated sequence numbers seen",
  not_observable: "not enough packets yet",
};

// A replay of a capture FILE, shown progressively. Clearly not live sniffing.
export default function ReplayPanel({ replay }) {
  const { windows, latest, total, done, label } = replay;
  const pct = total ? Math.round((windows.length / total) * 100) : 0;
  const verdict = latest?.so_far.verdict;
  const timeline = windows
    .filter((w) => w.window)
    .map((w) => ({
      window: w.index,
      start_sec: w.start_sec,
      end_sec: w.end_sec,
      class: w.window.class,
      label: trafficClassLabel[w.window.class] ?? w.window.class,
      confidence: w.window.confidence,
      packets: w.packets,
      bytes: w.bytes,
    }));

  return (
    <>
      <section className="panel">
        <h2 className="panel__title">Replay</h2>
        <p className="sim-banner" role="note">
          REPLAY OF A CAPTURE - NOT LIVE SNIFFING
        </p>
        <p className="assess__warn">{label}</p>
        <div className="meter" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
          <div className="meter__fill" style={{ width: `${pct}%` }} />
        </div>
        <p className="findings__evidence">
          {done ? "Replay finished - full analysis follows." : "Replaying..."} window {windows.length} of {total || "?"}
          {latest ? ` (capture time ${latest.end_sec}s, ${latest.so_far.packets.toLocaleString()} packets seen so far)` : ""}
        </p>

        {latest && (
          <ul className="findings">
            <li className="findings__item">
              <div className="findings__head">
                <span className="findings__title">Traffic type so far</span>
              </div>
              <p className="findings__value">
                {verdict?.class
                  ? `${trafficClassLabel[verdict.class] ?? verdict.class} (${Math.round(verdict.confidence * 100)}%)`
                  : "not enough traffic yet"}
              </p>
            </li>
            <li className="findings__item">
              <div className="findings__head">
                <span className="findings__title">Cipher family</span>
                {latest.so_far.cipher_family?.value !== "undetermined" && latest.so_far.cipher_family && (
                  <StatusChip status="inferred" confidence={latest.so_far.cipher_family.confidence} />
                )}
              </div>
              <p className="findings__value">{latest.so_far.cipher_family?.value ?? "no ESP packets"}</p>
            </li>
            <li className="findings__item">
              <div className="findings__head">
                <span className="findings__title">Tunnel or transport</span>
                {latest.so_far.mode && latest.so_far.mode.value !== "undetermined" && (
                  <StatusChip status="inferred" confidence={latest.so_far.mode.confidence} />
                )}
              </div>
              <p className="findings__value">{latest.so_far.mode?.value ?? "no ESP packets"}</p>
            </li>
            <li className="findings__item">
              <div className="findings__head">
                <span className="findings__title">Replay protection evidence</span>
              </div>
              <p className="findings__value">{REPLAY_STATUS[latest.so_far.replay_protection.status] ?? latest.so_far.replay_protection.status}</p>
            </li>
          </ul>
        )}
      </section>
      {timeline.length > 0 && <TimelineScrubber timeline={timeline} windowSec={1} />}
    </>
  );
}
