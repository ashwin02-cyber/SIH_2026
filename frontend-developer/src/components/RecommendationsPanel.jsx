import { useState } from "react";
import { StatusChip } from "./AssessmentPanels";
import "./RecommendationsPanel.css";

const PRIORITY_COLOR = {
  Critical: "var(--risk-high)",
  High: "var(--risk-high)",
  Medium: "var(--risk-medium)",
  Low: "var(--text-muted)",
};

function ScoreCard({ title, snap, note }) {
  return (
    <div className="ba__card">
      <p className="ba__title">{title}</p>
      <p className="ba__score">
        {snap.score ?? "n/a"} <span className="ba__level">{snap.risk_level}</span>
      </p>
      <p className="ba__note">
        completeness {Math.round(snap.completeness_pct)}%{note ? ` - ${note}` : ""}
      </p>
    </div>
  );
}

// Prioritised fixes, a generated strongSwan snippet and a before / after projection.
export default function RecommendationsPanel({ recommendations }) {
  const [copied, setCopied] = useState(false);
  const { items, secure_config: cfg, before_after: ba } = recommendations;

  async function copy() {
    try {
      await navigator.clipboard.writeText(cfg.text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section className="panel">
      <h2 className="panel__title">Recommendations</h2>
      {items.length === 0 ? (
        <p className="assess__lead">Nothing to change for the facts that could be checked.</p>
      ) : (
        <ol className="recs">
          {items.map((r) => (
            <li key={r.id} className="recs__item">
              <div className="recs__head">
                <span className="recs__prio" style={{ color: PRIORITY_COLOR[r.priority], borderColor: PRIORITY_COLOR[r.priority] }}>
                  {r.priority}
                </span>
                <strong>{r.title}</strong>
                <StatusChip status={r.based_on.status} confidence={r.based_on.confidence} />
              </div>
              <p className="recs__text">{r.action}</p>
              <p className="findings__evidence">{r.why}</p>
              {r.config_hint && <code className="recs__hint">{r.config_hint}</code>}
            </li>
          ))}
        </ol>
      )}

      <h3 className="recs__sub">Before / after (projection)</h3>
      <div className="ba">
        <ScoreCard title="Before" snap={ba.before} />
        <ScoreCard title="After, from a new passive capture" snap={ba.after_passive_capture} />
        <ScoreCard title="After, config reviewed directly" snap={ba.after_config_review} />
      </div>
      <p className="findings__evidence">
        {ba.label}. {ba.after_passive_capture.assumption}.
      </p>

      <h3 className="recs__sub">Generated strongSwan configuration</h3>
      <p className="assess__warn">{cfg.note}</p>
      <pre className="conf">{cfg.text}</pre>
      <button className="panel__button" onClick={copy}>
        {copied ? "Copied" : "Copy configuration"}
      </button>
    </section>
  );
}
