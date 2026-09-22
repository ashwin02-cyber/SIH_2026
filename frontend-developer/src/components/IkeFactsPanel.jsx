import { plainFor } from "../plainText";
import "./IkeFactsPanel.css";

const ratingColor = {
  strong: "var(--risk-low)",
  medium: "var(--risk-medium)",
  weak: "var(--risk-high)",
  unknown: "var(--text-muted)",
};

const sourceText = {
  observed: "read from capture",
  inferred: "inferred from packet sizes",
  declared: "from file name",
  unknown: "not determinable",
};

const keyOf = { Cipher: "cipher", Mode: "mode", "DH group": "dh_group", "Forward secrecy": "pfs" };

function Source({ source, confidence }) {
  const pct = source === "inferred" && confidence != null ? ` ${Math.round(confidence * 100)}%` : "";
  return (
    <span className={`source source--${source}`}>
      {sourceText[source]}
      {pct}
    </span>
  );
}

export default function IkeFactsPanel({ analysis, plainEnglish }) {
  const items = [
    ["Cipher", analysis.cipher, analysis.sources.cipher],
    ["Mode", analysis.mode, analysis.sources.mode],
    ["DH group", analysis.dh_group, analysis.sources.dh_group],
    ["Forward secrecy", analysis.pfs, analysis.sources.pfs],
  ];

  return (
    <section className="panel">
      <h2 className="panel__title">Handshake configuration</h2>
      <dl className="ike-grid">
        {items.map(([label, value, source]) => (
          <div className="ike-grid__item" key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
            <Source source={source} confidence={analysis.confidence?.[keyOf[label]]} />
          </div>
        ))}
      </dl>

      <ul className="ike-findings">
        {analysis.breakdown.map((b) => (
          <li key={b.factor} className="ike-findings__item">
            <span className="ike-findings__dot" style={{ background: ratingColor[b.rating] }} />
            <div>
              <p className="ike-findings__factor">
                {b.factor} <span className="ike-findings__rating">{b.rating}</span>
              </p>
              <p className="ike-findings__note">{plainEnglish ? plainFor(b.factor, b.rating) : b.reason}</p>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
