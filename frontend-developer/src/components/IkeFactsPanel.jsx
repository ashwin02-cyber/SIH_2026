import "./IkeFactsPanel.css";

const ratingColor = {
  strong: "var(--risk-low)",
  medium: "var(--risk-medium)",
  weak: "var(--risk-high)",
};

export default function IkeFactsPanel({ facts, plainEnglish }) {
  return (
    <section className="panel">
      <h2 className="panel__title">Handshake configuration</h2>
      <dl className="ike-grid">
        <div className="ike-grid__item">
          <dt>Cipher</dt>
          <dd>{facts.cipher}</dd>
        </div>
        <div className="ike-grid__item">
          <dt>Mode</dt>
          <dd>{facts.mode}</dd>
        </div>
        <div className="ike-grid__item">
          <dt>DH group</dt>
          <dd>{facts.dh_group}</dd>
        </div>
        <div className="ike-grid__item">
          <dt>Forward secrecy</dt>
          <dd>{facts.pfs_enabled ? "Enabled" : "Disabled"}</dd>
        </div>
      </dl>

      <ul className="ike-findings">
        {facts.findings.map((f) => (
          <li key={f.factor} className="ike-findings__item">
            <span
              className="ike-findings__dot"
              style={{ background: ratingColor[f.rating] }}
            />
            <div>
              <p className="ike-findings__factor">{f.factor}</p>
              <p className="ike-findings__note">{plainEnglish ? f.plain : f.note}</p>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
