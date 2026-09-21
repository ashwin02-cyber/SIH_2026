import { useState } from "react";
import "./ConfigComparison.css";

const levelColor = {
  LOW: "var(--risk-low)",
  MEDIUM: "var(--risk-medium)",
  HIGH: "var(--risk-high)",
  UNKNOWN: "var(--text-muted)",
};

// Compares the analysed capture with the bundled weak example (a real analysis of a weak
// testbed configuration: AES-CBC-128, DH group 2, transport mode).
export default function ConfigComparison({ current, weak }) {
  const [showWeak, setShowWeak] = useState(false);
  const config = showWeak ? weak : current;

  return (
    <section className="panel">
      <h2 className="panel__title">Compare against a weak setup</h2>
      <p className="compare__hint">See how a different set of choices changes the risk score.</p>

      <div className="compare__switch">
        <button
          className={`compare__option ${!showWeak ? "compare__option--active" : ""}`}
          onClick={() => setShowWeak(false)}
        >
          This capture
        </button>
        <button
          className={`compare__option ${showWeak ? "compare__option--active" : ""}`}
          onClick={() => setShowWeak(true)}
        >
          Weak example
        </button>
      </div>

      <div className="compare__result">
        <div className="compare__score" style={{ color: levelColor[config.risk_level] }}>
          {config.score ?? "n/a"}
          <span className="compare__level">{config.risk_level}</span>
        </div>
        <dl className="compare__details">
          <div>
            <dt>Cipher</dt>
            <dd>{config.cipher}</dd>
          </div>
          <div>
            <dt>Mode</dt>
            <dd>{config.mode}</dd>
          </div>
          <div>
            <dt>DH group</dt>
            <dd>{config.dh_group}</dd>
          </div>
          <div>
            <dt>Forward secrecy</dt>
            <dd>{config.pfs}</dd>
          </div>
        </dl>
      </div>
    </section>
  );
}
