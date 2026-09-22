import { useState } from "react";
import "./ConfigComparison.css";

const levelColor = {
  LOW: "var(--risk-low)",
  MEDIUM: "var(--risk-medium)",
  HIGH: "var(--risk-high)",
  UNKNOWN: "var(--text-muted)",
};

// Forward secrecy wording for this card: on / off / unknown. A real capture whose PFS cannot be
// determined stays "unknown"; only the fixed reference example (a defined configuration) is "off".
const PFS_TEXT = { enabled: "on", disabled: "off" };
const pfsLabel = (pfs) => PFS_TEXT[pfs] ?? pfs;

// Compares the analysed capture with a fixed weak REFERENCE configuration (not a capture):
// AES-CBC-128, DH group 2, transport mode, PFS off - scored by the same scoring engine.
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

      {showWeak && <p className="compare__note">{weak.note}</p>}

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
            <dd>{pfsLabel(config.pfs)}</dd>
          </div>
        </dl>
      </div>
    </section>
  );
}
