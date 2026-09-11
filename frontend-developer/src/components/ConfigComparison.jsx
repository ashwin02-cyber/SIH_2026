import { useState } from "react";
import "./ConfigComparison.css";

const levelColor = {
  LOW: "var(--risk-low)",
  MEDIUM: "var(--risk-medium)",
  HIGH: "var(--risk-high)",
};

export default function ConfigComparison({ configs }) {
  const [showWeak, setShowWeak] = useState(false);
  const config = showWeak ? configs.weak : configs.current;

  return (
    <section className="panel">
      <h2 className="panel__title">Compare against a weak setup</h2>
      <p className="compare__hint">
        See how a different set of choices changes the risk score.
      </p>

      <div className="compare__switch">
        <button
          className={`compare__option ${!showWeak ? "compare__option--active" : ""}`}
          onClick={() => setShowWeak(false)}
        >
          {configs.current.label}
        </button>
        <button
          className={`compare__option ${showWeak ? "compare__option--active" : ""}`}
          onClick={() => setShowWeak(true)}
        >
          {configs.weak.label}
        </button>
      </div>

      <div className="compare__result">
        <div className="compare__score" style={{ color: levelColor[config.level] }}>
          {config.score}
          <span className="compare__level">{config.level}</span>
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
            <dd>{config.pfs_enabled ? "Enabled" : "Disabled"}</dd>
          </div>
        </dl>
      </div>
    </section>
  );
}
