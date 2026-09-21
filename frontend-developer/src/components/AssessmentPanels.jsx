import "./AssessmentPanels.css";

const STATUS_TEXT = {
  observed: "observed",
  inferred: "inferred",
  declared: "declared (file name)",
  unknown: "unknown",
};

export function StatusChip({ status, confidence }) {
  const pct = status === "inferred" && confidence != null ? ` ${Math.round(confidence * 100)}%` : "";
  return (
    <span className={`status status--${status}`}>
      {STATUS_TEXT[status] ?? status}
      {pct}
    </span>
  );
}

// How much of what matters could actually be established from this capture, and every finding with its status.
export function CompletenessPanel({ assessment }) {
  const pct = Math.round(assessment.completeness_pct);
  return (
    <section className="panel">
      <h2 className="panel__title">Assessment completeness</h2>
      <div className="meter" role="img" aria-label={`Assessment completeness ${pct} percent`}>
        <div className="meter__fill" style={{ width: `${pct}%` }} />
      </div>
      <p className="assess__lead">
        <strong>{pct}%</strong> of the security facts that matter could be established from this capture.
        {assessment.score_capped && (
          <>
            {" "}
            The score is therefore capped at <strong>{assessment.score_cap}</strong>.
          </>
        )}
      </p>
      <ul className="findings">
        {assessment.findings.map((f) => (
          <li key={f.id} className="findings__item">
            <div className="findings__head">
              <span className="findings__title">{f.title}</span>
              <StatusChip status={f.status} confidence={f.confidence} />
            </div>
            <p className="findings__value">{f.value}</p>
            <p className="findings__evidence">{f.evidence}</p>
          </li>
        ))}
      </ul>
      {assessment.consistency_checks?.some((c) => !c.agree) && (
        <p className="assess__warn" role="alert">
          A value declared by the file name disagrees with the packet-size inference - see the explanation.
        </p>
      )}
    </section>
  );
}

const LEVEL_COLOR = { LOW: "var(--risk-low)", MEDIUM: "var(--risk-medium)", HIGH: "var(--risk-high)" };

// What an eavesdropper learns without any key.
export function ExposurePanel({ exposure }) {
  return (
    <section className="panel">
      <h2 className="panel__title">Metadata exposure</h2>
      <p className="assess__lead">
        What an eavesdropper learns without any key:{" "}
        <strong style={{ color: LEVEL_COLOR[exposure.level] }}>
          {exposure.score}/100 ({exposure.level})
        </strong>
      </p>
      <ul className="exposure">
        {exposure.items.map((i) => (
          <li key={i.what} className="exposure__item">
            <div className="exposure__row">
              <span>{i.what}</span>
              <span className="exposure__pts">
                {i.points} / {i.weight}
              </span>
            </div>
            <div className="meter meter--thin">
              <div className="meter__fill meter__fill--warn" style={{ width: `${i.exposed_fraction * 100}%` }} />
            </div>
            <p className="findings__evidence">
              {i.learned}. {i.why}.
            </p>
          </li>
        ))}
      </ul>
      <p className="findings__evidence">{exposure.note}</p>
    </section>
  );
}

const RESULT_TEXT = { meets: "meets", does_not_meet: "does not meet", cannot_assess: "cannot assess" };

// Guideline mapping - deliberately not called "compliance certified".
export function CompliancePanel({ compliance }) {
  return (
    <section className="panel">
      <h2 className="panel__title">Guideline mapping</h2>
      <p className="assess__warn">{compliance.label}</p>
      <ul className="checks">
        {compliance.checks.map((c) => (
          <li key={c.id} className="checks__item">
            <span className={`result result--${c.result}`}>{RESULT_TEXT[c.result]}</span>
            <div>
              <p className="checks__req">{c.requirement}</p>
              <p className="findings__evidence">
                {c.guideline} - {c.evidence} <StatusChip status={c.input_status} />
              </p>
            </div>
          </li>
        ))}
      </ul>
      <details className="notes">
        <summary>Not evaluated</summary>
        <ul>
          {compliance.not_evaluated.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      </details>
    </section>
  );
}
