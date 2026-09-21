import "./ExplanationPanel.css";

export default function ExplanationPanel({ analysis }) {
  const { explanation, warnings, errors, capture } = analysis;
  return (
    <section className="panel">
      <h2 className="panel__title">Why this result</h2>
      {errors.length > 0 && (
        <ul className="notes notes--error" role="alert">
          {errors.map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      )}
      <ul className="explain">
        {explanation.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
      {capture && (
        <p className="explain__meta">
          {capture.packets.toLocaleString()} {capture.esp_only ? "ESP" : "IP"} packets, {capture.span_sec}s of traffic
          {capture.truncated ? " (capture truncated)" : ""}.
        </p>
      )}
      {warnings.length > 0 && (
        <details className="notes">
          <summary>{warnings.length} note(s) about what this capture can and cannot show</summary>
          <ul>
            {warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}
