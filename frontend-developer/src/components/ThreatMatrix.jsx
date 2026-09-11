import "./ThreatMatrix.css";

const severityByRating = {
  strong: "Low",
  medium: "Medium",
  weak: "High",
};

const columns = ["Low", "Medium", "High"];

const columnColor = {
  Low: "var(--risk-low)",
  Medium: "var(--risk-medium)",
  High: "var(--risk-high)",
};

export default function ThreatMatrix({ findings }) {
  return (
    <section className="panel">
      <h2 className="panel__title">Threat matrix</h2>
      <div className="matrix">
        <div className="matrix__row matrix__row--header">
          <span className="matrix__row-label" />
          {columns.map((c) => (
            <span key={c} className="matrix__col-label">
              {c}
            </span>
          ))}
        </div>
        {findings.map((f) => {
          const severity = severityByRating[f.rating];
          return (
            <div key={f.factor} className="matrix__row">
              <span className="matrix__row-label">{f.factor}</span>
              {columns.map((c) => (
                <span
                  key={c}
                  className="matrix__cell"
                  style={
                    c === severity
                      ? { background: columnColor[c], opacity: 1 }
                      : undefined
                  }
                />
              ))}
            </div>
          );
        })}
      </div>
    </section>
  );
}
