import "./ThreatMatrix.css";

// A factor's rating decides which column is lit. "unknown" gets its own column so a factor that
// could not be determined is never shown as safe (or as dangerous).
const columnByRating = { strong: "Low", medium: "Medium", weak: "High", unknown: "Unknown" };
const columns = ["Low", "Medium", "High", "Unknown"];
const columnColor = {
  Low: "var(--risk-low)",
  Medium: "var(--risk-medium)",
  High: "var(--risk-high)",
  Unknown: "var(--text-muted)",
};

export default function ThreatMatrix({ breakdown }) {
  return (
    <section className="panel">
      <h2 className="panel__title">Threat matrix</h2>
      <div className="matrix" role="table" aria-label="Risk per security factor">
        <div className="matrix__row matrix__row--header" role="row">
          <span className="matrix__row-label" />
          {columns.map((c) => (
            <span key={c} className="matrix__col-label" role="columnheader">
              {c}
            </span>
          ))}
        </div>
        {breakdown.map((b) => {
          const active = columnByRating[b.rating];
          return (
            <div key={b.factor} className="matrix__row" role="row">
              <span className="matrix__row-label" role="rowheader" title={b.value}>
                {b.factor}
              </span>
              {columns.map((c) => (
                <span
                  key={c}
                  role="cell"
                  aria-label={c === active ? `${b.factor}: ${c}` : undefined}
                  className="matrix__cell"
                  style={c === active ? { background: columnColor[c], opacity: 1 } : undefined}
                />
              ))}
            </div>
          );
        })}
      </div>
    </section>
  );
}
