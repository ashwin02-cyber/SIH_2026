import "./AnomaliesList.css";

const severityColor = {
  HIGH: "var(--risk-high)",
  MEDIUM: "var(--risk-medium)",
  LOW: "var(--risk-low)",
};

export default function AnomaliesList({ anomalies }) {
  return (
    <section className="panel">
      <h2 className="panel__title">Anomalies detected</h2>
      {anomalies.length === 0 ? (
        <p className="anomalies__empty">No anomalies found in this capture.</p>
      ) : (
        <ul className="anomalies">
          {anomalies.map((a, i) => (
            <li key={i} className="anomalies__item">
              <span
                className="anomalies__badge"
                style={{ color: severityColor[a.severity], borderColor: severityColor[a.severity] }}
              >
                {a.severity}
              </span>
              <p className="anomalies__desc">{a.description}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
