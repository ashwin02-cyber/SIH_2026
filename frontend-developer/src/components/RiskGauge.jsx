import "./RiskGauge.css";

const levelColor = {
  LOW: "var(--risk-low)",
  MEDIUM: "var(--risk-medium)",
  HIGH: "var(--risk-high)",
  UNKNOWN: "var(--text-muted)",
};

const basisNote = {
  observed: "Based on values read from the capture.",
  declared: "Based on the configuration named in the file name (declared by the testbed), not read from the capture.",
  mixed: "Some values were read from the capture, others come from the file name.",
  none: "The capture does not reveal the cipher or key exchange, so no score can be given.",
};

export default function RiskGauge({ score, level, basis }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const shown = score ?? 0;
  const offset = circumference - (shown / 100) * circumference;

  return (
    <section className="panel">
      <h2 className="panel__title">Security risk score</h2>
      <div className="gauge">
        <svg width="140" height="140" viewBox="0 0 140 140" role="img" aria-label={`Security score ${score ?? "unknown"} out of 100, ${level} risk`}>
          <circle cx="70" cy="70" r={radius} fill="none" stroke="var(--border)" strokeWidth="10" />
          <circle
            cx="70"
            cy="70"
            r={radius}
            fill="none"
            stroke={levelColor[level]}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            transform="rotate(-90 70 70)"
          />
        </svg>
        <div className="gauge__center">
          <span className="gauge__score">{score ?? "n/a"}</span>
          <span className="gauge__level" style={{ color: levelColor[level] }}>
            {level}
          </span>
        </div>
      </div>
      <p className="gauge__note">{basisNote[basis]}</p>
    </section>
  );
}
