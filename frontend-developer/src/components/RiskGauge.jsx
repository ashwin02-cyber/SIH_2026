import "./RiskGauge.css";

const levelColor = {
  LOW: "var(--risk-low)",
  MEDIUM: "var(--risk-medium)",
  HIGH: "var(--risk-high)",
};

export default function RiskGauge({ score, level }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <section className="panel">
      <h2 className="panel__title">Security risk score</h2>
      <div className="gauge">
        <svg width="140" height="140" viewBox="0 0 140 140">
          <circle
            cx="70"
            cy="70"
            r={radius}
            fill="none"
            stroke="var(--border)"
            strokeWidth="10"
          />
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
          <span className="gauge__score">{score}</span>
          <span className="gauge__level" style={{ color: levelColor[level] }}>
            {level}
          </span>
        </div>
      </div>
    </section>
  );
}
