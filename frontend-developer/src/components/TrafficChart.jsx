import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import "./TrafficChart.css";

export default function TrafficChart({ classification }) {
  const { class: predictedClass, confidence, flows_analyzed, breakdown } = classification;

  return (
    <section className="panel">
      <div className="chart-header">
        <h2 className="panel__title">Traffic classification</h2>
        <p className="chart-header__meta">
          {flows_analyzed} flows analyzed &middot; top guess{" "}
          <strong>{predictedClass.replace("_", " ")}</strong> at {Math.round(confidence * 100)}%
        </p>
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={breakdown} layout="vertical" margin={{ left: 8, right: 24 }}>
          <XAxis type="number" domain={[0, 1]} hide />
          <YAxis
            type="category"
            dataKey="name"
            width={110}
            tick={{ fill: "var(--text-muted)", fontSize: 12 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            formatter={(value) => `${Math.round(value * 100)}%`}
            contentStyle={{
              background: "var(--surface-raised)",
              border: "1px solid var(--border)",
              borderRadius: 4,
              color: "var(--text)",
            }}
          />
          <Bar dataKey="value" radius={[0, 3, 3, 0]}>
            {breakdown.map((entry, i) => (
              <Cell
                key={entry.name}
                fill={i === 0 ? "var(--accent)" : "var(--accent-dim)"}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </section>
  );
}
