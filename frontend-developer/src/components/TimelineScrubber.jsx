import { useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { trafficClassColor, trafficClassLabel } from "../data/mockData";
import "./TimelineScrubber.css";

function WindowTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const w = payload[0].payload;
  return (
    <div className="timeline__tooltip">
      <strong>{w.label}</strong>
      <span>
        {w.start_sec}s - {w.end_sec}s
      </span>
      <span>{Math.round(w.confidence * 100)}% confidence</span>
      <span>
        {w.packets} packets, {w.bytes.toLocaleString()} bytes
      </span>
    </div>
  );
}

// One bar per fixed time window: height = the model's confidence, colour = predicted traffic class.
export default function TimelineScrubber({ timeline, windowSec }) {
  const [active, setActive] = useState(null);

  if (!timeline.length) {
    return (
      <section className="panel">
        <h2 className="panel__title">Traffic timeline</h2>
        <p className="timeline__meta">No time windows with enough packets to classify.</p>
      </section>
    );
  }

  const shown = active ?? timeline[0];
  const present = [...new Set(timeline.map((t) => t.class))];

  return (
    <section className="panel">
      <h2 className="panel__title">Traffic timeline</h2>
      <p className="timeline__meta">
        {windowSec ?? 1}-second windows &middot; window {shown.window} ({shown.start_sec}s-{shown.end_sec}s):{" "}
        <strong>{shown.label}</strong> at {Math.round(shown.confidence * 100)}% confidence
      </p>
      <div className="timeline__chart" aria-label="Predicted traffic type for each time window">
        <ResponsiveContainer width="100%" height={150}>
          <BarChart
            data={timeline}
            margin={{ top: 4, right: 8, left: -18, bottom: 0 }}
            onMouseMove={(state) => {
              const idx = Number(state?.activeTooltipIndex);
              if (Number.isInteger(idx) && timeline[idx]) setActive(timeline[idx]);
            }}
            onMouseLeave={() => setActive(null)}
          >
            <XAxis
              dataKey="start_sec"
              tick={{ fill: "var(--text-muted)", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              unit="s"
              interval="preserveStartEnd"
            />
            <YAxis
              domain={[0, 1]}
              ticks={[0, 0.5, 1]}
              tickFormatter={(v) => `${v * 100}%`}
              tick={{ fill: "var(--text-muted)", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<WindowTooltip />} cursor={{ fill: "rgba(255,255,255,0.06)" }} />
            <Bar dataKey="confidence" radius={[3, 3, 0, 0]} isAnimationActive={false}>
              {timeline.map((seg) => (
                <Cell key={seg.window} fill={trafficClassColor[seg.class] ?? "var(--accent)"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="timeline__legend">
        {present.map((cls) => (
          <span key={cls} className="timeline__legend-item">
            <span className="timeline__legend-dot" style={{ background: trafficClassColor[cls] }} />
            {trafficClassLabel[cls] ?? cls}
          </span>
        ))}
      </div>
    </section>
  );
}
