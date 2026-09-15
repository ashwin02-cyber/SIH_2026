import { useState } from "react";
import { trafficClassColor } from "../data/mockData";
import "./TimelineScrubber.css";

export default function TimelineScrubber({ timeline }) {
  const [active, setActive] = useState(null);
  const shown = active ?? timeline[0];

  return (
    <section className="panel">
      <h2 className="panel__title">Traffic timeline</h2>
      <p className="timeline__meta">
        Segment {shown.segment} &middot;{" "}
        <strong>{shown.class.replace("_", " ")}</strong> at{" "}
        {Math.round(shown.confidence * 100)}% confidence
      </p>
      <div className="timeline">
        {timeline.map((seg) => (
          <button
            key={seg.segment}
            className="timeline__segment"
            style={{ background: trafficClassColor[seg.class] }}
            onMouseEnter={() => setActive(seg)}
            onFocus={() => setActive(seg)}
            onMouseLeave={() => setActive(null)}
            onBlur={() => setActive(null)}
            aria-label={`Segment ${seg.segment}: ${seg.class}, ${Math.round(seg.confidence * 100)}% confidence`}
          />
        ))}
      </div>
      <div className="timeline__legend">
        {Object.entries(trafficClassColor).map(([cls, color]) => (
          <span key={cls} className="timeline__legend-item">
            <span className="timeline__legend-dot" style={{ background: color }} />
            {cls.replace("_", " ")}
          </span>
        ))}
      </div>
    </section>
  );
}
