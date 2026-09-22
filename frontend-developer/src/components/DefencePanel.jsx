import "./DefencePanel.css";

const pct = (x) => `${Math.round(x * 100)}%`;

function Bar({ value }) {
  return (
    <div className="meter meter--thin" aria-hidden="true">
      <div className="meter__fill" style={{ width: `${value * 100}%` }} />
    </div>
  );
}

// What-if defence simulator. Everything here is a SIMULATION and is labelled as one.
export default function DefencePanel({ simulation }) {
  if (!simulation) return null;
  if (!simulation.available) {
    return (
      <section className="panel">
        <h2 className="panel__title">Defence what-if (simulation)</h2>
        <p className="assess__lead">Not available for this capture: {simulation.reason}.</p>
      </section>
    );
  }
  const { baseline, defences, population } = simulation;
  const popRows = population ? Object.entries(population.defences) : [];
  const worstAdaptive = popRows.length ? Math.min(...popRows.map(([, r]) => r.adaptive_capture_accuracy)) : null;

  return (
    <section className="panel">
      <h2 className="panel__title">Defence what-if</h2>
      <p className="sim-banner" role="note">
        SIMULATION
      </p>
      <p className="assess__warn">{simulation.label}</p>

      <h3 className="recs__sub">This capture</h3>
      <p className="findings__evidence">
        Without a defence the classifier says: <strong>{baseline.class}</strong> ({pct(baseline.confidence)}).
      </p>
      <table className="sim-table">
        <thead>
          <tr>
            <th>Defence</th>
            <th>Classifier then says</th>
            <th>Bandwidth</th>
            <th>Delay</th>
          </tr>
        </thead>
        <tbody>
          {defences.map((d) => (
            <tr key={d.id} className={d.changes_answer ? "sim-table__changed" : ""}>
              <td title={d.description}>{d.label}</td>
              <td>
                {d.result ? `${d.result.class} (${pct(d.result.confidence)})` : "too sparse"}
                {d.changes_answer ? " - changed" : ""}
              </td>
              <td>+{d.cost.bandwidth_overhead_pct}%</td>
              <td>{d.cost.mean_added_delay_ms} ms</td>
            </tr>
          ))}
        </tbody>
      </table>

      {population && (
        <>
          <h3 className="recs__sub">Across the {population.captures} lab captures (unseen VPN configurations)</h3>
          <table className="sim-table">
            <thead>
              <tr>
                <th>Defence</th>
                <th>Naive attacker</th>
                <th>Adaptive attacker</th>
                <th>Median bandwidth</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>No defence</td>
                <td>
                  {pct(population.baseline.non_adaptive_capture_accuracy)}
                  <Bar value={population.baseline.non_adaptive_capture_accuracy} />
                </td>
                <td>-</td>
                <td>0%</td>
              </tr>
              {popRows.map(([id, r]) => (
                <tr key={id}>
                  <td>{r.label}</td>
                  <td>
                    {pct(r.non_adaptive_capture_accuracy)}
                    <Bar value={r.non_adaptive_capture_accuracy} />
                  </td>
                  <td>
                    {pct(r.adaptive_capture_accuracy)}
                    <Bar value={r.adaptive_capture_accuracy} />
                  </td>
                  <td>+{r.cost.bandwidth_overhead_pct_median}%</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="findings__evidence">
            Naive attacker = classifier trained on clean traffic. Adaptive attacker = retrained on defended traffic. Chance level is{" "}
            {pct(population.chance_level_capture_accuracy)}.{" "}
            {worstAdaptive !== null && worstAdaptive >= 0.95 && (
              <strong>
                On this lab dataset every simulated defence still leaves an adaptive attacker at {pct(worstAdaptive)} or better: the traffic types
                differ too much in rate and timing for padding alone to hide them, and the stronger defences cost a lot of bandwidth.
              </strong>
            )}
          </p>
        </>
      )}
    </section>
  );
}
