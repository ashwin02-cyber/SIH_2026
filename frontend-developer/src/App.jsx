import { useEffect, useState } from "react";
import Header from "./components/Header";
import UploadPanel from "./components/UploadPanel";
import IkeFactsPanel from "./components/IkeFactsPanel";
import RiskGauge from "./components/RiskGauge";
import TrafficChart from "./components/TrafficChart";
import AnomaliesList from "./components/AnomaliesList";
import ThreatMatrix from "./components/ThreatMatrix";
import TimelineScrubber from "./components/TimelineScrubber";
import ConfigComparison from "./components/ConfigComparison";
import ExplanationPanel from "./components/ExplanationPanel";
import { analyzeFile, analyzeSample, checkHealth, listSamples } from "./api";
import { bundledSamples, weakExample } from "./data/mockData";
import "./App.css";

function App() {
  const [plainEnglish, setPlainEnglish] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [source, setSource] = useState(null); // "server" | "bundled"
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [serverChecked, setServerChecked] = useState(false);
  const [serverOnline, setServerOnline] = useState(false);
  const [serverSamples, setServerSamples] = useState([]);

  useEffect(() => {
    let cancelled = false;
    checkHealth()
      .then(async (health) => {
        const samples = await listSamples().catch(() => []);
        if (cancelled) return;
        setServerOnline(health.status === "ok");
        setServerSamples(samples);
        setServerChecked(true);
      })
      .catch(() => {
        if (cancelled) return;
        setServerOnline(false);
        setServerChecked(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function run(task) {
    setBusy(true);
    setError(null);
    setAnalysis(null); // never show the previous file's results next to a new file name
    try {
      setAnalysis(await task());
      setSource("server");
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const handleAnalyzeFile = (file) => run(() => analyzeFile(file));

  function handleAnalyzeSample(sample) {
    if (typeof sample === "string") return run(() => analyzeSample(sample));
    // A bundled (offline) sample: real API output that ships with the app.
    setError(null);
    setAnalysis(sample.analysis);
    setSource("bundled");
  }

  return (
    <div className="app">
      <Header
        plainEnglish={plainEnglish}
        onTogglePlainEnglish={setPlainEnglish}
        analysis={analysis}
        serverOnline={serverOnline}
        serverChecked={serverChecked}
      />
      <main className="dashboard" id="dashboard-content">
        <div className="dashboard__column">
          <UploadPanel
            onAnalyzeFile={handleAnalyzeFile}
            onAnalyzeSample={handleAnalyzeSample}
            busy={busy}
            serverOnline={serverOnline}
            serverSamples={serverSamples}
            bundledSamples={bundledSamples}
          />
          {error && (
            <div className="banner banner--error" role="alert">
              <strong>Analysis failed.</strong> {error}
            </div>
          )}
          {analysis && <IkeFactsPanel analysis={analysis} plainEnglish={plainEnglish} />}
          {analysis && <ExplanationPanel analysis={analysis} />}
          {analysis && <ConfigComparison current={analysis} weak={weakExample} />}
        </div>
        <div className="dashboard__column">
          {busy && <div className="banner">Analyzing capture - this can take a few seconds for large files...</div>}
          {!analysis && !busy && (
            <section className="panel empty">
              <h2 className="panel__title">No capture analyzed yet</h2>
              <p>
                Upload a .pcap file, or pick a sample on the left, to see the security score, threat matrix,
                traffic classification and timeline.
              </p>
            </section>
          )}
          {analysis && (
            <>
              {source === "bundled" && (
                <div className="banner">
                  Showing a bundled sample analysis (real output from the analyzer, saved with the app).
                </div>
              )}
              <RiskGauge score={analysis.score} level={analysis.risk_level} basis={analysis.score_basis} />
              <ThreatMatrix breakdown={analysis.breakdown} />
              <TrafficChart traffic={analysis.traffic} capture={analysis.capture} />
              <TimelineScrubber timeline={analysis.timeline} windowSec={analysis.capture?.window_sec} />
              <AnomaliesList anomalies={analysis.anomalies} />
            </>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
