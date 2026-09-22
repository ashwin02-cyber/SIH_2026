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
import { CompletenessPanel, CompliancePanel, ExposurePanel } from "./components/AssessmentPanels";
import RecommendationsPanel from "./components/RecommendationsPanel";
import DefencePanel from "./components/DefencePanel";
import ReplayPanel from "./components/ReplayPanel";
import { analyzeFile, analyzeSample, checkHealth, listSamples, replayFile, replaySample } from "./api";
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
  const [replayMode, setReplayMode] = useState(false);
  const [replay, setReplay] = useState(null); // live state of a replay of a capture file

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

  // Replay of a capture file (not live sniffing): progressive events, then the full analysis.
  async function runReplay(start) {
    setBusy(true);
    setError(null);
    setAnalysis(null);
    setReplay({ label: "", windows: [], latest: null, total: 0, done: false });
    try {
      await start((ev) => {
        if (ev.type === "start") setReplay((r) => ({ ...r, label: ev.label, total: ev.total_windows }));
        else if (ev.type === "window") setReplay((r) => ({ ...r, windows: [...r.windows, ev], latest: ev }));
        else if (ev.type === "end") setReplay((r) => ({ ...r, done: true }));
        else if (ev.type === "final") {
          setAnalysis(ev.analysis);
          setSource("server");
        } else if (ev.type === "error") setError(ev.detail);
      });
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
      setReplay((r) => (r ? { ...r, done: true } : r));
    }
  }

  const handleAnalyzeFile = (file) => (replayMode ? runReplay((on) => replayFile(file, on)) : run(() => analyzeFile(file)));

  function handleAnalyzeSample(sample) {
    if (typeof sample === "string") return replayMode ? runReplay((on) => replaySample(sample, on)) : run(() => analyzeSample(sample));
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
            replayMode={replayMode}
            onReplayModeChange={setReplayMode}
          />
          {error && (
            <div className="banner banner--error" role="alert">
              <strong>Analysis failed.</strong> {error}
            </div>
          )}
          {analysis && <IkeFactsPanel analysis={analysis} plainEnglish={plainEnglish} />}
          {analysis && <ExplanationPanel analysis={analysis} />}
          {analysis && <CompletenessPanel assessment={analysis.assessment} />}
          {analysis && <ConfigComparison current={analysis} weak={weakExample} />}
        </div>
        <div className="dashboard__column">
          {busy && !replay && <div className="banner">Analyzing capture - this can take a few seconds for large files...</div>}
          {replay && !analysis && <ReplayPanel replay={replay} />}
          {!analysis && !busy && !replay && (
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
              <RiskGauge score={analysis.score} level={analysis.risk_level} basis={analysis.score_basis} assessment={analysis.assessment} />
              <ThreatMatrix breakdown={analysis.breakdown} />
              <TrafficChart traffic={analysis.traffic} capture={analysis.capture} />
              <TimelineScrubber timeline={analysis.timeline} windowSec={analysis.capture?.window_sec} />
              <RecommendationsPanel recommendations={analysis.recommendations} />
              <DefencePanel simulation={analysis.details?.defence_simulation} />
              <AnomaliesList anomalies={analysis.anomalies} />
              <ExposurePanel exposure={analysis.assessment.metadata_exposure} />
              <CompliancePanel compliance={analysis.assessment.compliance} />
            </>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
