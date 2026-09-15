import { useState } from "react";
import Header from "./components/Header";
import UploadPanel from "./components/UploadPanel";
import IkeFactsPanel from "./components/IkeFactsPanel";
import RiskGauge from "./components/RiskGauge";
import TrafficChart from "./components/TrafficChart";
import AnomaliesList from "./components/AnomaliesList";
import ThreatMatrix from "./components/ThreatMatrix";
import TimelineScrubber from "./components/TimelineScrubber";
import ConfigComparison from "./components/ConfigComparison";
import {
  mockIkeFacts,
  mockRiskScore,
  mockClassification,
  mockAnomalies,
  mockTimeline,
  mockConfigs,
} from "./data/mockData";
import "./App.css";

function App() {
  const [plainEnglish, setPlainEnglish] = useState(false);

  function handleAnalyze(fileName) {
    // Placeholder for now — once Backend Developer's API is ready,
    // this will POST the file and replace the mock data below with
    // the real response.
    console.log("Analyzing:", fileName);
  }

  return (
    <div className="app">
      <Header plainEnglish={plainEnglish} onTogglePlainEnglish={setPlainEnglish} />
      <main className="dashboard" id="dashboard-content">
        <div className="dashboard__column">
          <UploadPanel onAnalyze={handleAnalyze} />
          <IkeFactsPanel facts={mockIkeFacts} plainEnglish={plainEnglish} />
          <ConfigComparison configs={mockConfigs} />
        </div>
        <div className="dashboard__column">
          <RiskGauge score={mockRiskScore.score} level={mockRiskScore.level} />
          <ThreatMatrix findings={mockIkeFacts.findings} />
          <TrafficChart classification={mockClassification} />
          <TimelineScrubber timeline={mockTimeline} />
          <AnomaliesList anomalies={mockAnomalies} />
        </div>
      </main>
    </div>
  );
}

export default App;
