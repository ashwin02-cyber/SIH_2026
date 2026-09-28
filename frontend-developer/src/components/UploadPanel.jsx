import { useState, useRef } from "react";
import "./UploadPanel.css";
import "./ReplayPanel.css";

const MAX_MB = 50;

export default function UploadPanel({ onAnalyzeFile, onAnalyzeSample, busy, serverOnline, serverSamples, bundledSamples, replayMode, onReplayModeChange }) {
  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [localError, setLocalError] = useState(null);
  const [selectedSampleKey, setSelectedSampleKey] = useState("");
  const inputRef = useRef(null);

  // Server online: options are raw filenames (the API resolves them by name).
  // Server offline: options are the bundled samples, each carrying its own real analysis.
  const sampleOptions = serverOnline
    ? serverSamples.map((name) => ({
        value: name,
        label: name.replace(/_run1\.pcap$|\.pcap$/, ""),
      }))
    : bundledSamples.map((s) => ({
        value: s.key,
        label: s.meta
          ? `${s.meta.title} — ${s.meta.cipher}, ${s.meta.mode}, PFS ${s.meta.pfs} (${s.meta.risk_level})`
          : s.title,
      }));

  function handleLoadSample() {
    if (!selectedSampleKey) return;
    if (serverOnline) {
      onAnalyzeSample(selectedSampleKey);
    } else {
      const sample = bundledSamples.find((s) => s.key === selectedSampleKey);
      if (sample) onAnalyzeSample(sample);
    }
  }

  function handleFile(f) {
    if (!f) return;
    if (!/\.(pcap|pcapng)$/i.test(f.name)) {
      setLocalError("Please choose a .pcap or .pcapng file.");
      setFile(null);
      return;
    }
    if (f.size > MAX_MB * 1024 * 1024) {
      setLocalError(`That file is larger than ${MAX_MB} MB.`);
      setFile(null);
      return;
    }
    setLocalError(null);
    setFile(f);
  }

  function handleDrop(e) {
    e.preventDefault();
    setDragActive(false);
    handleFile(e.dataTransfer.files?.[0]);
  }

  return (
    <section className="panel">
      <h2 className="panel__title">Upload capture</h2>
      <div
        className={`upload-zone ${dragActive ? "upload-zone--active" : ""}`}
        role="button"
        tabIndex={0}
        onDragOver={(e) => {
          e.preventDefault();
          setDragActive(true);
        }}
        onDragLeave={() => setDragActive(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          hidden
          onChange={(e) => handleFile(e.target.files?.[0])}
        />
        {file ? (
          <p className="upload-zone__file">{file.name}</p>
        ) : (
          <>
            <p className="upload-zone__label">Drop a .pcap file here, or click to browse</p>
            <p className="upload-zone__hint">Up to {MAX_MB} MB. Best with a capture that includes IKE and ESP traffic.</p>
          </>
        )}
      </div>
      {localError && (
        <p className="upload-error" role="alert">
          {localError}
        </p>
      )}
      <button
        className="panel__button"
        disabled={!file || busy || !serverOnline}
        onClick={() => onAnalyzeFile(file)}
      >
        {busy ? "Analyzing..." : "Analyze capture"}
      </button>
      <label className="replay-toggle">
        <input type="checkbox" checked={replayMode} onChange={(e) => onReplayModeChange(e.target.checked)} disabled={busy} />
        <span>Replay as a stream: watch the analysis build up second by second. This is a replay of the capture file, not live sniffing.</span>
      </label>
      {!serverOnline && (
        <p className="upload-hint">
          The analysis server is offline, so uploads are disabled. You can still look at the bundled samples below.
        </p>
      )}

      <div className="samples">
        <p className="samples__title">Or load a sample file</p>
        <div className="samples__dropdown">
          <select
            className="samples__select"
            value={selectedSampleKey}
            disabled={busy || sampleOptions.length === 0}
            onChange={(e) => setSelectedSampleKey(e.target.value)}
          >
            <option value="">
              {sampleOptions.length === 0 ? "No sample files available" : "Choose a sample file..."}
            </option>
            {sampleOptions.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
          <button
            className="samples__load-button"
            disabled={busy || !selectedSampleKey}
            onClick={handleLoadSample}
          >
            {busy ? "Loading..." : "Load sample file"}
          </button>
        </div>
      </div>
    </section>
  );
}
