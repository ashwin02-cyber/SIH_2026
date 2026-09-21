import { useState, useRef } from "react";
import "./UploadPanel.css";

const MAX_MB = 50;

export default function UploadPanel({ onAnalyzeFile, onAnalyzeSample, busy, serverOnline, serverSamples, bundledSamples }) {
  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [localError, setLocalError] = useState(null);
  const inputRef = useRef(null);

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
      {!serverOnline && (
        <p className="upload-hint">
          The analysis server is offline, so uploads are disabled. You can still look at the bundled samples below.
        </p>
      )}

      <div className="samples">
        <p className="samples__title">Or try a sample</p>
        <div className="samples__list">
          {serverOnline
            ? serverSamples.map((name) => (
                <button key={name} className="samples__button" disabled={busy} onClick={() => onAnalyzeSample(name)}>
                  {name.replace(/_run1\.pcap$|\.pcap$/, "")}
                </button>
              ))
            : bundledSamples.map((s) => (
                <button key={s.key} className="samples__button" onClick={() => onAnalyzeSample(s)}>
                  {s.title}
                </button>
              ))}
        </div>
      </div>
    </section>
  );
}
