import { useState, useRef } from "react";
import "./UploadPanel.css";

export default function UploadPanel({ onAnalyze }) {
  const [fileName, setFileName] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const inputRef = useRef(null);

  function handleFile(file) {
    if (!file) return;
    setFileName(file.name);
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
        onDragOver={(e) => {
          e.preventDefault();
          setDragActive(true);
        }}
        onDragLeave={() => setDragActive(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          hidden
          onChange={(e) => handleFile(e.target.files?.[0])}
        />
        {fileName ? (
          <p className="upload-zone__file">{fileName}</p>
        ) : (
          <>
            <p className="upload-zone__label">Drop a .pcap file here, or click to browse</p>
            <p className="upload-zone__hint">Captures should include IKE and ESP traffic</p>
          </>
        )}
      </div>
      <button
        className="panel__button"
        disabled={!fileName}
        onClick={() => onAnalyze?.(fileName)}
      >
        Analyze capture
      </button>
    </section>
  );
}
