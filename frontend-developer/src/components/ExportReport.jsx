import { useState } from "react";
import html2canvas from "html2canvas";
import "./ExportReport.css";

export default function ExportReport({ targetId }) {
  const [busy, setBusy] = useState(false);

  async function handleExport() {
    const node = document.getElementById(targetId);
    if (!node) return;
    setBusy(true);
    try {
      const canvas = await html2canvas(node, {
        backgroundColor: "#0D1321",
        scale: 2,
      });
      const link = document.createElement("a");
      link.download = "vpn-analysis-report.png";
      link.href = canvas.toDataURL("image/png");
      link.click();
    } finally {
      setBusy(false);
    }
  }

  return (
    <button className="export-btn" onClick={handleExport} disabled={busy}>
      {busy ? "Preparing..." : "Download report"}
    </button>
  );
}
