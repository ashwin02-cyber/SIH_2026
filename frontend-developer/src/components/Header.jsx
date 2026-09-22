import PlainEnglishToggle from "./PlainEnglishToggle";
import ExportReport from "./ExportReport";
import "./Header.css";

export default function Header({ plainEnglish, onTogglePlainEnglish, analysis, serverOnline, serverChecked }) {
  const statusText = !serverChecked
    ? "Checking analysis engine..."
    : serverOnline
      ? "Analysis engine ready"
      : "Analysis engine offline";
  const dotClass = !serverChecked ? "header__status-dot--wait" : serverOnline ? "" : "header__status-dot--off";

  return (
    <header className="header">
      <div>
        <h1 className="header__title">IPsec VPN traffic analyzer</h1>
        <p className="header__subtitle">Upload a capture to see how it was secured</p>
      </div>
      <div className="header__controls">
        <PlainEnglishToggle plainEnglish={plainEnglish} onChange={onTogglePlainEnglish} />
        <ExportReport analysis={analysis} serverOnline={serverOnline} />
        <div className="header__status" role="status">
          <span className={`header__status-dot ${dotClass}`} />
          {statusText}
        </div>
      </div>
    </header>
  );
}
