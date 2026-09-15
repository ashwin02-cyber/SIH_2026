import PlainEnglishToggle from "./PlainEnglishToggle";
import ExportReport from "./ExportReport";
import "./Header.css";

export default function Header({ plainEnglish, onTogglePlainEnglish }) {
  return (
    <header className="header">
      <div>
        <h1 className="header__title">IPsec VPN traffic analyzer</h1>
        <p className="header__subtitle">Upload a capture to see how it was secured</p>
      </div>
      <div className="header__controls">
        <PlainEnglishToggle plainEnglish={plainEnglish} onChange={onTogglePlainEnglish} />
        <ExportReport targetId="dashboard-content" />
        <div className="header__status">
          <span className="header__status-dot" />
          Analysis engine ready
        </div>
      </div>
    </header>
  );
}
