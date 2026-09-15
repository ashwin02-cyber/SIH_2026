import "./PlainEnglishToggle.css";

export default function PlainEnglishToggle({ plainEnglish, onChange }) {
  return (
    <label className="toggle">
      <span className="toggle__label">
        {plainEnglish ? "Plain English" : "Technical terms"}
      </span>
      <button
        type="button"
        role="switch"
        aria-checked={plainEnglish}
        className={`toggle__switch ${plainEnglish ? "toggle__switch--on" : ""}`}
        onClick={() => onChange(!plainEnglish)}
      >
        <span className="toggle__knob" />
      </button>
    </label>
  );
}
