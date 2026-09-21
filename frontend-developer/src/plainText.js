// Plain-English wording for the "Plain English" toggle. The technical wording comes from the API
// (breakdown[].reason); this is only the simplified alternative, keyed by factor and rating.
const PLAIN = {
  Cipher: {
    strong: "The lock itself is one of the toughest available today.",
    medium: "The lock is decent, but it relies on a second mechanism to notice tampering.",
    weak: "The lock is outdated and could be broken with enough effort.",
    unknown: "We could not tell which lock (encryption) is used.",
  },
  "DH group": {
    strong: "The way the two sides agree on a secret key is modern and strong.",
    medium: "The key agreement is acceptable today, but has little safety margin for the future.",
    weak: "The key agreement is too small by modern standards and could be attacked.",
    unknown: "We could not tell how the two sides agreed on their secret key.",
  },
  PFS: {
    strong: "Even if a key leaks later, past conversations stay safe.",
    medium: "Past conversations are only partly protected if a key leaks.",
    weak: "If one key leaks, every past conversation could be read.",
    unknown: "This capture cannot show whether past conversations stay safe if a key leaks.",
  },
  Mode: {
    strong: "The entire package is hidden, not just what's inside it.",
    medium: "Only the contents are hidden; the addresses on the outside stay visible.",
    weak: "The packaging gives little protection.",
    unknown: "This capture cannot show how the packages are wrapped.",
  },
};

export function plainFor(factor, rating) {
  return PLAIN[factor]?.[rating] ?? "";
}
