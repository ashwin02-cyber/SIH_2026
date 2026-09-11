// Mock data — matches the shape ML Engineer's predict.py and Backend's
// IKE parser are expected to return. Swap the functions in api.js later
// to fetch this from the real backend instead.

export const mockIkeFacts = {
  cipher: "AES-256-CBC",
  mode: "tunnel",
  dh_group: 14,
  pfs_enabled: true,
  findings: [
    {
      factor: "Cipher",
      rating: "strong",
      note: "AES-256-CBC is a strong, modern cipher choice",
      plain: "The lock itself is one of the toughest available today.",
    },
    {
      factor: "DH Group",
      rating: "medium",
      note: "Group 14 is acceptable; Group 19+ (ECC) is stronger",
      plain: "The key exchange method is decent, but not the strongest option out there.",
    },
    {
      factor: "Mode",
      rating: "strong",
      note: "Tunnel mode encrypts the full original packet",
      plain: "The entire package is hidden, not just what's inside it.",
    },
    {
      factor: "PFS",
      rating: "strong",
      note: "Perfect Forward Secrecy is enabled",
      plain: "Even if a key leaks later, past conversations stay safe.",
    },
  ],
};

export const mockRiskScore = {
  score: 72,
  level: "MEDIUM",
};

export const mockClassification = {
  class: "video_streaming",
  confidence: 0.87,
  flows_analyzed: 42,
  explanation: ["packet_size_std", "avg_interarrival_time", "burst_ratio"],
  breakdown: [
    { name: "Video streaming", value: 0.87 },
    { name: "Web browsing", value: 0.06 },
    { name: "VoIP", value: 0.04 },
    { name: "File transfer", value: 0.02 },
    { name: "ICMP", value: 0.01 },
  ],
};

export const mockAnomalies = [
  { severity: "MEDIUM", description: "Unusual burst pattern detected in segment 2" },
  { severity: "LOW", description: "Minor jitter above baseline in segment 4" },
];

// Segment-by-segment classification over the capture's duration —
// mirrors the "timeline" field in ML Engineer's predict.py output.
export const mockTimeline = [
  { segment: 1, class: "web_browsing", confidence: 0.81 },
  { segment: 2, class: "video_streaming", confidence: 0.93 },
  { segment: 3, class: "video_streaming", confidence: 0.89 },
  { segment: 4, class: "video_streaming", confidence: 0.76 },
  { segment: 5, class: "file_transfer", confidence: 0.68 },
  { segment: 6, class: "video_streaming", confidence: 0.91 },
  { segment: 7, class: "voip", confidence: 0.72 },
  { segment: 8, class: "icmp", confidence: 0.95 },
];

export const trafficClassColor = {
  web_browsing: "#4EA8DE",
  video_streaming: "#8B5CF6",
  voip: "#34D399",
  file_transfer: "#FBBF24",
  icmp: "#F87171",
};

// Two configs for the before/after comparison — the "current" capture
// vs. a deliberately weak example, so the risk difference is visible.
export const mockConfigs = {
  current: {
    label: "This capture",
    cipher: "AES-256-CBC",
    mode: "tunnel",
    dh_group: 14,
    pfs_enabled: true,
    score: 72,
    level: "MEDIUM",
  },
  weak: {
    label: "Weak example",
    cipher: "AES-128-CBC",
    mode: "transport",
    dh_group: 2,
    pfs_enabled: false,
    score: 28,
    level: "HIGH",
  },
};
