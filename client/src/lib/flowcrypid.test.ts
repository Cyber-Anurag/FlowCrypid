import { describe, expect, it } from "vitest";
import { asTimestamp, isSeverity, normalizeFinding } from "./flowcrypid";

describe("FlowCrypid contracts", () => {
  it("accepts only known severity tiers", () => {
    expect(isSeverity("P0")).toBe(true);
    expect(isSeverity("P6")).toBe(false);
    expect(isSeverity(null)).toBe(false);
  });

  it("normalizes incomplete findings safely", () => {
    const finding = normalizeFinding({ title: "Test", risk_score: 91, explanation: ["Threshold exceeded"] }, 2);
    expect(finding.id).toBe("finding-3");
    expect(finding.tier).toBe("P2");
    expect(finding.risk_score).toBe(91);
    expect(finding.explanation).toEqual(["Threshold exceeded"]);
  });

  it("normalizes seconds, milliseconds, ISO dates, and fallback timestamps", () => {
    expect(asTimestamp(1_700_000_000, 0)).toBe(1_700_000_000);
    expect(asTimestamp(1_700_000_000_000, 0)).toBe(1_700_000_000);
    expect(asTimestamp("2023-11-14T22:13:20Z", 0)).toBe(1_700_000_000);
    expect(asTimestamp("invalid", 42)).toBe(42);
  });
});
