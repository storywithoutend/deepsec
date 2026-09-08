import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@deepsec/core", async (importOriginal) => ({
  ...((await importOriginal()) as Record<string, unknown>),
  readProjectConfig: vi.fn(() => ({ projectId: "proj", rootPath: "/tmp/proj" })),
}));

vi.mock("@deepsec/processor", async (importOriginal) => ({
  ...((await importOriginal()) as Record<string, unknown>),
  triage: vi.fn(async () => ({ triaged: 0, p0: 0, p1: 0, p2: 0, skip: 0 })),
}));

vi.mock("../resolve-project-id.js", () => ({
  resolveProjectId: vi.fn(() => "proj"),
}));

vi.mock("../preflight.js", () => ({
  applyConfiguredModelRoute: vi.fn(async () => {}),
  assertAgentCredential: vi.fn(),
  assertSageCredential: vi.fn(),
}));

import { SAGE_MODEL_NAME, triage } from "@deepsec/processor";
import { triageCommand } from "../commands/triage.js";

describe("triageCommand option resolution", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  it("rejects a non-numeric --min-confidence instead of failing every Sage verdict", async () => {
    // `parseFloat("0.8.5")` yields NaN, which would make the confidence floor
    // reject every Sage decision and silently re-triage the corpus with Claude.
    await expect(triageCommand({ provider: "sage", minConfidence: Number.NaN })).rejects.toThrow(
      /--min-confidence/,
    );
    expect(vi.mocked(triage)).not.toHaveBeenCalled();
  });

  it("rejects a --min-confidence outside the 0..1 calibrated range", async () => {
    await expect(triageCommand({ provider: "sage", minConfidence: 90 })).rejects.toThrow(
      /between 0 and 1/,
    );
    expect(vi.mocked(triage)).not.toHaveBeenCalled();
  });

  it("accepts the boundary values 0 and 1", async () => {
    await triageCommand({ provider: "sage", minConfidence: 0 });
    await triageCommand({ provider: "sage", minConfidence: 1 });
    expect(vi.mocked(triage)).toHaveBeenCalledTimes(2);
  });

  it("--sage selects the sage provider and its model, overriding --provider/--model", async () => {
    await triageCommand({ sage: true, provider: "claude", model: "claude-sonnet-4-6" });

    expect(vi.mocked(triage)).toHaveBeenCalledTimes(1);
    const args = vi.mocked(triage).mock.calls[0][0];
    expect(args.provider).toBe("sage");
    expect(args.model).toBe(SAGE_MODEL_NAME);
  });

  it("rejects a --model the sage provider cannot honor", async () => {
    await expect(triageCommand({ provider: "sage", model: "levanto-sage-v1" })).rejects.toThrow(
      /not available for the sage provider/,
    );
    expect(vi.mocked(triage)).not.toHaveBeenCalled();
  });

  it("rejects --min-confidence when the sage provider was not selected", async () => {
    // The Claude path never reads it, so accepting it would echo an inert setting.
    await expect(triageCommand({ minConfidence: 0.9 })).rejects.toThrow(/Sage triage only/);
    expect(vi.mocked(triage)).not.toHaveBeenCalled();
  });

  it("rejects --latency-mode when the sage provider was not selected", async () => {
    await expect(triageCommand({ latencyMode: "fast" })).rejects.toThrow(/Sage triage only/);
    expect(vi.mocked(triage)).not.toHaveBeenCalled();
  });

  it("rejects --no-claude-fallback when the sage provider was not selected", async () => {
    await expect(triageCommand({ claudeFallback: false })).rejects.toThrow(/Sage triage only/);
    expect(vi.mocked(triage)).not.toHaveBeenCalled();
  });

  it("accepts the Sage-only flags under --sage", async () => {
    await triageCommand({
      sage: true,
      minConfidence: 0.9,
      latencyMode: "fast",
      claudeFallback: false,
    });

    const args = vi.mocked(triage).mock.calls[0][0];
    expect(args.provider).toBe("sage");
    expect(args.minConfidence).toBe(0.9);
    expect(args.latencyMode).toBe("fast");
    expect(args.fallbackToClaude).toBe(false);
  });

  it("still honors --model for the claude provider", async () => {
    await triageCommand({ provider: "claude", model: "claude-opus-4-1" });

    const args = vi.mocked(triage).mock.calls[0][0];
    expect(args.provider).toBe("claude");
    expect(args.model).toBe("claude-opus-4-1");
  });
});
