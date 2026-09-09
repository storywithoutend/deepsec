import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@deepsec/core", async (importOriginal) => ({
  ...((await importOriginal()) as Record<string, unknown>),
  ensureProject: vi.fn(),
  readProjectConfig: vi.fn(() => ({ projectId: "test-proj", rootPath: "/tmp/test-proj" })),
}));

vi.mock("@deepsec/processor", async (importOriginal) => ({
  ...((await importOriginal()) as Record<string, unknown>),
  process: vi.fn(async () => ({
    runId: "run-123",
    analysisCount: 1,
    findingCount: 0,
    errorBatchCount: 0,
    candidatesFilteredBySage: 3,
  })),
}));

vi.mock("@deepsec/scanner", async (importOriginal) => ({
  ...((await importOriginal()) as Record<string, unknown>),
  scanFiles: vi.fn(async () => ({ candidateCount: 2, filesScanned: 1 })),
}));

vi.mock("../resolve-project-id.js", () => ({
  resolveProjectId: vi.fn(() => "test-proj"),
  resolveProjectIdForDirect: vi.fn(() => ({
    projectId: "test-proj",
    rootPath: "/tmp/test-proj",
    autoCreated: false,
  })),
}));

vi.mock("../resolve-agent-type.js", () => ({
  resolveAgentType: vi.fn(() => "claude-agent-sdk"),
}));

vi.mock("../agent-defaults.js", () => ({
  defaultModelForAgent: vi.fn(() => "claude-opus-4-8"),
}));

vi.mock("../agent-config.js", () => ({
  buildAgentConfig: vi.fn(() => ({})),
}));

vi.mock("../file-sources.js", () => ({
  resolveFiles: vi.fn(() => ({
    sourceLabel: "files:cli",
    filePaths: ["src/app.ts"],
  })),
}));

vi.mock("../preflight.js", () => ({
  applyConfiguredModelRoute: vi.fn(async () => undefined),
  assertAgentCredential: vi.fn(),
  assertSageCredential: vi.fn(),
}));

import { DEFAULT_SAGE_GATE_CONFIDENCE, process as processRun } from "@deepsec/processor";
import { processCommand } from "../commands/process.js";
import { assertSageCredential } from "../preflight.js";

describe("processCommand --sage-gate flags and validation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  it("passes --sage-gate and --sage-gate-confidence to processor in standard mode", async () => {
    await processCommand({
      projectId: "test-proj",
      sageGate: true,
      sageGateConfidence: 0.9,
    });

    expect(assertSageCredential).toHaveBeenCalledTimes(1);
    expect(processRun).toHaveBeenCalledTimes(1);
    const passedParams = vi.mocked(processRun).mock.calls[0][0];
    expect(passedParams.sageGate).toBe(true);
    expect(passedParams.sageGateConfidence).toBe(0.9);
  });

  it("rejects --sage-gate-confidence without --sage-gate", async () => {
    await expect(
      processCommand({
        projectId: "test-proj",
        sageGateConfidence: 0.9,
      }),
    ).rejects.toThrow(/--sage-gate-confidence requires --sage-gate/);

    expect(processRun).not.toHaveBeenCalled();
  });

  it("rejects NaN --sage-gate-confidence", async () => {
    await expect(
      processCommand({
        projectId: "test-proj",
        sageGate: true,
        sageGateConfidence: Number.NaN,
      }),
    ).rejects.toThrow(/between 0 and 1/);

    expect(processRun).not.toHaveBeenCalled();
  });

  it("rejects negative --sage-gate-confidence", async () => {
    await expect(
      processCommand({
        projectId: "test-proj",
        sageGate: true,
        sageGateConfidence: -0.1,
      }),
    ).rejects.toThrow(/between 0 and 1/);

    expect(processRun).not.toHaveBeenCalled();
  });

  it("rejects --sage-gate-confidence > 1", async () => {
    await expect(
      processCommand({
        projectId: "test-proj",
        sageGate: true,
        sageGateConfidence: 1.5,
      }),
    ).rejects.toThrow(/between 0 and 1/);

    expect(processRun).not.toHaveBeenCalled();
  });

  it("accepts boundary confidence values 0 and 1", async () => {
    await processCommand({
      projectId: "test-proj",
      sageGate: true,
      sageGateConfidence: 0,
    });
    await processCommand({
      projectId: "test-proj",
      sageGate: true,
      sageGateConfidence: 1,
    });

    expect(processRun).toHaveBeenCalledTimes(2);
  });

  it("prints the default confidence threshold from the shared constant", async () => {
    const logSpy = vi.spyOn(console, "log");
    await processCommand({ projectId: "test-proj", sageGate: true });

    const printed = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(printed).toContain(
      `Sage candidate gate: enabled (confidence threshold: ${DEFAULT_SAGE_GATE_CONFIDENCE})`,
    );
  });

  it("reports gate errors and skipped files in the run summary", async () => {
    vi.mocked(processRun).mockResolvedValueOnce({
      runId: "run-err",
      analysisCount: 1,
      findingCount: 0,
      errorBatchCount: 0,
      candidatesFilteredBySage: 0,
      sageGateSkippedFiles: 2,
      sageGateErrors: { count: 4, messages: ["HTTP 401 invalid api key"] },
    } as never);
    const logSpy = vi.spyOn(console, "log");

    await processCommand({ projectId: "test-proj", sageGate: true });

    const printed = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(printed).toContain("Files skipped by Sage gate: 2");
    expect(printed).toContain("Sage gate errors: 4");
    expect(printed).toContain("HTTP 401 invalid api key");
  });

  it("supports --sage-gate in direct mode", async () => {
    await processCommand({
      files: "src/app.ts",
      sageGate: true,
      sageGateConfidence: 0.88,
    });

    expect(assertSageCredential).toHaveBeenCalledTimes(1);
    expect(processRun).toHaveBeenCalledTimes(1);
    const passedParams = vi.mocked(processRun).mock.calls[0][0];
    expect(passedParams.sageGate).toBe(true);
    expect(passedParams.sageGateConfidence).toBe(0.88);
  });
});
