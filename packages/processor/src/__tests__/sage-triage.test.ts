import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { query } from "@anthropic-ai/claude-agent-sdk";
import type { Finding } from "@deepsec/core";
import { ensureProject, loadAllFileRecords, writeFileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LevantoSageClient, SageBatchResponse } from "../sage/client.js";
import { CLAUDE_DEFAULT_MODEL, formatFindingForSage, SAGE_MODEL_NAME, triage } from "../triage.js";

vi.mock("@anthropic-ai/claude-agent-sdk", () => ({
  query: vi.fn(),
}));

describe("Sage Triage", () => {
  const projectId = "sage-triage-test";
  let tmpDir: string;
  let oldDataRoot: string | undefined;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-triage-"));
    oldDataRoot = process.env.DEEPSEC_DATA_ROOT;
    process.env.DEEPSEC_DATA_ROOT = tmpDir;
    ensureProject(projectId, tmpDir);
    vi.clearAllMocks();
  });

  afterEach(() => {
    if (oldDataRoot === undefined) {
      delete process.env.DEEPSEC_DATA_ROOT;
    } else {
      process.env.DEEPSEC_DATA_ROOT = oldDataRoot;
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  describe("formatFindingForSage", () => {
    it("formats complete finding into structured text content", () => {
      const finding: Finding = {
        title: "SQL Injection in User Lookup",
        severity: "MEDIUM",
        vulnSlug: "sql-injection",
        description: "User input is directly concatenated into SQL query without sanitization.",
        lineNumbers: [42, 43],
        confidence: "high",
        recommendation: "Use parameterized queries or ORM methods.",
      };

      const formatted = formatFindingForSage(finding, "src/api/users.ts");

      expect(formatted).toContain("Title: SQL Injection in User Lookup");
      expect(formatted).toContain("File: src/api/users.ts");
      expect(formatted).toContain("Severity: MEDIUM");
      expect(formatted).toContain("Vulnerability Slug: sql-injection");
      expect(formatted).toContain("Lines: 42, 43");
      expect(formatted).toContain("Scanner Confidence: high");
      expect(formatted).toContain(
        "Description: User input is directly concatenated into SQL query without sanitization.",
      );
      expect(formatted).toContain("Recommendation: Use parameterized queries or ORM methods.");
    });

    it("handles minimal finding with optional fields omitted", () => {
      const finding: Finding = {
        title: "Hardcoded secret",
        severity: "MEDIUM",
        vulnSlug: "secret-in-code",
        description: "Potential API key in source",
        lineNumbers: [],
        confidence: "medium",
        recommendation: "",
      };

      const formatted = formatFindingForSage(finding);

      expect(formatted).toContain("Title: Hardcoded secret");
      expect(formatted).toContain("Severity: MEDIUM");
      expect(formatted).not.toContain("File:");
      expect(formatted).not.toContain("Lines:");
      expect(formatted).not.toContain("Recommendation:");
    });
  });

  describe("Sage provider evaluation", () => {
    it("triages findings via Sage and records levanto-sage-v0.8 model", async () => {
      const finding: Finding = {
        title: "Cross-Site Scripting in Comment Body",
        severity: "MEDIUM",
        vulnSlug: "xss",
        description: "Unescaped HTML rendered directly in DOM",
        lineNumbers: [10],
        confidence: "high",
        recommendation: "Escape HTML entities",
      };

      writeFileRecord({
        projectId,
        filePath: "src/comments.ts",
        fileHash: "hash1",
        status: "analyzed",
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "run1",
        candidates: [],
        findings: [finding],
        analysisHistory: [],
      });

      const mockBatchResponse: SageBatchResponse = {
        results: [
          {
            answers: [
              {
                ok: true,
                result: {
                  id: "priority",
                  kind: "choice",
                  result: {
                    chosen: "P0",
                    confidence: 0.94,
                    probabilities: [
                      { option: "P0", probability: 0.94 },
                      { option: "P1", probability: 0.12 },
                    ],
                  },
                },
              },
              {
                ok: true,
                result: {
                  id: "exploitability",
                  kind: "choice",
                  result: {
                    chosen: "trivial",
                    confidence: 0.89,
                    probabilities: [{ option: "trivial", probability: 0.89 }],
                  },
                },
              },
              {
                ok: true,
                result: {
                  id: "impact",
                  kind: "choice",
                  result: {
                    chosen: "high",
                    confidence: 0.91,
                    probabilities: [{ option: "high", probability: 0.91 }],
                  },
                },
              },
            ],
          },
        ],
        meta: {
          model: SAGE_MODEL_NAME,
          request_count: 1,
          question_count: 3,
          latency_ms: 110,
        },
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => mockBatchResponse),
      } as unknown as LevantoSageClient;

      const progressMessages: string[] = [];
      const result = await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        sageClient: mockSageClient,
        onProgress: (p) => progressMessages.push(p.message),
      });

      expect(result).toEqual({ triaged: 1, p0: 1, p1: 0, p2: 0, skip: 0 });
      expect(mockSageClient.decideBatch).toHaveBeenCalledTimes(1);

      const records = loadAllFileRecords(projectId);
      expect(records).toHaveLength(1);
      const triagedFinding = records[0].findings[0];
      expect(triagedFinding.triage).toBeDefined();
      expect(triagedFinding.triage?.priority).toBe("P0");
      expect(triagedFinding.triage?.exploitability).toBe("trivial");
      expect(triagedFinding.triage?.impact).toBe("high");
      expect(triagedFinding.triage?.model).toBe(SAGE_MODEL_NAME);
      expect(triagedFinding.triage?.reasoning).toContain("Levanto Sage decision: P0");
      expect(triagedFinding.triage?.reasoning).toContain("94%");
    });
  });

  describe("low confidence handling and fallback", () => {
    it("falls back low-confidence finding to Claude when minConfidence is set", async () => {
      const findingHighConfidence: Finding = {
        title: "Clear SQL injection",
        severity: "MEDIUM",
        vulnSlug: "sqli",
        description: "raw sql concat",
        lineNumbers: [5],
        confidence: "high",
        recommendation: "parameterize",
      };

      const findingLowConfidence: Finding = {
        title: "Ambiguous regex denial of service",
        severity: "MEDIUM",
        vulnSlug: "redos",
        description: "complex regex pattern",
        lineNumbers: [20],
        confidence: "low",
        recommendation: "review regex",
      };

      writeFileRecord({
        projectId,
        filePath: "src/db.ts",
        fileHash: "hash-db",
        status: "analyzed",
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "run1",
        candidates: [],
        findings: [findingHighConfidence],
        analysisHistory: [],
      });

      writeFileRecord({
        projectId,
        filePath: "src/parser.ts",
        fileHash: "hash-parser",
        status: "analyzed",
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "run1",
        candidates: [],
        findings: [findingLowConfidence],
        analysisHistory: [],
      });

      // Sage responds: finding 1 has 0.95 confidence; finding 2 has 0.45 confidence
      const mockBatchResponse: SageBatchResponse = {
        results: [
          {
            answers: [
              {
                ok: true,
                result: {
                  id: "priority",
                  kind: "choice",
                  result: { chosen: "P0", confidence: 0.95, probabilities: [] },
                },
              },
            ],
          },
          {
            answers: [
              {
                ok: true,
                result: {
                  id: "priority",
                  kind: "choice",
                  result: { chosen: "P2", confidence: 0.45, probabilities: [] },
                },
              },
            ],
          },
        ],
        meta: { model: SAGE_MODEL_NAME, latency_ms: 95 },
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => mockBatchResponse),
      } as unknown as LevantoSageClient;

      // Mock Claude agent SDK query response for the low-confidence finding
      vi.mocked(query).mockImplementation(async function* () {
        yield {
          type: "result",
          subtype: "success",
          result: JSON.stringify([
            {
              title: "Ambiguous regex denial of service",
              priority: "P1",
              exploitability: "moderate",
              impact: "medium",
              reasoning: "Claude verified catastrophic backtracking in parser",
            },
          ]),
        } as any;
      } as any);

      const result = await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        minConfidence: 0.8, // 0.45 is below this floor -> fallback to Claude
        fallbackToClaude: true,
        sageClient: mockSageClient,
      });

      expect(result.triaged).toBe(2);
      expect(result.p0).toBe(1); // Sage gave P0 to finding 1
      expect(result.p1).toBe(1); // Claude gave P1 to finding 2

      const records = loadAllFileRecords(projectId);
      const dbRec = records.find((r) => r.filePath === "src/db.ts");
      const parserRec = records.find((r) => r.filePath === "src/parser.ts");

      // Finding 1 was triaged by Sage
      expect(dbRec?.findings[0].triage?.model).toBe(SAGE_MODEL_NAME);
      expect(dbRec?.findings[0].triage?.priority).toBe("P0");

      // Finding 2 was triaged by Claude fallback
      expect(parserRec?.findings[0].triage?.model).toBe(CLAUDE_DEFAULT_MODEL);
      expect(parserRec?.findings[0].triage?.priority).toBe("P1");
      expect(parserRec?.findings[0].triage?.reasoning).toBe(
        "Claude verified catastrophic backtracking in parser",
      );
    });

    it("falls back entire batch to Claude when Sage client throws an error", async () => {
      const finding: Finding = {
        title: "Information disclosure in logs",
        severity: "MEDIUM",
        vulnSlug: "log-leak",
        description: "Password printed in log",
        lineNumbers: [15],
        confidence: "high",
        recommendation: "Sanitize logs",
      };

      writeFileRecord({
        projectId,
        filePath: "src/logger.ts",
        fileHash: "hash-logger",
        status: "analyzed",
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "run1",
        candidates: [],
        findings: [finding],
        analysisHistory: [],
      });

      const mockSageClient = {
        decideBatch: vi.fn(async () => {
          throw new Error("Sage API 503 Service Unavailable");
        }),
      } as unknown as LevantoSageClient;

      vi.mocked(query).mockImplementation(async function* () {
        yield {
          type: "result",
          subtype: "success",
          result: JSON.stringify([
            {
              title: "Information disclosure in logs",
              priority: "P1",
              exploitability: "moderate",
              impact: "high",
              reasoning: "Claude fallback triage completed",
            },
          ]),
        } as any;
      } as any);

      const result = await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        fallbackToClaude: true,
        sageClient: mockSageClient,
      });

      expect(result.triaged).toBe(1);
      expect(result.p1).toBe(1);

      const records = loadAllFileRecords(projectId);
      expect(records[0].findings[0].triage?.model).toBe(CLAUDE_DEFAULT_MODEL);
      expect(records[0].findings[0].triage?.priority).toBe("P1");
    });
  });

  describe("malformed Sage responses", () => {
    function writeSingleFinding(filePath: string, title: string) {
      writeFileRecord({
        projectId,
        filePath,
        fileHash: `hash-${filePath}`,
        status: "analyzed",
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "run1",
        candidates: [],
        findings: [
          {
            title,
            severity: "MEDIUM",
            vulnSlug: "generic",
            description: "some issue",
            lineNumbers: [1],
            confidence: "high",
            recommendation: "fix it",
          },
        ],
        analysisHistory: [],
      });
    }

    function mockClaudeVerdict(title: string) {
      vi.mocked(query).mockImplementation(async function* () {
        yield {
          type: "result",
          subtype: "success",
          result: JSON.stringify([
            {
              title,
              priority: "P1",
              exploitability: "moderate",
              impact: "medium",
              reasoning: "Claude fallback verdict",
            },
          ]),
        } as any;
      } as any);
    }

    it("never persists a priority outside P0/P1/P2/skip and falls back instead", async () => {
      writeSingleFinding("src/odd.ts", "Unrecognized priority finding");
      mockClaudeVerdict("Unrecognized priority finding");

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "priority",
                    kind: "choice",
                    result: { chosen: "p0 ", confidence: 0.99, probabilities: [] },
                  },
                },
              ],
            },
          ],
          meta: { model: SAGE_MODEL_NAME },
        })),
      } as unknown as LevantoSageClient;

      const result = await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        fallbackToClaude: true,
        sageClient: mockSageClient,
      });

      expect(result).toEqual({ triaged: 1, p0: 0, p1: 1, p2: 0, skip: 0 });

      // The record must survive a full reload — an out-of-enum priority would
      // make salvage drop the finding entirely.
      const records = loadAllFileRecords(projectId);
      expect(records[0].findings).toHaveLength(1);
      expect(records[0].findings[0].triage?.priority).toBe("P1");
      expect(records[0].findings[0].triage?.model).toBe(CLAUDE_DEFAULT_MODEL);
    });

    it("treats a missing confidence as below the minConfidence floor", async () => {
      writeSingleFinding("src/noconf.ts", "Finding without confidence");
      mockClaudeVerdict("Finding without confidence");

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "priority",
                    kind: "choice",
                    result: { chosen: "P0", probabilities: [] },
                  },
                },
              ],
            },
          ],
          meta: { model: SAGE_MODEL_NAME },
        })),
      } as unknown as LevantoSageClient;

      const result = await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        minConfidence: 0.8,
        fallbackToClaude: true,
        sageClient: mockSageClient,
      });

      expect(result).toEqual({ triaged: 1, p0: 0, p1: 1, p2: 0, skip: 0 });
      const records = loadAllFileRecords(projectId);
      expect(records[0].findings[0].triage?.model).toBe(CLAUDE_DEFAULT_MODEL);
    });

    it("counts each finding once when a probability entry is malformed", async () => {
      writeSingleFinding("src/a.ts", "First finding");
      writeSingleFinding("src/b.ts", "Second finding");

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "priority",
                    kind: "choice",
                    result: {
                      chosen: "P0",
                      confidence: 0.97,
                      probabilities: [{ option: "P0", probability: 0.97 }],
                    },
                  },
                },
              ],
            },
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "priority",
                    kind: "choice",
                    result: {
                      chosen: "P0",
                      confidence: 0.96,
                      probabilities: [{ option: "P0" }],
                    },
                  },
                },
              ],
            },
          ],
          meta: { model: SAGE_MODEL_NAME },
        })),
      } as unknown as LevantoSageClient;

      const result = await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        fallbackToClaude: true,
        sageClient: mockSageClient,
      });

      expect(result).toEqual({ triaged: 2, p0: 2, p1: 0, p2: 0, skip: 0 });
      expect(vi.mocked(query)).not.toHaveBeenCalled();
    });

    it("reports low-confidence findings as untriaged when the Claude fallback is off", async () => {
      writeSingleFinding("src/low.ts", "Low confidence finding");

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "priority",
                    kind: "choice",
                    result: { chosen: "P2", confidence: 0.3, probabilities: [] },
                  },
                },
              ],
            },
          ],
          meta: { model: SAGE_MODEL_NAME },
        })),
      } as unknown as LevantoSageClient;

      const progressMessages: string[] = [];
      const result = await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        minConfidence: 0.8,
        fallbackToClaude: false,
        sageClient: mockSageClient,
        onProgress: (p) => progressMessages.push(p.message),
      });

      expect(result).toEqual({ triaged: 0, p0: 0, p1: 0, p2: 0, skip: 0 });
      expect(vi.mocked(query)).not.toHaveBeenCalled();
      expect(loadAllFileRecords(projectId)[0].findings[0].triage).toBeUndefined();
      expect(progressMessages.some((m) => m.includes("fell back to Claude"))).toBe(false);
      expect(progressMessages.some((m) => m.includes("1 left untriaged"))).toBe(true);
    });
  });

  describe("Claude verdict validation", () => {
    function writeFinding(filePath: string, title: string) {
      writeFileRecord({
        projectId,
        filePath,
        fileHash: `hash-${filePath}`,
        status: "analyzed",
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "run1",
        candidates: [],
        findings: [
          {
            title,
            severity: "MEDIUM",
            vulnSlug: "generic",
            description: "some issue",
            lineNumbers: [1],
            confidence: "high",
            recommendation: "fix it",
          },
        ],
        analysisHistory: [],
      });
    }

    it("never persists a Claude priority outside the schema enum", async () => {
      writeFinding("src/claude-bad.ts", "Bad priority finding");

      vi.mocked(query).mockImplementation(async function* () {
        yield {
          type: "result",
          subtype: "success",
          result: JSON.stringify([
            {
              title: "Bad priority finding",
              priority: "P3",
              exploitability: "moderate",
              impact: "medium",
              reasoning: "out of range priority",
            },
          ]),
        } as any;
      } as any);

      const result = await triage({ projectId, severity: "MEDIUM", provider: "claude" });

      expect(result).toEqual({ triaged: 0, p0: 0, p1: 0, p2: 0, skip: 0 });

      // The record must still round-trip: an out-of-enum triage block would make
      // salvage drop the whole finding on reload.
      const records = loadAllFileRecords(projectId);
      expect(records).toHaveLength(1);
      expect(records[0].findings).toHaveLength(1);
      expect(records[0].findings[0].triage).toBeUndefined();
    });

    it("normalizes out-of-enum exploitability/impact and a missing reasoning", async () => {
      writeFinding("src/claude-partial.ts", "Partial verdict finding");

      vi.mocked(query).mockImplementation(async function* () {
        yield {
          type: "result",
          subtype: "success",
          result: JSON.stringify([
            {
              title: "Partial verdict finding",
              priority: "P1",
              exploitability: "very-easy",
              impact: 3,
            },
          ]),
        } as any;
      } as any);

      const result = await triage({ projectId, severity: "MEDIUM", provider: "claude" });

      expect(result).toEqual({ triaged: 1, p0: 0, p1: 1, p2: 0, skip: 0 });

      const records = loadAllFileRecords(projectId);
      expect(records[0].findings).toHaveLength(1);
      expect(records[0].findings[0].triage?.priority).toBe("P1");
      expect(records[0].findings[0].triage?.exploitability).toBe("moderate");
      expect(records[0].findings[0].triage?.impact).toBe("high");
      expect(records[0].findings[0].triage?.reasoning).toBe("");
    });

    it("survives a Claude response that is valid JSON but not an array", async () => {
      writeFinding("src/claude-obj.ts", "Object response finding");

      vi.mocked(query).mockImplementation(async function* () {
        yield {
          type: "result",
          subtype: "success",
          result: JSON.stringify({ error: "could not classify" }),
        } as any;
      } as any);

      const result = await triage({ projectId, severity: "MEDIUM", provider: "claude" });

      expect(result).toEqual({ triaged: 0, p0: 0, p1: 0, p2: 0, skip: 0 });
      expect(loadAllFileRecords(projectId)[0].findings[0].triage).toBeUndefined();
    });

    it("records the model Sage reports it actually ran", async () => {
      writeFinding("src/sage-model.ts", "Sage model finding");

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "priority",
                    kind: "choice",
                    result: { chosen: "P1", confidence: 0.9, probabilities: [] },
                  },
                },
              ],
            },
          ],
          meta: { model: "levanto-sage-v0.9" },
        })),
      } as unknown as LevantoSageClient;

      await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        sageClient: mockSageClient,
      });

      expect(loadAllFileRecords(projectId)[0].findings[0].triage?.model).toBe("levanto-sage-v0.9");
    });
  });

  describe("backwards compatibility with Claude", () => {
    it("runs existing Claude triage when provider is 'claude' or undefined", async () => {
      const finding: Finding = {
        title: "Insecure cookie flag",
        severity: "MEDIUM",
        vulnSlug: "cookie-flag",
        description: "Missing Secure flag",
        lineNumbers: [3],
        confidence: "high",
        recommendation: "Set secure: true",
      };

      writeFileRecord({
        projectId,
        filePath: "src/auth.ts",
        fileHash: "hash-auth",
        status: "analyzed",
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "run1",
        candidates: [],
        findings: [finding],
        analysisHistory: [],
      });

      vi.mocked(query).mockImplementation(async function* () {
        yield {
          type: "result",
          subtype: "success",
          result: JSON.stringify([
            {
              title: "Insecure cookie flag",
              priority: "P2",
              exploitability: "difficult",
              impact: "low",
              reasoning: "Defense in depth improvement",
            },
          ]),
        } as any;
      } as any);

      const result = await triage({
        projectId,
        severity: "MEDIUM",
        // provider omitted -> defaults to claude
      });

      expect(result).toEqual({ triaged: 1, p0: 0, p1: 0, p2: 1, skip: 0 });

      const records = loadAllFileRecords(projectId);
      expect(records[0].findings[0].triage?.model).toBe(CLAUDE_DEFAULT_MODEL);
      expect(records[0].findings[0].triage?.priority).toBe("P2");
      expect(vi.mocked(query)).toHaveBeenCalledTimes(1);
    });
  });
});
