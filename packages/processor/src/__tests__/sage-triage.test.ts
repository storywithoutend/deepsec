import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { query } from "@anthropic-ai/claude-agent-sdk";
import type { Finding } from "@deepsec/core";
import { ensureProject, listRuns, loadAllFileRecords, writeFileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  LevantoSageAuthError,
  type LevantoSageClient,
  LevantoSageError,
  LevantoSageQuotaError,
  LevantoSageServerError,
  LevantoSageValidationError,
  type SageBatchResponse,
} from "../sage/client.js";
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

  it("prepends project context when it is supplied", () => {
    const finding: Finding = {
      title: "Hardcoded credential on an internal route",
      severity: "MEDIUM",
      vulnSlug: "secret-in-code",
      description: "Static token in the handler",
      lineNumbers: [7],
      confidence: "high",
      recommendation: "Move to the secret store",
    };

    const formatted = formatFindingForSage(
      finding,
      "src/internal/route.ts",
      "All /internal/* routes sit behind mTLS at the edge.",
    );

    expect(formatted).toContain(
      "Project Context: All /internal/* routes sit behind mTLS at the edge.",
    );
    expect(formatted).toContain("Title: Hardcoded credential on an internal route");
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

    it("degrades a single malformed answer to fallback without aborting the batch", async () => {
      writeSingleFinding("src/ok.ts", "Well formed finding");
      writeSingleFinding("src/broken.ts", "Malformed answer finding");

      vi.mocked(query).mockImplementation(async function* () {
        yield {
          type: "result",
          subtype: "success",
          result: JSON.stringify([
            {
              title: "Well formed finding",
              priority: "P1",
              exploitability: "moderate",
              impact: "medium",
              reasoning: "Claude fallback verdict",
            },
            {
              title: "Malformed answer finding",
              priority: "P1",
              exploitability: "moderate",
              impact: "medium",
              reasoning: "Claude fallback verdict",
            },
          ]),
        } as any;
      } as any);

      // The second group carries an `ok: true` answer with no `result` payload.
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
                    result: { chosen: "P0", confidence: 0.95, probabilities: [] },
                  },
                },
              ],
            },
            { answers: [{ ok: true }] },
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

      // Every finding is counted exactly once: Sage handled one, Claude the other.
      expect(result).toEqual({ triaged: 2, p0: 1, p1: 1, p2: 0, skip: 0 });

      const triages = loadAllFileRecords(projectId).map((r) => r.findings[0].triage);
      expect(triages.filter((t) => t?.model === SAGE_MODEL_NAME)).toHaveLength(1);
      expect(triages.filter((t) => t?.model === CLAUDE_DEFAULT_MODEL)).toHaveLength(1);
      expect(triages.map((t) => t?.priority).sort()).toEqual(["P0", "P1"]);
    });

    it("leaves no orphaned Sage verdicts on disk when the batch aborts mid-decode", async () => {
      writeSingleFinding("src/first.ts", "First finding");
      writeSingleFinding("src/second.ts", "Second finding");

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
                    result: { chosen: "P0", confidence: 0.95, probabilities: [] },
                  },
                },
              ],
            },
            {
              // A getter that throws mid-loop, after finding 1 has been decoded.
              get answers(): unknown[] {
                throw new TypeError("malformed group");
              },
            },
          ],
          meta: { model: SAGE_MODEL_NAME },
        })),
      } as unknown as LevantoSageClient;

      const result = await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        fallbackToClaude: false,
        sageClient: mockSageClient,
      });

      // Nothing was committed, so the reported counts and the records agree.
      expect(result).toEqual({ triaged: 0, p0: 0, p1: 0, p2: 0, skip: 0 });
      const records = loadAllFileRecords(projectId);
      expect(records.map((r) => r.findings[0].triage)).toEqual([undefined, undefined]);
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

      // A server-side model roll needs no client release, so the record must
      // attribute the verdict (and its confidence) to what actually decided it.
      expect(loadAllFileRecords(projectId)[0].findings[0].triage?.model).toBe("levanto-sage-v0.9");
    });

    it("falls back to SAGE_MODEL_NAME when Sage reports no model", async () => {
      writeFinding("src/no-meta-model.ts", "No meta model finding");

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
          meta: {},
        })),
      } as unknown as LevantoSageClient;

      await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        sageClient: mockSageClient,
      });

      expect(loadAllFileRecords(projectId)[0].findings[0].triage?.model).toBe(SAGE_MODEL_NAME);
    });

    it("pins the sage model for run meta even when a caller passes another model", async () => {
      writeFinding("src/pinned.ts", "Pinned model finding");

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
                    result: { chosen: "P2", confidence: 0.9, probabilities: [] },
                  },
                },
              ],
            },
          ],
          meta: { model: SAGE_MODEL_NAME },
        })),
      } as unknown as LevantoSageClient;

      await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        model: "levanto-sage-v1",
        sageClient: mockSageClient,
      });

      const findingModel = loadAllFileRecords(projectId)[0].findings[0].triage?.model;
      expect(findingModel).toBe(SAGE_MODEL_NAME);

      const runModels = listRuns(projectId).map((r) => r.processorConfig?.model);
      expect(runModels).toContain(SAGE_MODEL_NAME);
      expect(runModels).not.toContain("levanto-sage-v1");
    });

    it("binds same-title verdicts across files to distinct findings", async () => {
      writeFinding("src/a.ts", "Hardcoded API key in config");
      writeFinding("src/b.ts", "Hardcoded API key in config");

      const records = loadAllFileRecords(projectId);
      const idA = records.find((r) => r.filePath === "src/a.ts")?.findings[0].findingId;
      const idB = records.find((r) => r.filePath === "src/b.ts")?.findings[0].findingId;
      expect(idA).toBeDefined();
      expect(idB).toBeDefined();
      expect(idA).not.toBe(idB);

      vi.mocked(query).mockImplementation(async function* () {
        yield {
          type: "result",
          subtype: "success",
          result: JSON.stringify([
            {
              id: idA,
              title: "Hardcoded API key in config",
              priority: "P0",
              exploitability: "trivial",
              impact: "critical",
              reasoning: "live key in a.ts",
            },
            {
              id: idB,
              title: "Hardcoded API key in config",
              priority: "skip",
              exploitability: "difficult",
              impact: "low",
              reasoning: "placeholder in b.ts",
            },
          ]),
        } as any;
      } as any);

      const result = await triage({ projectId, severity: "MEDIUM", provider: "claude" });

      expect(result).toEqual({ triaged: 2, p0: 1, p1: 0, p2: 0, skip: 1 });

      const after = loadAllFileRecords(projectId);
      const recA = after.find((r) => r.filePath === "src/a.ts");
      const recB = after.find((r) => r.filePath === "src/b.ts");
      expect(recA?.findings[0].triage?.priority).toBe("P0");
      expect(recB?.findings[0].triage?.priority).toBe("skip");
    });

    it("falls back to title binding without reusing an already-bound finding", async () => {
      writeFinding("src/c.ts", "Missing CSRF token");
      writeFinding("src/d.ts", "Missing CSRF token");

      vi.mocked(query).mockImplementation(async function* () {
        yield {
          type: "result",
          subtype: "success",
          result: JSON.stringify([
            {
              title: "Missing CSRF token",
              priority: "P1",
              exploitability: "moderate",
              impact: "high",
              reasoning: "first",
            },
            {
              title: "Missing CSRF token",
              priority: "P2",
              exploitability: "difficult",
              impact: "medium",
              reasoning: "second",
            },
          ]),
        } as any;
      } as any);

      const result = await triage({ projectId, severity: "MEDIUM", provider: "claude" });

      expect(result).toEqual({ triaged: 2, p0: 0, p1: 1, p2: 1, skip: 0 });

      const after = loadAllFileRecords(projectId);
      const priorities = after.map((r) => r.findings[0].triage?.priority).sort();
      expect(priorities).toEqual(["P1", "P2"]);
    });
  });

  describe("permanent Sage failures", () => {
    function writeOneFinding(filePath: string, title: string) {
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

    for (const [label, makeError] of [
      ["auth", () => new LevantoSageAuthError("revoked key", { status: 401 })],
      ["quota", () => new LevantoSageQuotaError("out of credits", { status: 402 })],
    ] as const) {
      it(`aborts the run on a ${label} error instead of re-triaging with Claude`, async () => {
        writeOneFinding("src/one.ts", "First finding");
        writeOneFinding("src/two.ts", "Second finding");

        const mockSageClient = {
          decideBatch: vi.fn(async () => {
            throw makeError();
          }),
        } as unknown as LevantoSageClient;

        await expect(
          triage({
            projectId,
            severity: "MEDIUM",
            provider: "sage",
            fallbackToClaude: true,
            sageClient: mockSageClient,
          }),
        ).rejects.toThrow(makeError().constructor as never);

        // The expensive provider the user opted out of is never reached, and the
        // run is not recorded as a success.
        expect(vi.mocked(query)).not.toHaveBeenCalled();
        expect(listRuns(projectId).map((r) => r.phase)).toContain("error");
        for (const record of loadAllFileRecords(projectId)) {
          expect(record.findings[0].triage).toBeUndefined();
        }
      });
    }

    // A rejected request is scoped to the payload that caused it — one
    // oversized finding must not strand the rest of the corpus untriaged.
    for (const [label, makeError] of [
      ["validation", () => new LevantoSageValidationError("bad request", { status: 400 })],
      ["unprocessable", () => new LevantoSageError("unprocessable entity", { status: 422 })],
      ["payload-too-large", () => new LevantoSageError("payload too large", { status: 413 })],
    ] as const) {
      it(`falls back to Claude on a ${label} error instead of aborting the run`, async () => {
        writeOneFinding("src/rejected.ts", "Rejected finding");

        vi.mocked(query).mockImplementation(async function* () {
          yield {
            type: "result",
            subtype: "success",
            result: JSON.stringify([
              {
                title: "Rejected finding",
                priority: "P1",
                exploitability: "moderate",
                impact: "medium",
                reasoning: "Claude fallback verdict",
              },
            ]),
          } as any;
        } as any);

        const mockSageClient = {
          decideBatch: vi.fn(async () => {
            throw makeError();
          }),
        } as unknown as LevantoSageClient;

        const result = await triage({
          projectId,
          severity: "MEDIUM",
          provider: "sage",
          fallbackToClaude: true,
          sageClient: mockSageClient,
        });

        expect(result).toEqual({ triaged: 1, p0: 0, p1: 1, p2: 0, skip: 0 });
        expect(listRuns(projectId).map((r) => r.phase)).toContain("done");
      });
    }

    it("still falls back to Claude on a transient Sage error", async () => {
      writeOneFinding("src/transient.ts", "Transient finding");

      vi.mocked(query).mockImplementation(async function* () {
        yield {
          type: "result",
          subtype: "success",
          result: JSON.stringify([
            {
              title: "Transient finding",
              priority: "P1",
              exploitability: "moderate",
              impact: "medium",
              reasoning: "Claude fallback verdict",
            },
          ]),
        } as any;
      } as any);

      const mockSageClient = {
        decideBatch: vi.fn(async () => {
          throw new LevantoSageServerError("service unavailable", { status: 503 });
        }),
      } as unknown as LevantoSageClient;

      const result = await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        fallbackToClaude: true,
        sageClient: mockSageClient,
      });

      expect(result).toEqual({ triaged: 1, p0: 0, p1: 1, p2: 0, skip: 0 });
      expect(listRuns(projectId).map((r) => r.phase)).toContain("done");
    });
  });

  describe("calibrated confidence", () => {
    it("persists the Sage confidence as a structured field and passes project context", async () => {
      fs.writeFileSync(
        path.join(tmpDir, projectId, "INFO.md"),
        "All /internal/* routes sit behind mTLS at the edge.",
      );

      writeFileRecord({
        projectId,
        filePath: "src/conf.ts",
        fileHash: "hash-conf",
        status: "analyzed",
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "run1",
        candidates: [],
        findings: [
          {
            title: "Confidence finding",
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
                      confidence: 0.93,
                      probabilities: [{ option: "P0", probability: 0.93 }],
                    },
                  },
                },
              ],
            },
          ],
          meta: { model: SAGE_MODEL_NAME },
        })),
      } as unknown as LevantoSageClient;

      await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        sageClient: mockSageClient,
      });

      // Survives a full reload, so the schema accepts the new field.
      const triaged = loadAllFileRecords(projectId)[0].findings[0].triage;
      expect(triaged?.priority).toBe("P0");
      expect(triaged?.confidence).toBe(0.93);

      const sent = vi.mocked(mockSageClient.decideBatch).mock.calls[0][0];
      expect(sent.requests[0].content).toContain(
        "Project Context: All /internal/* routes sit behind mTLS at the edge.",
      );
    });

    it("treats an out-of-range confidence as missing rather than persisting it", async () => {
      writeFileRecord({
        projectId,
        filePath: "src/outofrange.ts",
        fileHash: "hash-oor",
        status: "analyzed",
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "run1",
        candidates: [],
        findings: [
          {
            title: "Out of range confidence finding",
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

      // A 0-100 scale reading would otherwise clear any --min-confidence floor.
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
                    result: { chosen: "P0", confidence: 95, probabilities: [] },
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
        minConfidence: 0.9,
        fallbackToClaude: false,
        sageClient: mockSageClient,
      });

      expect(result).toEqual({ triaged: 0, p0: 0, p1: 0, p2: 0, skip: 0 });
      expect(loadAllFileRecords(projectId)[0].findings[0].triage).toBeUndefined();
    });

    it("keeps the boundary confidences 0 and 1", async () => {
      for (const [file, value] of [
        ["src/zero.ts", 0],
        ["src/one.ts", 1],
      ] as const) {
        writeFileRecord({
          projectId,
          filePath: file,
          fileHash: `hash-${file}`,
          status: "analyzed",
          lastScannedAt: new Date().toISOString(),
          lastScannedRunId: "run1",
          candidates: [],
          findings: [
            {
              title: `Boundary ${value} finding`,
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

      const mockSageClient = {
        decideBatch: vi.fn(async (req: { requests: { content: string }[] }) => ({
          results: req.requests.map((r) => ({
            answers: [
              {
                ok: true,
                result: {
                  id: "priority",
                  kind: "choice",
                  result: {
                    chosen: "P2",
                    confidence: r.content.includes("Boundary 0 finding") ? 0 : 1,
                    probabilities: [],
                  },
                },
              },
            ],
          })),
          meta: { model: SAGE_MODEL_NAME },
        })),
      } as unknown as LevantoSageClient;

      await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        sageClient: mockSageClient,
      });

      const confidences = loadAllFileRecords(projectId)
        .map((r) => r.findings[0].triage?.confidence)
        .sort();
      expect(confidences).toEqual([0, 1]);
    });

    it("omits confidence when Sage does not report one", async () => {
      writeFileRecord({
        projectId,
        filePath: "src/noconfidence.ts",
        fileHash: "hash-noconf",
        status: "analyzed",
        lastScannedAt: new Date().toISOString(),
        lastScannedRunId: "run1",
        candidates: [],
        findings: [
          {
            title: "No confidence finding",
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
                    result: { chosen: "P2", probabilities: [] },
                  },
                },
              ],
            },
          ],
          meta: { model: SAGE_MODEL_NAME },
        })),
      } as unknown as LevantoSageClient;

      await triage({
        projectId,
        severity: "MEDIUM",
        provider: "sage",
        sageClient: mockSageClient,
      });

      const triaged = loadAllFileRecords(projectId)[0].findings[0].triage;
      expect(triaged?.priority).toBe("P2");
      expect(triaged?.confidence).toBeUndefined();
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
