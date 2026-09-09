import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { CandidateMatch, FileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildCandidateGateContent,
  DEFAULT_SAGE_GATE_CONFIDENCE,
  extractCandidateContext,
  extractSurroundingLines,
  filterCandidatesWithSage,
  GATE_BLOCK_CHAR_LIMIT,
  GATE_CONTEXT_LINE_LIMIT,
  getRuleDescription,
  parseYesNoResult,
  SAGE_GATE_QUESTION_INSTRUCTIONS,
} from "../gate.js";
import {
  LevantoSageAuthError,
  LevantoSageServerError,
  LevantoSageValidationError,
} from "../sage/client.js";

function fileWithLines(count = 60): string {
  return Array.from({ length: count }, (_, i) => `line ${i + 1}`).join("\n");
}

function writeFile(dir: string, relPath: string, content: string): string {
  const full = path.join(dir, relPath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return hashOf(content);
}

function writeScratchRoot(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-gate-root-"));
  for (const [relPath, content] of Object.entries(files)) {
    const full = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

function hashOf(content: string): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function createTestRecord(
  filePath: string,
  candidates: CandidateMatch[] = [],
  fileHash = "hash-test",
): FileRecord {
  return {
    filePath,
    projectId: "test-proj",
    candidates,
    lastScannedAt: new Date().toISOString(),
    lastScannedRunId: "scan-test",
    fileHash,
    findings: [],
    analysisHistory: [],
    status: "pending",
  };
}

describe("Sage candidate gate", () => {
  describe("helper functions", () => {
    it("extractSurroundingLines extracts context window around line numbers", () => {
      const lines = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`);
      const content = lines.join("\n");

      // Line 15 with 5 lines context -> lines 10 to 20
      const context = extractSurroundingLines(content, [15], 5);
      expect(context).toContain("line 10");
      expect(context).toContain("line 15");
      expect(context).toContain("line 20");
      expect(context).not.toContain("line 8");
      expect(context).not.toContain("line 22");
    });

    it("extractSurroundingLines handles start/end boundaries safely", () => {
      const content = "line 1\nline 2\nline 3\nline 4\nline 5";
      const context = extractSurroundingLines(content, [1], 5);
      expect(context).toBe(content);
    });

    it("windows every match and caps the total when hits span the whole file", () => {
      const content = Array.from({ length: 1200 }, (_, i) => `line ${i + 1}`).join("\n");
      // One candidate carrying every hit in the file — matchers commonly do this.
      const { text, coveredLines } = extractCandidateContext(content, [12, 45, 300, 1180]);

      const codeLines = text.split("\n").filter((l: string) => l !== "…");
      expect(codeLines.length).toBeLessThanOrEqual(GATE_CONTEXT_LINE_LIMIT);
      // Every hit is visible, not just the first — filtering the candidate on
      // one benign hit while three others were never sent would be unsafe.
      for (const hit of [12, 45, 300, 1180]) {
        expect(codeLines).toContain(`line ${hit}`);
      }
      expect(coveredLines).toEqual([12, 45, 300, 1180]);
      // Non-contiguous windows are marked as elided rather than run together.
      expect(text).toContain("\n…\n");
      expect(text).not.toContain("line 200");
    });

    it("covers every hit of a many-hit candidate by shrinking the windows", () => {
      const content = Array.from({ length: 2000 }, (_, i) => `line ${i + 1}`).join("\n");
      const hits = Array.from({ length: 40 }, (_, i) => 20 + i * 40);
      const { text, coveredLines } = extractCandidateContext(content, hits);

      const codeLines = text.split("\n").filter((l: string) => l !== "…");
      expect(codeLines.length).toBeLessThanOrEqual(GATE_CONTEXT_LINE_LIMIT);
      expect(coveredLines).toEqual(hits);
    });

    it("spends leftover budget widening the windows of a many-hit candidate", () => {
      const content = Array.from({ length: 2000 }, (_, i) => `line ${i + 1}`).join("\n");
      const hits = Array.from({ length: 21 }, (_, i) => 20 + i * 40);
      const { text, coveredLines } = extractCandidateContext(content, hits);

      const codeLines = text.split("\n").filter((l: string) => l !== "…");
      expect(coveredLines).toEqual(hits);
      // Bare matched lines alone would be 21; the rest of the budget buys
      // surrounding context instead of going unused.
      expect(codeLines.length).toBeGreaterThan(hits.length);
      expect(codeLines.length).toBeLessThanOrEqual(GATE_CONTEXT_LINE_LIMIT);
    });

    it("stops at the character budget so the context is never clamped later", () => {
      const wide = "x".repeat(300);
      const content = Array.from({ length: 2000 }, (_, i) => `${wide} ${i + 1}`).join("\n");
      const hits = Array.from({ length: 40 }, (_, i) => 20 + i * 40);
      const { text, coveredLines } = extractCandidateContext(content, hits);

      expect(text.length).toBeLessThanOrEqual(GATE_BLOCK_CHAR_LIMIT);
      // Coverage reflects the character cap, not just the line cap.
      expect(coveredLines.length).toBeLessThan(hits.length);
    });

    it("drops hit lines past the end of the file instead of inflating the budget", () => {
      // A stale record: the file shrank after it was scanned.
      const content = Array.from({ length: 100 }, (_, i) => `line ${i + 1}`).join("\n");
      const hits = Array.from({ length: 60 }, (_, i) => 20 + i * 30);
      const { text, coveredLines } = extractCandidateContext(content, hits);

      const codeLines = text.split("\n").filter((l: string) => l !== "…");
      expect(codeLines.length).toBeLessThanOrEqual(GATE_CONTEXT_LINE_LIMIT);
      expect(coveredLines).toEqual(hits.filter((h) => h <= 100));
      expect(codeLines.every((l: string) => l.startsWith("line "))).toBe(true);
    });

    it("reports only the hits it actually sent when the cap truncates windows", () => {
      const content = Array.from({ length: 4000 }, (_, i) => `line ${i + 1}`).join("\n");
      const hits = Array.from({ length: 80 }, (_, i) => 20 + i * 40);
      const { text, coveredLines } = extractCandidateContext(content, hits);

      const codeLines = text.split("\n").filter((l: string) => l !== "…");
      expect(codeLines.length).toBeLessThanOrEqual(GATE_CONTEXT_LINE_LIMIT);
      expect(coveredLines.length).toBeLessThan(hits.length);
      for (const covered of coveredLines) {
        expect(codeLines).toContain(`line ${covered}`);
      }
      for (const hit of hits.filter((h) => !coveredLines.includes(h))) {
        expect(codeLines).not.toContain(`line ${hit}`);
      }
    });

    it("buildCandidateGateContent truncates oversized code blocks", () => {
      const huge = "x".repeat(GATE_BLOCK_CHAR_LIMIT * 3);
      const content = buildCandidateGateContent({
        snippet: huge,
        surroundingContext: `${huge}-context`,
        vulnSlug: "rce",
      });

      expect(content).toContain("… (truncated)");
      expect(content.length).toBeLessThan(GATE_BLOCK_CHAR_LIMIT * 3);
    });

    it("extractSurroundingLines handles empty or missing line numbers", () => {
      const content = "const a = 1;\nconst b = 2;";
      expect(extractSurroundingLines("", [1])).toBe("");
      expect(extractSurroundingLines(content, [])).toBe(content);
      // Hits that no longer exist in the file yield no context at all rather
      // than the unrelated head of the file.
      expect(extractCandidateContext(content, [900])).toEqual({ text: "", coveredLines: [] });
    });

    it("buildCandidateGateContent includes snippet, surrounding context, and rule description", () => {
      const content = buildCandidateGateContent({
        snippet: 'eval("2 + 2")',
        surroundingContext: 'function run() {\n  eval("2 + 2")\n}',
        ruleDescription: "exec, spawn, eval, Function constructor with potential user input",
        vulnSlug: "rce",
        filePath: "src/calc.ts",
        lineNumbers: [2],
      });

      expect(content).toContain("File: src/calc.ts (lines 2)");
      expect(content).toContain("Vulnerability Type: rce");
      expect(content).toContain("Vulnerability Rule Description: exec, spawn, eval");
      expect(content).toContain('Candidate Match Snippet:\n```\neval("2 + 2")\n```');
      expect(content).toContain("Surrounding Context:\n```\nfunction run()");
    });

    it("buildCandidateGateContent omits surrounding context when identical to snippet", () => {
      const content = buildCandidateGateContent({
        snippet: 'eval("2 + 2")',
        surroundingContext: 'eval("2 + 2")',
        ruleDescription: "RCE rule",
        vulnSlug: "rce",
      });

      expect(content).toContain("Candidate Match Snippet:");
      expect(content).not.toContain("Surrounding Context:");
    });

    it("getRuleDescription resolves descriptions for built-in slugs", () => {
      const sqlDesc = getRuleDescription("sql-injection");
      expect(sqlDesc).toContain("SQL");

      const xssDesc = getRuleDescription("xss");
      expect(xssDesc).toContain("innerHTML");

      const unknownDesc = getRuleDescription("non-existent-rule-slug");
      expect(unknownDesc).toBe("non-existent-rule-slug");
    });

    it("parseYesNoResult handles objects, strings, booleans, and nulls", () => {
      expect(parseYesNoResult({ answer: "no", confidence: 0.9 })).toEqual({
        answer: "no",
        confidence: 0.9,
      });
      expect(parseYesNoResult({ answer: true, confidence: 0.8 })).toEqual({
        answer: "yes",
        confidence: 0.8,
      });
      expect(parseYesNoResult({ answer: false, confidence: 0.85 })).toEqual({
        answer: "no",
        confidence: 0.85,
      });
      expect(parseYesNoResult({ chosen: "NO", confidence: 0.92 })).toEqual({
        answer: "no",
        confidence: 0.92,
      });
      // A bare payload carries no calibrated confidence: report none rather
      // than synthesizing 1.0 and bypassing the caller's threshold.
      expect(parseYesNoResult("yes")).toEqual({ answer: "yes", confidence: undefined });
      expect(parseYesNoResult(false)).toEqual({ answer: "no", confidence: undefined });
      expect(parseYesNoResult(null)).toEqual({});
      expect(parseYesNoResult(undefined)).toEqual({});
    });
  });

  describe("benign filtering", () => {
    it("filters out obvious benign candidates when Sage answers 'yes' with confidence >= threshold", async () => {
      const mockCandidate: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [10],
        snippet: "const query = 'SELECT * FROM users WHERE active = 1';",
        matchedPattern: "SELECT",
      };

      let capturedRequest: any = null;
      const mockSageClient = {
        decideBatch: vi.fn(async (req: any) => {
          capturedRequest = req;
          return {
            results: [
              {
                answers: [
                  {
                    ok: true,
                    result: {
                      id: "benign_false_positive",
                      kind: "yesno",
                      result: { answer: "yes", confidence: 0.95 },
                    },
                  },
                ],
              },
            ],
          };
        }),
      };

      const result = await filterCandidatesWithSage({
        candidates: [mockCandidate],
        filePath: "src/db.ts",
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      // Verify question spec
      expect(mockSageClient.decideBatch).toHaveBeenCalledTimes(1);
      const firstGroup = capturedRequest.requests[0];
      expect(firstGroup.questions[0]).toEqual({
        id: "benign_false_positive",
        kind: "yesno",
        instructions: SAGE_GATE_QUESTION_INSTRUCTIONS,
      });
      expect(capturedRequest.latency_mode).toBe("fast");
      expect(firstGroup.content).toContain(mockCandidate.snippet);
      expect(firstGroup.content).toContain("sql-injection");

      // Verify candidate was filtered
      expect(result.filteredCount).toBe(1);
      expect(result.retainedCount).toBe(0);
      expect(result.retainedCandidates).toHaveLength(0);
      expect(result.filteredCandidates).toEqual([mockCandidate]);
      expect(result.decisions[0].filtered).toBe(true);
      expect(result.decisions[0].answer).toBe("yes");
      expect(result.decisions[0].confidence).toBe(0.95);
    });

    it("reports retained candidates per file without mutating the record", async () => {
      const benignCandidate: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [5],
        snippet: "const staticSql = 'SELECT 1';",
        matchedPattern: "SELECT",
      };
      const rootPath = writeScratchRoot({ "src/queries.ts": fileWithLines() });
      const record = createTestRecord("src/queries.ts", [benignCandidate], hashOf(fileWithLines()));

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.9 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        records: [record],
        rootPath,
        sageClient: mockSageClient as any,
      });

      expect(result.filteredCount).toBe(1);
      expect(result.retainedCandidatesByFile.get("src/queries.ts")).toEqual([]);
      // Persisted scan state is untouched: a later run without the gate
      // still sees the candidate.
      expect(record.candidates).toEqual([benignCandidate]);
    });
  });

  describe("vulnerability retention", () => {
    it("retains a candidate when no file content was available to gate on", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "crypto-usage",
        // The snippet covers the first hit only; the others exist solely in the
        // file, which the caller gave the gate no way to read.
        lineNumbers: [12, 40, 88, 140],
        snippet: "hash := md5.New()",
        matchedPattern: "md5",
      };
      const record = createTestRecord("pkg/crypto/util.go", [candidate]);

      let capturedContent = "";
      const mockSageClient = {
        decideBatch: vi.fn(async (req: any) => {
          capturedContent = req.requests[0].content;
          return {
            results: [
              {
                answers: [
                  {
                    ok: true,
                    result: {
                      id: "benign_false_positive",
                      kind: "yesno",
                      result: { answer: "yes", confidence: 0.99 },
                    },
                  },
                ],
              },
            ],
          };
        }),
      };

      const result = await filterCandidatesWithSage({
        records: [record],
        sageClient: mockSageClient as any,
      });

      // The verdict could only ever be ignored, so the request is never made.
      expect(mockSageClient.decideBatch).not.toHaveBeenCalled();
      expect(capturedContent).toBe("");
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCandidatesByFile.get("pkg/crypto/util.go")).toEqual([candidate]);
    });

    it("retains candidate when Sage answers 'no' (vulnerability plausible) with high confidence", async () => {
      const realVulnCandidate: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [12],
        snippet: "const query = 'SELECT * FROM users WHERE id = ' + req.params.id;",
        matchedPattern: "SELECT",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "no", confidence: 0.98 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        candidates: [realVulnCandidate],
        fileContent: fileWithLines(),
        filePath: "src/api.ts",
        sageClient: mockSageClient as any,
      });

      expect(result.filteredCount).toBe(0);
      expect(result.retainedCount).toBe(1);
      expect(result.retainedCandidates).toEqual([realVulnCandidate]);
      expect(result.decisions[0].filtered).toBe(false);
      expect(result.decisions[0].answer).toBe("no");
    });

    it("retains candidate when Sage calls it benign with low confidence", async () => {
      const borderlineCandidate: CandidateMatch = {
        vulnSlug: "open-redirect",
        lineNumbers: [25],
        snippet: "res.redirect(targetUrl);",
        matchedPattern: "redirect",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.55 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        candidates: [borderlineCandidate],
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      expect(result.filteredCount).toBe(0);
      expect(result.retainedCount).toBe(1);
      expect(result.retainedCandidates).toEqual([borderlineCandidate]);
      expect(result.decisions[0].filtered).toBe(false);
    });
  });

  describe("threshold boundaries", () => {
    it("default threshold is 0.85", () => {
      expect(DEFAULT_SAGE_GATE_CONFIDENCE).toBe(0.85);
    });

    it("filters candidate at exact threshold boundary (confidence === 0.85)", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "xss",
        lineNumbers: [10],
        snippet: "element.innerHTML = '<b>safe</b>';",
        matchedPattern: "innerHTML",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.85 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      // confidence 0.85 >= default threshold 0.85 -> filtered
      expect(result.filteredCount).toBe(1);
      expect(result.retainedCount).toBe(0);
      expect(result.decisions[0].filtered).toBe(true);
    });

    it("retains candidate when confidence is just below threshold (confidence = 0.849)", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "xss",
        lineNumbers: [10],
        snippet: "element.innerHTML = maybeSafe;",
        matchedPattern: "innerHTML",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.849 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      // confidence 0.849 < threshold 0.85 -> retained (fail-safe)
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCount).toBe(1);
      expect(result.retainedCandidates).toEqual([candidate]);
      expect(result.decisions[0].filtered).toBe(false);
    });

    it("respects custom threshold (e.g. 0.90)", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "auth-bypass",
        lineNumbers: [20],
        snippet: "if (!user.isAdmin) return;",
        matchedPattern: "isAdmin",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.88 },
                  },
                },
              ],
            },
          ],
        })),
      };

      // With threshold 0.90, confidence 0.88 is retained
      const retainedResult = await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        threshold: 0.9,
        sageClient: mockSageClient as any,
      });
      expect(retainedResult.filteredCount).toBe(0);
      expect(retainedResult.retainedCount).toBe(1);

      // With threshold 0.85, confidence 0.88 is filtered
      const filteredResult = await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        threshold: 0.85,
        sageClient: mockSageClient as any,
      });
      expect(filteredResult.filteredCount).toBe(1);
      expect(filteredResult.retainedCount).toBe(0);
    });
  });

  describe("fail-open behavior", () => {
    it("fails open when Sage API throws a network error", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [1],
        snippet: "query()",
        matchedPattern: "query",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => {
          throw new TypeError("fetch failed: connection refused");
        }),
      };

      const result = await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      // Network error fails open: candidate is retained, run does not crash
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCount).toBe(1);
      expect(result.retainedCandidates).toEqual([candidate]);
      expect(result.decisions[0].filtered).toBe(false);
      expect(result.decisions[0].error).toContain("fetch failed");
    });

    it("fails open on LevantoSageServerError (500)", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "rce",
        lineNumbers: [1],
        snippet: "exec()",
        matchedPattern: "exec",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => {
          throw new LevantoSageServerError("Internal server error", { status: 500 });
        }),
      };

      const result = await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      expect(result.filteredCount).toBe(0);
      expect(result.retainedCount).toBe(1);
      expect(result.retainedCandidates).toEqual([candidate]);
      expect(result.decisions[0].filtered).toBe(false);
    });

    it("fails open on individual batch answer error", async () => {
      const c1: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [1],
        snippet: "db.query()",
        matchedPattern: "query",
      };
      const c2: CandidateMatch = {
        vulnSlug: "xss",
        lineNumbers: [2],
        snippet: "element.innerHTML = 'foo'",
        matchedPattern: "innerHTML",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              // Answer 1 has an error
              answers: [{ ok: false, error: "model timeout on this question" }],
            },
            {
              // Answer 2 succeeded and is benign
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.92 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        candidates: [c1, c2],
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      // c1 failed open and was retained; c2 was successfully filtered
      expect(result.filteredCount).toBe(1);
      expect(result.retainedCount).toBe(1);
      expect(result.retainedCandidates).toEqual([c1]);
      expect(result.filteredCandidates).toEqual([c2]);
      expect(result.errorCount).toBe(1);
      expect(result.errors).toEqual(["model timeout on this question"]);
    });

    it("fails only the malformed answer, not the candidates already decided", async () => {
      const benign: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [1],
        snippet: "const q = 'SELECT 1';",
        matchedPattern: "SELECT",
      };
      const other: CandidateMatch = {
        vulnSlug: "xss",
        lineNumbers: [2],
        snippet: "el.innerHTML = 'constant'",
        matchedPattern: "innerHTML",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.99 },
                  },
                },
              ],
            },
            // Malformed group: decoding it throws.
            { answers: [null] },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        candidates: [benign, other],
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      // One decision per candidate — no candidate is both filtered and retained.
      expect(result.totalCandidates).toBe(2);
      expect(result.filteredCandidates).toEqual([benign]);
      expect(result.retainedCandidates).toEqual([other]);
      expect(result.errorCount).toBe(1);
    });

    it("counts a failed answer with no message as an error", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [1],
        snippet: "db.query()",
        matchedPattern: "query",
      };

      const mockSageClient = {
        // Malformed failure: `ok: false` with no error string.
        decideBatch: vi.fn(async () => ({ results: [{ answers: [{ ok: false }] }] })),
      };

      const result = await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      expect(result.filteredCount).toBe(0);
      expect(result.retainedCandidates).toEqual([candidate]);
      // Without a message the failure would be invisible in the run summary.
      expect(result.errorCount).toBe(1);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toBeTruthy();
    });

    it("fails open when answer format is unrecognized or null", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [1],
        snippet: "test",
        matchedPattern: "test",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "maybe", confidence: 0.99 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      // "maybe" is not "yes" -> retained
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCount).toBe(1);
      expect(result.decisions[0].filtered).toBe(false);
    });

    it("retains a candidate whose benign verdict carries no confidence", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [1],
        snippet: "const q = 'SELECT 1';",
        matchedPattern: "SELECT",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  // Bare payload: an answer with no calibrated confidence.
                  result: { id: "benign_false_positive", kind: "yesno", result: "yes" },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        threshold: 0.99,
        sageClient: mockSageClient as any,
      });

      expect(result.decisions[0].answer).toBe("yes");
      expect(result.decisions[0].confidence).toBeUndefined();
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCandidates).toEqual([candidate]);
    });

    it("stops calling Sage after a permanent error and fails the rest open", async () => {
      const candidates: CandidateMatch[] = [1, 2, 3, 4].map((n) => ({
        vulnSlug: "sql-injection",
        lineNumbers: [n],
        snippet: `query${n}()`,
        matchedPattern: "query",
      }));

      const mockSageClient = {
        decideBatch: vi.fn(async () => {
          throw new LevantoSageAuthError("API key required or invalid.");
        }),
      };

      const result = await filterCandidatesWithSage({
        candidates,
        fileContent: fileWithLines(),
        batchSize: 1,
        sageClient: mockSageClient as any,
      });

      // One doomed round trip, not one per chunk.
      expect(mockSageClient.decideBatch).toHaveBeenCalledTimes(1);
      // Every candidate is still accounted for and retained.
      expect(result.errorCount).toBe(4);
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCandidates).toEqual(candidates);
      expect(result.errors).toEqual(["API key required or invalid."]);
    });

    it("keeps calling Sage after a request-scoped rejection", async () => {
      const candidates: CandidateMatch[] = [1, 2, 3].map((n) => ({
        vulnSlug: "rce",
        lineNumbers: [n],
        snippet: `exec${n}()`,
        matchedPattern: "exec",
      }));

      let call = 0;
      const mockSageClient = {
        decideBatch: vi.fn(async () => {
          call++;
          if (call === 1) {
            // 400 / oversized payload: this request is doomed, the next is not.
            throw new LevantoSageValidationError("request payload rejected");
          }
          return {
            results: [
              {
                answers: [
                  {
                    ok: true,
                    result: {
                      id: "benign_false_positive",
                      kind: "yesno",
                      result: { answer: "yes", confidence: 0.99 },
                    },
                  },
                ],
              },
            ],
          };
        }),
      };

      const result = await filterCandidatesWithSage({
        candidates,
        fileContent: fileWithLines(),
        batchSize: 1,
        sageClient: mockSageClient as any,
      });

      expect(mockSageClient.decideBatch).toHaveBeenCalledTimes(3);
      expect(result.errorCount).toBe(1);
      expect(result.filteredCount).toBe(2);
    });

    it("keeps calling Sage after a retryable error", async () => {
      const candidates: CandidateMatch[] = [1, 2].map((n) => ({
        vulnSlug: "xss",
        lineNumbers: [n],
        snippet: `innerHTML${n}`,
        matchedPattern: "innerHTML",
      }));

      const mockSageClient = {
        decideBatch: vi.fn(async () => {
          throw new LevantoSageServerError("Internal server error", { status: 500 });
        }),
      };

      const result = await filterCandidatesWithSage({
        candidates,
        fileContent: fileWithLines(),
        batchSize: 1,
        sageClient: mockSageClient as any,
      });

      expect(mockSageClient.decideBatch).toHaveBeenCalledTimes(2);
      expect(result.errorCount).toBe(2);
      expect(result.retainedCount).toBe(2);
    });

    it("fails the whole chunk open when the batch response length does not match", async () => {
      const realVuln: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [1],
        snippet: "db.query('SELECT ' + input)",
        matchedPattern: "SELECT",
      };
      const other: CandidateMatch = {
        vulnSlug: "xss",
        lineNumbers: [2],
        snippet: "el.innerHTML = 'constant'",
        matchedPattern: "innerHTML",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          // One result for two requests: positional binding would score the
          // real vulnerability with a verdict meant for another candidate.
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.99 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        candidates: [realVuln, other],
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      expect(result.filteredCount).toBe(0);
      expect(result.retainedCandidates).toEqual([realVuln, other]);
      expect(result.errorCount).toBe(2);
      expect(result.errors[0]).toContain("1 result(s) for 2 request(s)");
    });

    it("works with single decide API and fails open on single decide error", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [1],
        snippet: "test",
        matchedPattern: "test",
      };

      const mockSageClient = {
        decide: vi.fn(async () => {
          throw new Error("HTTP 429 rate limit exceeded");
        }),
      };

      const result = await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        sageClient: mockSageClient as any,
      });

      expect(result.filteredCount).toBe(0);
      expect(result.retainedCount).toBe(1);
      expect(result.retainedCandidates).toEqual([candidate]);
      expect(result.decisions[0].filtered).toBe(false);
    });
  });

  describe("surrounding context extraction and rule resolution", () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-gate-test-"));
    });

    afterEach(() => {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        // Ignored
      }
    });

    it("extracts context from file on disk and resolves rule description", async () => {
      const filePath = "src/example.ts";
      const fileHash = writeFile(
        tmpDir,
        filePath,
        "// Header comment\nconst x = 1;\nconst query = 'SELECT ' + input;\nconst y = 2;\n",
      );

      const candidate: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [3],
        snippet: "const query = 'SELECT ' + input;",
        matchedPattern: "SELECT",
      };
      const record = createTestRecord(filePath, [candidate], fileHash);

      let capturedContent = "";
      const mockSageClient = {
        decideBatch: vi.fn(async (req: any) => {
          capturedContent = req.requests[0].content;
          return {
            results: [
              {
                answers: [
                  {
                    ok: true,
                    result: {
                      id: "benign_false_positive",
                      kind: "yesno",
                      result: { answer: "yes", confidence: 0.9 },
                    },
                  },
                ],
              },
            ],
          };
        }),
      };

      await filterCandidatesWithSage({
        records: [record],
        rootPath: tmpDir,
        sageClient: mockSageClient as any,
      });

      expect(capturedContent).toContain("File: src/example.ts (lines 3)");
      expect(capturedContent).toContain("Header comment");
      expect(capturedContent).toContain("Vulnerability Rule Description:");
    });

    it("advertises only the hit lines the sent context actually covers", async () => {
      const filePath = "src/many-hits.ts";
      const fileHash = writeFile(
        tmpDir,
        filePath,
        `${Array.from({ length: 4000 }, (_, i) => `line ${i + 1}`).join("\n")}\n`,
      );

      const hits = Array.from({ length: 80 }, (_, i) => 20 + i * 40);
      const candidate: CandidateMatch = {
        vulnSlug: "crypto-usage",
        lineNumbers: hits,
        snippet: "line 20",
        matchedPattern: "crypto",
      };
      const record = createTestRecord(filePath, [candidate], fileHash);

      let capturedContent = "";
      const mockSageClient = {
        decideBatch: vi.fn(async (req: any) => {
          capturedContent = req.requests[0].content;
          return {
            results: [
              {
                answers: [
                  {
                    ok: true,
                    result: {
                      id: "benign_false_positive",
                      kind: "yesno",
                      result: { answer: "no", confidence: 0.9 },
                    },
                  },
                ],
              },
            ],
          };
        }),
      };

      const result = await filterCandidatesWithSage({
        records: [record],
        rootPath: tmpDir,
        sageClient: mockSageClient as any,
      });

      // The cap left hits unsent, so no verdict could be acted on: the gate
      // must not spend a request to buy one, and must not report the retain as
      // "Sage found nothing benign".
      expect(mockSageClient.decideBatch).not.toHaveBeenCalled();
      expect(capturedContent).toBe("");
      expect(result.totalCandidates).toBe(1);
      expect(result.unevaluatedCount).toBe(1);
      expect(result.errorCount).toBe(0);
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCandidatesByFile.get(filePath)).toEqual([candidate]);
    });

    it("filters a many-hit candidate once every hit fits the context window", async () => {
      const filePath = "src/many-but-covered.ts";
      const fileHash = writeFile(
        tmpDir,
        filePath,
        `${Array.from({ length: 2000 }, (_, i) => `line ${i + 1}`).join("\n")}\n`,
      );

      const candidate: CandidateMatch = {
        vulnSlug: "crypto-usage",
        lineNumbers: Array.from({ length: 40 }, (_, i) => 20 + i * 40),
        snippet: "line 20",
        matchedPattern: "crypto",
      };
      const record = createTestRecord(filePath, [candidate], fileHash);

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.99 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        records: [record],
        rootPath: tmpDir,
        sageClient: mockSageClient as any,
      });

      // Sage saw all 40 hits, so its benign verdict applies to the whole
      // candidate — the gate must actually save the agent run here.
      expect(mockSageClient.decideBatch).toHaveBeenCalledTimes(1);
      expect(result.unevaluatedCount).toBe(0);
      expect(result.filteredCount).toBe(1);
      expect(result.retainedCandidatesByFile.get(filePath)).toEqual([]);
    });

    it("retains a candidate whose context was cut by the character budget", async () => {
      const filePath = "src/wide-lines.ts";
      const wide = "x".repeat(300);
      const fileHash = writeFile(
        tmpDir,
        filePath,
        `${Array.from({ length: 2000 }, (_, i) => `${wide} ${i + 1}`).join("\n")}\n`,
      );

      const candidate: CandidateMatch = {
        vulnSlug: "crypto-usage",
        // Few enough hits to fit the line budget, too wide to fit the char budget.
        lineNumbers: Array.from({ length: 40 }, (_, i) => 20 + i * 40),
        snippet: `${wide} 20`,
        matchedPattern: "crypto",
      };
      const record = createTestRecord(filePath, [candidate], fileHash);

      let capturedContent = "";
      const mockSageClient = {
        decideBatch: vi.fn(async (req: any) => {
          capturedContent = req.requests[0].content;
          return {
            results: [
              {
                answers: [
                  {
                    ok: true,
                    result: {
                      id: "benign_false_positive",
                      kind: "yesno",
                      result: { answer: "yes", confidence: 0.99 },
                    },
                  },
                ],
              },
            ],
          };
        }),
      };

      const result = await filterCandidatesWithSage({
        records: [record],
        rootPath: tmpDir,
        sageClient: mockSageClient as any,
      });

      expect(mockSageClient.decideBatch).not.toHaveBeenCalled();
      expect(capturedContent).toBe("");
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCandidatesByFile.get(filePath)).toEqual([candidate]);
    });

    it("retains a candidate whose snippet is too large to send in full", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "rce",
        lineNumbers: [1],
        snippet: "x".repeat(GATE_BLOCK_CHAR_LIMIT * 2),
        matchedPattern: "exec",
      };

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.99 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        filePath: "src/huge.ts",
        sageClient: mockSageClient as any,
      });

      expect(mockSageClient.decideBatch).not.toHaveBeenCalled();
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCandidates).toEqual([candidate]);
    });

    it("retains a candidate whose hits did not all fit the context window", async () => {
      const filePath = "src/partial.ts";
      const fileHash = writeFile(
        tmpDir,
        filePath,
        `${Array.from({ length: 4000 }, (_, i) => `line ${i + 1}`).join("\n")}\n`,
      );

      const candidate: CandidateMatch = {
        vulnSlug: "crypto-usage",
        lineNumbers: Array.from({ length: 80 }, (_, i) => 20 + i * 40),
        snippet: "line 20",
        matchedPattern: "crypto",
      };
      const record = createTestRecord(filePath, [candidate], fileHash);

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.99 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        records: [record],
        rootPath: tmpDir,
        sageClient: mockSageClient as any,
      });

      // Sage is never consulted about a candidate it could not see whole, and
      // the candidate stays visible to the agent.
      expect(mockSageClient.decideBatch).not.toHaveBeenCalled();
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCandidatesByFile.get(filePath)).toEqual([candidate]);
    });

    it("retains a candidate whose file changed since it was scanned", async () => {
      const filePath = "src/shifted.ts";
      writeFile(tmpDir, filePath, "// inserted header\n// inserted header\nconst safe = 1;\n");

      const candidate: CandidateMatch = {
        vulnSlug: "sql-injection",
        // Line 3 held the match when the record was written; it holds unrelated
        // code now, so the extract cannot be shown to cover the candidate.
        lineNumbers: [3],
        snippet: "db.query(`SELECT * FROM u WHERE id=${req.query.id}`)",
        matchedPattern: "SELECT",
      };
      const record = createTestRecord(filePath, [candidate], hashOf("the file as scanned\n"));

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.99 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const result = await filterCandidatesWithSage({
        records: [record],
        rootPath: tmpDir,
        sageClient: mockSageClient as any,
      });

      expect(mockSageClient.decideBatch).not.toHaveBeenCalled();
      expect(result.unevaluatedCount).toBe(1);
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCandidatesByFile.get(filePath)).toEqual([candidate]);
    });

    it("retains a candidate whose file could not be read", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "crypto-usage",
        // The snippet only covers the first hit; the rest can only come from
        // the file, which is gone.
        lineNumbers: [12, 40, 88, 140],
        snippet: "hash := md5.New()",
        matchedPattern: "md5",
      };
      const record = createTestRecord("gone.go", [candidate]);

      let capturedContent = "";
      const mockSageClient = {
        decideBatch: vi.fn(async (req: any) => {
          capturedContent = req.requests[0].content;
          return {
            results: [
              {
                answers: [
                  {
                    ok: true,
                    result: {
                      id: "benign_false_positive",
                      kind: "yesno",
                      result: { answer: "yes", confidence: 0.99 },
                    },
                  },
                ],
              },
            ],
          };
        }),
      };

      const result = await filterCandidatesWithSage({
        records: [record],
        rootPath: tmpDir,
        sageClient: mockSageClient as any,
      });

      // Nothing to ask about: without the file the verdict could not be used.
      expect(mockSageClient.decideBatch).not.toHaveBeenCalled();
      expect(capturedContent).toBe("");
      expect(result.unevaluatedCount).toBe(1);
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCandidatesByFile.get("gone.go")).toEqual([candidate]);
    });

    it("falls back to the candidate snippet when it carries no line numbers", async () => {
      const filePath = "src/no-lines.ts";
      const fileHash = writeFile(tmpDir, filePath, "const unrelated = 1;\n");

      const candidate: CandidateMatch = {
        vulnSlug: "xss",
        lineNumbers: [],
        snippet: "element.innerHTML = untrusted;",
        matchedPattern: "innerHTML",
      };
      const record = createTestRecord(filePath, [candidate], fileHash);

      let capturedContent = "";
      const mockSageClient = {
        decideBatch: vi.fn(async (req: any) => {
          capturedContent = req.requests[0].content;
          return {
            results: [
              {
                answers: [
                  {
                    ok: true,
                    result: {
                      id: "benign_false_positive",
                      kind: "yesno",
                      result: { answer: "yes", confidence: 0.9 },
                    },
                  },
                ],
              },
            ],
          };
        }),
      };

      await filterCandidatesWithSage({
        records: [record],
        rootPath: tmpDir,
        sageClient: mockSageClient as any,
      });

      expect(mockSageClient.decideBatch).toHaveBeenCalledTimes(1);
      expect(capturedContent).toContain(
        "Candidate Match Snippet:\n```\nelement.innerHTML = untrusted;",
      );
      expect(capturedContent).not.toContain("const unrelated = 1;");
    });

    it("accepts custom ruleDescriptions map or resolver function", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "custom-rule-slug",
        lineNumbers: [1],
        snippet: "run()",
        matchedPattern: "run",
      };

      let capturedContent = "";
      const mockSageClient = {
        decideBatch: vi.fn(async (req: any) => {
          capturedContent = req.requests[0].content;
          return {
            results: [
              {
                answers: [
                  {
                    ok: true,
                    result: {
                      id: "benign_false_positive",
                      kind: "yesno",
                      result: { answer: "no", confidence: 0.9 },
                    },
                  },
                ],
              },
            ],
          };
        }),
      };

      await filterCandidatesWithSage({
        candidates: [candidate],
        fileContent: fileWithLines(),
        ruleDescriptions: {
          "custom-rule-slug": "Custom proprietary security check description",
        },
        sageClient: mockSageClient as any,
      });

      expect(capturedContent).toContain("Custom proprietary security check description");
    });
  });

  describe("multi-candidate and progress reporting", () => {
    it("processes mixed candidates across multiple files and reports them per file", async () => {
      const benignCand1: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [1],
        snippet: "SELECT 1",
        matchedPattern: "SELECT",
      };
      const realCand: CandidateMatch = {
        vulnSlug: "rce",
        lineNumbers: [2],
        snippet: "exec(userInput)",
        matchedPattern: "exec",
      };
      const benignCand2: CandidateMatch = {
        vulnSlug: "xss",
        lineNumbers: [3],
        snippet: "innerHTML = 'constant'",
        matchedPattern: "innerHTML",
      };

      const rootPath = writeScratchRoot({
        "file1.ts": fileWithLines(),
        "file2.ts": fileWithLines(),
      });
      const record1 = createTestRecord(
        "file1.ts",
        [benignCand1, realCand],
        hashOf(fileWithLines()),
      );
      const record2 = createTestRecord("file2.ts", [benignCand2], hashOf(fileWithLines()));

      const mockSageClient = {
        decideBatch: vi.fn(async (req: any) => ({
          results: req.requests.map((r: any) => {
            const isReal = r.content.includes("userInput");
            return {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: isReal
                      ? { answer: "no", confidence: 0.95 }
                      : { answer: "yes", confidence: 0.92 },
                  },
                },
              ],
            };
          }),
        })),
      };

      let progressMessage = "";
      const result = await filterCandidatesWithSage({
        records: [record1, record2],
        rootPath,
        sageClient: mockSageClient as any,
        onProgress: (p) => {
          progressMessage = p.message;
        },
      });

      expect(result.totalCandidates).toBe(3);
      expect(result.filteredCount).toBe(2);
      expect(result.retainedCount).toBe(1);
      expect(result.retainedCandidates).toEqual([realCand]);

      // Only the retained view narrows: record 1 keeps realCand, record 2 keeps nothing
      expect(result.retainedCandidatesByFile.get("file1.ts")).toEqual([realCand]);
      expect(result.retainedCandidatesByFile.get("file2.ts")).toEqual([]);
      // Both records still carry every scanner candidate
      expect(record1.candidates).toEqual([benignCand1, realCand]);
      expect(record2.candidates).toEqual([benignCand2]);

      expect(progressMessage).toContain("3/3 candidate(s) evaluated (2 filtered so far)");
    });

    it("emits progress at the start and after each chunk", async () => {
      const candidates: CandidateMatch[] = [1, 2].map((n) => ({
        vulnSlug: "xss",
        lineNumbers: [n],
        snippet: `innerHTML${n}`,
        matchedPattern: "innerHTML",
      }));

      const mockSageClient = {
        decideBatch: vi.fn(async () => ({
          results: [
            {
              answers: [
                {
                  ok: true,
                  result: {
                    id: "benign_false_positive",
                    kind: "yesno",
                    result: { answer: "yes", confidence: 0.99 },
                  },
                },
              ],
            },
          ],
        })),
      };

      const messages: string[] = [];
      await filterCandidatesWithSage({
        candidates,
        fileContent: fileWithLines(),
        batchSize: 1,
        sageClient: mockSageClient as any,
        onProgress: (p) => {
          messages.push(p.message);
        },
      });

      expect(messages[0]).toContain("Evaluating 2 candidate(s)");
      expect(messages[1]).toContain("1/2 candidate(s) evaluated");
      expect(messages[2]).toContain("2/2 candidate(s) evaluated");
    });

    it("returns empty result when no candidates exist", async () => {
      const record = createTestRecord("empty.ts", []);

      const mockSageClient = {
        decideBatch: vi.fn(),
      };

      const result = await filterCandidatesWithSage({
        records: [record],
        sageClient: mockSageClient as any,
      });

      expect(mockSageClient.decideBatch).not.toHaveBeenCalled();
      expect(result.totalCandidates).toBe(0);
      expect(result.filteredCount).toBe(0);
      expect(result.retainedCount).toBe(0);
    });
  });
});
