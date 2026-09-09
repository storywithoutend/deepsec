import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { CandidateMatch, FileRecord } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildCandidateGateContent,
  DEFAULT_SAGE_GATE_CONFIDENCE,
  extractSurroundingLines,
  filterCandidatesWithSage,
  getRuleDescription,
  parseYesNoResult,
  SAGE_GATE_QUESTION_INSTRUCTIONS,
} from "../gate.js";
import { LevantoSageAuthError, LevantoSageServerError } from "../sage/client.js";

function createTestRecord(filePath: string, candidates: CandidateMatch[] = []): FileRecord {
  return {
    filePath,
    projectId: "test-proj",
    candidates,
    lastScannedAt: new Date().toISOString(),
    lastScannedRunId: "scan-test",
    fileHash: "hash-test",
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

    it("extractSurroundingLines handles empty or missing line numbers", () => {
      const content = "const a = 1;\nconst b = 2;";
      expect(extractSurroundingLines("", [1])).toBe("");
      expect(extractSurroundingLines(content, [])).toBe(content);
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
      const record = createTestRecord("src/queries.ts", [benignCandidate]);

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
        threshold: 0.9,
        sageClient: mockSageClient as any,
      });
      expect(retainedResult.filteredCount).toBe(0);
      expect(retainedResult.retainedCount).toBe(1);

      // With threshold 0.85, confidence 0.88 is filtered
      const filteredResult = await filterCandidatesWithSage({
        candidates: [candidate],
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
      const fullPath = path.join(tmpDir, filePath);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(
        fullPath,
        "// Header comment\nconst x = 1;\nconst query = 'SELECT ' + input;\nconst y = 2;\n",
      );

      const candidate: CandidateMatch = {
        vulnSlug: "sql-injection",
        lineNumbers: [3],
        snippet: "const query = 'SELECT ' + input;",
        matchedPattern: "SELECT",
      };
      const record = createTestRecord(filePath, [candidate]);

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

    it("falls back to candidate snippet when file does not exist on disk", async () => {
      const candidate: CandidateMatch = {
        vulnSlug: "xss",
        lineNumbers: [5],
        snippet: "element.innerHTML = untrusted;",
        matchedPattern: "innerHTML",
      };
      const record = createTestRecord("does-not-exist.ts", [candidate]);

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

      expect(capturedContent).toContain(
        "Candidate Match Snippet:\n```\nelement.innerHTML = untrusted;",
      );
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

      const record1 = createTestRecord("file1.ts", [benignCand1, realCand]);
      const record2 = createTestRecord("file2.ts", [benignCand2]);

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

      expect(progressMessage).toContain("Filtered 2 candidate(s)");
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
