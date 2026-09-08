import fs from "node:fs";
import path from "node:path";
import type { CandidateMatch, FileRecord } from "@deepsec/core";
import { getRegistry } from "@deepsec/core";
import { createDefaultRegistry } from "@deepsec/scanner";
import {
  LevantoSageClient,
  type SageBatchRequestGroup,
  type SageYesNoQuestion,
} from "./sage/index.js";

export const DEFAULT_SAGE_GATE_CONFIDENCE = 0.85;

export const SAGE_GATE_QUESTION_INSTRUCTIONS =
  "Does this code snippet plausibly introduce the specified vulnerability, or is it an obvious benign false positive?";

let cachedRegistry: ReturnType<typeof createDefaultRegistry> | undefined;

/**
 * Retrieve the human-readable vulnerability rule description for a given slug.
 * Resolves against built-in matchers in @deepsec/scanner and any custom registered matchers.
 */
export function getRuleDescription(slug: string): string {
  try {
    if (!cachedRegistry) {
      cachedRegistry = createDefaultRegistry();
      for (const m of getRegistry().matchers) {
        cachedRegistry.register(m);
      }
    }
    const matcher = cachedRegistry.getBySlug(slug);
    if (matcher?.description) {
      return matcher.description;
    }
  } catch {
    // Fail silently and return the slug as fallback
  }
  return slug;
}

/**
 * Extract lines surrounding the matched line numbers from file content.
 */
export function extractSurroundingLines(
  content: string,
  lineNumbers: number[],
  contextLines = 10,
): string {
  const lines = content.split("\n");
  if (lines.length === 0) return "";
  const validLines = lineNumbers.filter((n) => typeof n === "number" && !Number.isNaN(n) && n > 0);
  if (validLines.length === 0) return content.slice(0, 1000);
  const minLine = Math.min(...validLines);
  const maxLine = Math.max(...validLines);
  const start = Math.max(0, minLine - 1 - contextLines);
  const end = Math.min(lines.length, maxLine + contextLines);
  return lines.slice(start, end).join("\n");
}

/**
 * Assemble content for Sage gate evaluation containing snippet, surrounding context,
 * and vulnerability rule description.
 */
export function buildCandidateGateContent(params: {
  snippet: string;
  surroundingContext?: string;
  ruleDescription?: string;
  vulnSlug?: string;
  filePath?: string;
  lineNumbers?: number[];
}): string {
  const parts: string[] = [];
  if (params.filePath) {
    const lineInfo =
      params.lineNumbers && params.lineNumbers.length > 0
        ? ` (lines ${params.lineNumbers.join(", ")})`
        : "";
    parts.push(`File: ${params.filePath}${lineInfo}`);
  }
  if (params.vulnSlug) {
    parts.push(`Vulnerability Type: ${params.vulnSlug}`);
  }
  if (params.ruleDescription) {
    parts.push(`Vulnerability Rule Description: ${params.ruleDescription}`);
  }
  parts.push(`Candidate Match Snippet:\n\`\`\`\n${params.snippet}\n\`\`\``);
  if (params.surroundingContext && params.surroundingContext.trim() !== params.snippet.trim()) {
    parts.push(`Surrounding Context:\n\`\`\`\n${params.surroundingContext}\n\`\`\``);
  }
  return parts.join("\n\n");
}

export function parseYesNoResult(raw: unknown): { answer?: string; confidence?: number } {
  if (typeof raw === "object" && raw !== null) {
    let answer: string | undefined;
    let confidence: number | undefined;

    if ("answer" in raw) {
      const a = (raw as Record<string, unknown>).answer;
      if (typeof a === "boolean") {
        answer = a ? "yes" : "no";
      } else if (typeof a === "string") {
        answer = a.trim().toLowerCase();
      }
    } else if ("chosen" in raw) {
      const c = (raw as Record<string, unknown>).chosen;
      if (typeof c === "string") {
        answer = c.trim().toLowerCase();
      }
    }

    if ("confidence" in raw && typeof (raw as Record<string, unknown>).confidence === "number") {
      confidence = (raw as Record<string, unknown>).confidence as number;
    }

    return { answer, confidence };
  }

  if (typeof raw === "string") {
    return { answer: raw.trim().toLowerCase(), confidence: 1.0 };
  }

  if (typeof raw === "boolean") {
    return { answer: raw ? "yes" : "no", confidence: 1.0 };
  }

  return {};
}

export interface CandidateGateDecision {
  candidate: CandidateMatch;
  filePath?: string;
  filtered: boolean;
  answer?: "yes" | "no" | string;
  confidence?: number;
  error?: string;
}

export interface FilterCandidatesParams {
  records?: FileRecord[];
  candidates?: CandidateMatch[];
  filePath?: string;
  fileContent?: string;
  rootPath?: string;
  threshold?: number;
  confidenceThreshold?: number;
  ruleDescriptions?: Record<string, string> | ((slug: string) => string | undefined);
  sageClient?: LevantoSageClient;
  batchSize?: number;
  onProgress?: (progress: { type: string; message: string }) => void;
}

export interface FilterCandidatesResult {
  records?: FileRecord[];
  candidates: CandidateMatch[];
  retainedCandidates: CandidateMatch[];
  filteredCandidates: CandidateMatch[];
  filteredCount: number;
  retainedCount: number;
  totalCandidates: number;
  decisions: CandidateGateDecision[];
}

const GATE_BATCH_SIZE = 30;

/**
 * Filter candidate matches using Levanto Sage decision model (kind: "yesno").
 * Candidates where Sage answers 'no' with confidence >= threshold are filtered out
 * as benign false positives.
 * Any answer of 'yes', low confidence (< threshold), or API/network error retains
 * the candidate (fail-open / fail-safe).
 */
export async function filterCandidatesWithSage(
  params: FilterCandidatesParams,
): Promise<FilterCandidatesResult> {
  const threshold = params.threshold ?? params.confidenceThreshold ?? DEFAULT_SAGE_GATE_CONFIDENCE;
  const sageClient = params.sageClient ?? new LevantoSageClient();

  // Helper to resolve rule description
  const resolveDescription = (slug: string): string => {
    if (typeof params.ruleDescriptions === "function") {
      const desc = params.ruleDescriptions(slug);
      if (desc) return desc;
    } else if (params.ruleDescriptions && typeof params.ruleDescriptions === "object") {
      const desc = params.ruleDescriptions[slug];
      if (desc) return desc;
    }
    return getRuleDescription(slug);
  };

  // Build items to evaluate
  interface ItemToEvaluate {
    candidate: CandidateMatch;
    filePath?: string;
    content: string;
  }

  const items: ItemToEvaluate[] = [];

  if (params.records) {
    for (const record of params.records) {
      if (!record.candidates || record.candidates.length === 0) continue;

      let fileContent: string | undefined;
      if (params.rootPath) {
        try {
          const fullPath = path.isAbsolute(record.filePath)
            ? record.filePath
            : path.join(params.rootPath, record.filePath);
          fileContent = fs.readFileSync(fullPath, "utf-8");
        } catch {
          // File not readable, surrounding context will fall back to snippet
        }
      }

      for (const candidate of record.candidates) {
        let surroundingContext: string | undefined;
        if (fileContent && candidate.lineNumbers && candidate.lineNumbers.length > 0) {
          surroundingContext = extractSurroundingLines(fileContent, candidate.lineNumbers);
        }

        const ruleDesc = resolveDescription(candidate.vulnSlug);
        const content = buildCandidateGateContent({
          snippet: candidate.snippet,
          surroundingContext: surroundingContext ?? candidate.snippet,
          ruleDescription: ruleDesc,
          vulnSlug: candidate.vulnSlug,
          filePath: record.filePath,
          lineNumbers: candidate.lineNumbers,
        });

        items.push({
          candidate,
          filePath: record.filePath,
          content,
        });
      }
    }
  } else if (params.candidates) {
    let fileContent = params.fileContent;
    if (!fileContent && params.rootPath && params.filePath) {
      try {
        const fullPath = path.isAbsolute(params.filePath)
          ? params.filePath
          : path.join(params.rootPath, params.filePath);
        fileContent = fs.readFileSync(fullPath, "utf-8");
      } catch {
        // Ignored
      }
    }

    for (const candidate of params.candidates) {
      let surroundingContext: string | undefined;
      if (fileContent && candidate.lineNumbers && candidate.lineNumbers.length > 0) {
        surroundingContext = extractSurroundingLines(fileContent, candidate.lineNumbers);
      }

      const ruleDesc = resolveDescription(candidate.vulnSlug);
      const content = buildCandidateGateContent({
        snippet: candidate.snippet,
        surroundingContext: surroundingContext ?? candidate.snippet,
        ruleDescription: ruleDesc,
        vulnSlug: candidate.vulnSlug,
        filePath: params.filePath,
        lineNumbers: candidate.lineNumbers,
      });

      items.push({
        candidate,
        filePath: params.filePath,
        content,
      });
    }
  }

  // If no candidates to evaluate, return immediately
  if (items.length === 0) {
    return {
      records: params.records,
      candidates: [],
      retainedCandidates: [],
      filteredCandidates: [],
      filteredCount: 0,
      retainedCount: 0,
      totalCandidates: 0,
      decisions: [],
    };
  }

  const decisions: CandidateGateDecision[] = [];
  const batchSize = params.batchSize ?? GATE_BATCH_SIZE;

  // Process items in chunks
  for (let i = 0; i < items.length; i += batchSize) {
    const chunk = items.slice(i, i + batchSize);

    if (typeof sageClient.decideBatch === "function") {
      try {
        const requests: SageBatchRequestGroup[] = chunk.map((item) => ({
          content: item.content,
          questions: [
            {
              id: "plausible_vulnerability",
              kind: "yesno" as const,
              instructions: SAGE_GATE_QUESTION_INSTRUCTIONS,
            },
          ],
        }));

        const batchResponse = await sageClient.decideBatch({
          requests,
        });

        for (let j = 0; j < chunk.length; j++) {
          const item = chunk[j];
          const groupResult = batchResponse?.results?.[j];
          const answer =
            groupResult?.answers?.find((a) => a.ok && a.result?.id === "plausible_vulnerability") ??
            groupResult?.answers?.[0];

          if (!answer || !answer.ok) {
            // Fail open on error in individual batch answer
            decisions.push({
              candidate: item.candidate,
              filePath: item.filePath,
              filtered: false,
              error: !answer ? "Missing answer" : answer.error,
            });
            continue;
          }

          const rawResult = (answer.result?.result ?? answer.result) as unknown;
          const { answer: ans, confidence } = parseYesNoResult(rawResult);

          const isNo = ans === "no";
          const isHighConfidence =
            typeof confidence === "number" && !Number.isNaN(confidence) && confidence >= threshold;
          const filtered = isNo && isHighConfidence;

          decisions.push({
            candidate: item.candidate,
            filePath: item.filePath,
            filtered,
            answer: ans,
            confidence,
          });
        }
      } catch (err) {
        // Network or API failure fails open (retains all candidates in chunk)
        for (const item of chunk) {
          decisions.push({
            candidate: item.candidate,
            filePath: item.filePath,
            filtered: false,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    } else if (typeof sageClient.decide === "function") {
      // Fallback for single decide API
      for (const item of chunk) {
        try {
          const question: SageYesNoQuestion = {
            id: "plausible_vulnerability",
            kind: "yesno",
            instructions: SAGE_GATE_QUESTION_INSTRUCTIONS,
          };
          const res = await sageClient.decide({
            content: item.content,
            question,
          });
          const rawResult = (res?.result ?? res) as unknown;
          const { answer: ans, confidence } = parseYesNoResult(rawResult);

          const isNo = ans === "no";
          const isHighConfidence =
            typeof confidence === "number" && !Number.isNaN(confidence) && confidence >= threshold;
          const filtered = isNo && isHighConfidence;

          decisions.push({
            candidate: item.candidate,
            filePath: item.filePath,
            filtered,
            answer: ans,
            confidence,
          });
        } catch (err) {
          decisions.push({
            candidate: item.candidate,
            filePath: item.filePath,
            filtered: false,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    } else {
      // No supported decision method on client — fail open
      for (const item of chunk) {
        decisions.push({
          candidate: item.candidate,
          filePath: item.filePath,
          filtered: false,
          error: "Sage client does not implement decideBatch or decide",
        });
      }
    }
  }

  const decisionMap = new Map<CandidateMatch, CandidateGateDecision>();
  for (const d of decisions) {
    decisionMap.set(d.candidate, d);
  }

  // If records were passed, update record.candidates in-place to exclude filtered matches
  if (params.records) {
    for (const record of params.records) {
      if (!record.candidates) continue;
      record.candidates = record.candidates.filter((c) => {
        const d = decisionMap.get(c);
        return !d || !d.filtered;
      });
    }
  }

  const filteredCount = decisions.filter((d) => d.filtered).length;
  const retainedCount = decisions.length - filteredCount;
  const retainedCandidates = decisions.filter((d) => !d.filtered).map((d) => d.candidate);
  const filteredCandidates = decisions.filter((d) => d.filtered).map((d) => d.candidate);

  if (params.onProgress) {
    params.onProgress({
      type: "sage_gate",
      message: `Filtered ${filteredCount} candidate(s) (${retainedCount} remaining of ${decisions.length})`,
    });
  }

  return {
    records: params.records,
    candidates: retainedCandidates,
    retainedCandidates,
    filteredCandidates,
    filteredCount,
    retainedCount,
    totalCandidates: decisions.length,
    decisions,
  };
}
