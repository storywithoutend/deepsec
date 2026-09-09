import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { CandidateMatch, FileRecord } from "@deepsec/core";
import { getRegistry } from "@deepsec/core";
import { createDefaultRegistry } from "@deepsec/scanner";
import {
  isRunWideSageError,
  LevantoSageClient,
  type SageBatchRequestGroup,
  type SageYesNoQuestion,
} from "./sage/index.js";

export const DEFAULT_SAGE_GATE_CONFIDENCE = 0.85;

/** Hard cap on the context window handed to Sage for one candidate. */
export const GATE_CONTEXT_LINE_LIMIT = 60;

/** Hard cap on each code block embedded in a candidate's gate content. */
export const GATE_BLOCK_CHAR_LIMIT = 4000;

export const SAGE_GATE_QUESTION_INSTRUCTIONS =
  "Is this code snippet an obvious benign false positive for the specified vulnerability? Answer yes only when the snippet clearly cannot introduce it. Answer no if the vulnerability is plausible or you are unsure.";

const GATE_QUESTION_ID = "benign_false_positive";

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
 * Extract the code around a candidate's matched lines, together with the lines
 * the extract actually covers.
 *
 * Many matchers report every hit in a file as one candidate, so a single span
 * from the first to the last match can cover the whole file. Instead each hit
 * gets its own window; overlapping windows are merged, non-contiguous ones are
 * separated by an elision marker, and the extract is bounded by both `maxLines`
 * and `maxChars` so it survives into the request unclamped. Windows start
 * minimal when there are many hits and then grow outward — up to `contextLines`
 * of padding — while budget remains. Hits that do not fit are reported back
 * through `coveredLines`, which is what tells the caller its view was partial.
 */
export function extractCandidateContext(
  content: string,
  lineNumbers: number[],
  contextLines = 10,
  maxLines = GATE_CONTEXT_LINE_LIMIT,
  maxChars = GATE_BLOCK_CHAR_LIMIT,
): { text: string; coveredLines: number[] } {
  const lines = content.split("\n");
  if (lines.length === 0) return { text: "", coveredLines: [] };
  // A record can outlive the file it was scanned from, so hits past the current
  // end of file are dropped rather than turned into inverted, budget-inflating
  // spans. They stay out of `coveredLines`, which keeps the candidate retained.
  const requestedLines = Array.from(
    new Set(lineNumbers.filter((n) => typeof n === "number" && !Number.isNaN(n) && n > 0)),
  ).sort((a, b) => a - b);
  if (requestedLines.length === 0) return { text: content.slice(0, 1000), coveredLines: [] };
  const validLines = requestedLines.filter((n) => n <= lines.length);
  // Every hit is past the end of the file: the file head is not this
  // candidate's surroundings, and labelling it as such would only mislead.
  if (validLines.length === 0) return { text: "", coveredLines: [] };

  const perHit = Math.max(1, Math.floor(maxLines / validLines.length));
  const half = Math.min(contextLines, Math.floor((perHit - 1) / 2));

  const spans: { start: number; end: number; minStart: number; maxEnd: number }[] = [];
  for (const line of validLines) {
    const start = Math.max(0, line - 1 - half);
    const end = Math.min(lines.length, line + half);
    const minStart = Math.max(0, line - 1 - contextLines);
    const maxEnd = Math.min(lines.length, line + contextLines);
    const last = spans[spans.length - 1];
    if (last && start <= last.end) {
      last.end = Math.max(last.end, end);
      last.maxEnd = Math.max(last.maxEnd, maxEnd);
    } else {
      spans.push({ start, end, minStart, maxEnd });
    }
  }

  const lineCost = (index: number) => lines[index].length + 1;
  const ELISION_COST = 2;

  let lineBudget = maxLines;
  let charBudget = maxChars;
  const emitted: { start: number; end: number; minStart: number; maxEnd: number }[] = [];
  let truncated = false;
  for (const span of spans) {
    if (emitted.length > 0) {
      if (charBudget - ELISION_COST < 0) {
        truncated = true;
        break;
      }
      charBudget -= ELISION_COST;
    }
    let end = span.start;
    while (end < span.end && lineBudget > 0 && charBudget - lineCost(end) >= 0) {
      charBudget -= lineCost(end);
      lineBudget--;
      end++;
    }
    if (end === span.start) {
      truncated = true;
      break;
    }
    emitted.push({ ...span, end });
    if (end < span.end) {
      truncated = true;
      break;
    }
  }

  // Every hit fit, so spend what is left widening the windows rather than
  // asking Sage to judge bare matched lines.
  if (!truncated) {
    let grew = true;
    while (grew && lineBudget > 0 && charBudget > 0) {
      grew = false;
      for (let i = 0; i < emitted.length; i++) {
        const span = emitted[i];
        const prev = emitted[i - 1];
        if (
          lineBudget > 0 &&
          span.start > span.minStart &&
          (!prev || span.start - 1 >= prev.end) &&
          charBudget - lineCost(span.start - 1) >= 0
        ) {
          charBudget -= lineCost(span.start - 1);
          lineBudget--;
          span.start--;
          grew = true;
        }
        const next = emitted[i + 1];
        if (
          lineBudget > 0 &&
          span.end < span.maxEnd &&
          (!next || span.end < next.start) &&
          charBudget - lineCost(span.end) >= 0
        ) {
          charBudget -= lineCost(span.end);
          lineBudget--;
          span.end++;
          grew = true;
        }
      }
    }
  }

  const blocks = emitted.map((span) => lines.slice(span.start, span.end).join("\n"));
  const text = blocks.reduce((acc, block, i) => {
    if (i === 0) return block;
    const contiguous = emitted[i].start === emitted[i - 1].end;
    return `${acc}\n${contiguous ? "" : "…\n"}${block}`;
  }, "");

  const coveredLines = validLines.filter((line) =>
    emitted.some((span) => line - 1 >= span.start && line - 1 < span.end),
  );

  return { text, coveredLines };
}

/**
 * Text-only view of {@link extractCandidateContext}.
 */
export function extractSurroundingLines(
  content: string,
  lineNumbers: number[],
  contextLines = 10,
  maxLines = GATE_CONTEXT_LINE_LIMIT,
): string {
  return extractCandidateContext(content, lineNumbers, contextLines, maxLines).text;
}

function clampBlock(text: string): string {
  return text.length <= GATE_BLOCK_CHAR_LIMIT
    ? text
    : `${text.slice(0, GATE_BLOCK_CHAR_LIMIT)}\n… (truncated)`;
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
  const snippet = clampBlock(params.snippet);
  parts.push(`Candidate Match Snippet:\n\`\`\`\n${snippet}\n\`\`\``);
  if (params.surroundingContext && params.surroundingContext.trim() !== params.snippet.trim()) {
    parts.push(`Surrounding Context:\n\`\`\`\n${clampBlock(params.surroundingContext)}\n\`\`\``);
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
    return { answer: raw.trim().toLowerCase() };
  }

  if (typeof raw === "boolean") {
    return { answer: raw ? "yes" : "no" };
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
  /**
   * Sage was never asked: the payload could not be shown to cover the
   * candidate, so any verdict would have had to be ignored anyway.
   */
  unevaluated?: boolean;
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
  /**
   * Per-file retained candidates, keyed by `FileRecord.filePath`. The gate
   * never mutates the records it was given — persisted scan results stay
   * intact — so callers use this view to decide what the agent sees.
   */
  retainedCandidatesByFile: Map<string, CandidateMatch[]>;
  filteredCount: number;
  retainedCount: number;
  totalCandidates: number;
  /** Candidates whose evaluation failed and were retained fail-open. */
  errorCount: number;
  /**
   * Candidates never sent to Sage because the gate could not build a payload
   * covering them (unreadable file, or hits the context budget could not fit).
   * They are retained, and they are not failures — but they are also not
   * evidence that Sage found nothing benign.
   */
  unevaluatedCount: number;
  /** Distinct failure messages behind `errorCount`, in first-seen order. */
  errors: string[];
  decisions: CandidateGateDecision[];
}

const GATE_BATCH_SIZE = 30;

/**
 * Filter candidate matches using Levanto Sage decision model (kind: "yesno").
 * The question is single-clause — "is this an obvious benign false positive?" —
 * so only an explicit 'yes' with confidence >= threshold filters a candidate out.
 * Any answer of 'no', an unparseable answer, a missing/low confidence, or an
 * API/network error retains the candidate (fail-open / fail-safe).
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
    /** True when the context cap kept some of the candidate's hits out of `content`. */
    partialContext: boolean;
  }

  const items: ItemToEvaluate[] = [];

  const pushItem = (
    candidate: CandidateMatch,
    filePath: string | undefined,
    fileContent: string | undefined,
  ) => {
    let surroundingContext: string | undefined;
    // No file content means the payload is the snippet alone, which cannot be
    // shown to cover the candidate's hits — such a view can only retain.
    let contextLineNumbers = fileContent ? candidate.lineNumbers : undefined;
    let partialContext = !fileContent || candidate.snippet.length > GATE_BLOCK_CHAR_LIMIT;
    if (fileContent && candidate.lineNumbers && candidate.lineNumbers.length > 0) {
      const extracted = extractCandidateContext(fileContent, candidate.lineNumbers);
      surroundingContext = extracted.text;
      contextLineNumbers = extracted.coveredLines;
      partialContext ||= extracted.coveredLines.length < new Set(candidate.lineNumbers).size;
    }

    items.push({
      candidate,
      filePath,
      content: buildCandidateGateContent({
        snippet: candidate.snippet,
        surroundingContext: surroundingContext ?? candidate.snippet,
        ruleDescription: resolveDescription(candidate.vulnSlug),
        vulnSlug: candidate.vulnSlug,
        filePath,
        lineNumbers: contextLineNumbers,
      }),
      partialContext,
    });
  };

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
          // Without the file there is no way to show Sage the candidate's hits
          // or to attest which lines the snippet covers.
        }
      }

      // The record's line numbers describe the file as scanned. If the file has
      // changed since, the code at those lines is no longer the match, so the
      // extract cannot be shown to cover the candidate either.
      if (fileContent !== undefined && record.fileHash) {
        const currentHash = crypto.createHash("sha256").update(fileContent).digest("hex");
        if (currentHash !== record.fileHash) fileContent = undefined;
      }

      for (const candidate of record.candidates) {
        pushItem(candidate, record.filePath, fileContent);
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
        // Ignored — the snippet-only path keeps the candidate.
      }
    }

    for (const candidate of params.candidates) {
      pushItem(candidate, params.filePath, fileContent);
    }
  }

  // If no candidates to evaluate, return immediately
  if (items.length === 0) {
    return {
      records: params.records,
      candidates: [],
      retainedCandidates: [],
      filteredCandidates: [],
      retainedCandidatesByFile: new Map(),
      filteredCount: 0,
      retainedCount: 0,
      totalCandidates: 0,
      errorCount: 0,
      errors: [],
      unevaluatedCount: 0,
      decisions: [],
    };
  }

  const decisions: CandidateGateDecision[] = [];
  const batchSize = params.batchSize ?? GATE_BATCH_SIZE;

  const recordVerdict = (item: ItemToEvaluate, rawResult: unknown) => {
    const { answer, confidence } = parseYesNoResult(rawResult);
    const isBenign = answer === "yes";
    const isHighConfidence =
      typeof confidence === "number" && !Number.isNaN(confidence) && confidence >= threshold;
    // A benign verdict formed from part of a candidate says nothing about the
    // hits that never left the machine, so partial coverage always retains.
    decisions.push({
      candidate: item.candidate,
      filePath: item.filePath,
      filtered: isBenign && isHighConfidence && !item.partialContext,
      answer,
      confidence,
    });
  };

  const recordFailure = (failed: ItemToEvaluate[], error: string) => {
    for (const item of failed) {
      decisions.push({
        candidate: item.candidate,
        filePath: item.filePath,
        filtered: false,
        error,
      });
    }
  };

  // A candidate whose context is already known to be partial can only be
  // retained, so asking Sage about it would buy an answer the gate is required
  // to ignore. Record the retain locally and bill only for the rest.
  const evaluable: ItemToEvaluate[] = [];
  for (const item of items) {
    if (item.partialContext) {
      decisions.push({
        candidate: item.candidate,
        filePath: item.filePath,
        filtered: false,
        unevaluated: true,
      });
    } else {
      evaluable.push(item);
    }
  }

  const unsent = items.length - evaluable.length;
  params.onProgress?.({
    type: "sage_gate",
    message: `Evaluating ${evaluable.length} candidate(s) in chunks of ${batchSize}…${
      unsent > 0 ? ` (${unsent} kept unevaluated for lack of full context)` : ""
    }`,
  });

  // A bad key or an exhausted quota fails the same way on every remaining
  // chunk. Record the failure once and fail the rest open without issuing more
  // known-doomed round trips. Request-scoped failures (a rejected or oversized
  // payload) stay chunk-local — the next chunk can still succeed.
  let permanentError: string | undefined;

  let evaluated = 0;

  // Process items in chunks
  for (let i = 0; i < evaluable.length; i += batchSize) {
    const chunk = evaluable.slice(i, i + batchSize);
    evaluated += chunk.length;

    if (permanentError) {
      recordFailure(chunk, permanentError);
      continue;
    }

    if (typeof sageClient.decideBatch === "function") {
      try {
        const requests: SageBatchRequestGroup[] = chunk.map((item) => ({
          content: item.content,
          questions: [
            {
              id: GATE_QUESTION_ID,
              kind: "yesno" as const,
              instructions: SAGE_GATE_QUESTION_INSTRUCTIONS,
            },
          ],
        }));

        const batchResponse = await sageClient.decideBatch({
          latency_mode: "fast",
          requests,
        });

        const results = batchResponse?.results;
        if (!results || results.length !== chunk.length) {
          // Group results are bound to requests by position only. A response of
          // a different length means we cannot tell which verdict belongs to
          // which candidate, and mis-binding one would silently drop a real
          // vulnerability — treat the whole chunk as unevaluated.
          recordFailure(
            chunk,
            `Batch response had ${results?.length ?? 0} result(s) for ${chunk.length} request(s)`,
          );
        } else {
          for (let j = 0; j < chunk.length; j++) {
            const item = chunk[j];
            // Each answer is decoded on its own: a malformed group must fail
            // only its own candidate, never re-record ones already decided.
            try {
              const groupResult = results[j];
              const answer =
                groupResult?.answers?.find((a) => a.ok && a.result?.id === GATE_QUESTION_ID) ??
                groupResult?.answers?.[0];

              if (!answer || !answer.ok) {
                // Fail open on error in individual batch answer
                const answerError =
                  typeof answer?.error === "string" && answer.error
                    ? answer.error
                    : "Sage returned a failed answer with no error message";
                recordFailure([item], !answer ? "Missing answer" : answerError);
                continue;
              }

              recordVerdict(item, (answer.result?.result ?? answer.result) as unknown);
            } catch (err) {
              recordFailure([item], err instanceof Error ? err.message : String(err));
            }
          }
        }
      } catch (err) {
        // Network or API failure fails open (retains all candidates in chunk)
        const message = err instanceof Error ? err.message : String(err);
        if (isRunWideSageError(err)) {
          permanentError = message;
        }
        recordFailure(chunk, message);
      }
    } else if (typeof sageClient.decide === "function") {
      // Fallback for single decide API
      for (const item of chunk) {
        if (permanentError) {
          recordFailure([item], permanentError);
          continue;
        }
        try {
          const question: SageYesNoQuestion = {
            id: GATE_QUESTION_ID,
            kind: "yesno",
            instructions: SAGE_GATE_QUESTION_INSTRUCTIONS,
          };
          const res = await sageClient.decide({
            content: item.content,
            question,
          });
          recordVerdict(item, (res?.result ?? res) as unknown);
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          if (isRunWideSageError(err)) {
            permanentError = message;
          }
          recordFailure([item], message);
        }
      }
    } else {
      // No supported decision method on client — fail open
      recordFailure(chunk, "Sage client does not implement decideBatch or decide");
    }

    params.onProgress?.({
      type: "sage_gate",
      message: `${evaluated}/${evaluable.length} candidate(s) evaluated (${decisions.filter((d) => d.filtered).length} filtered so far)`,
    });
  }

  const decisionMap = new Map<CandidateMatch, CandidateGateDecision>();
  for (const d of decisions) {
    decisionMap.set(d.candidate, d);
  }

  // The gate is advisory only: `record.candidates` is persisted scan state, so
  // filtered matches are reported per file rather than deleted from the record.
  const retainedCandidatesByFile = new Map<string, CandidateMatch[]>();
  const collectRetained = (filePath: string, candidates: CandidateMatch[]) => {
    const retained = candidates.filter((c) => {
      const d = decisionMap.get(c);
      return !d || !d.filtered;
    });
    retainedCandidatesByFile.set(filePath, retained);
  };
  if (params.records) {
    for (const record of params.records) {
      if (!record.candidates || record.candidates.length === 0) continue;
      collectRetained(record.filePath, record.candidates);
    }
  } else if (params.candidates && params.filePath) {
    collectRetained(params.filePath, params.candidates);
  }

  const errors: string[] = [];
  for (const d of decisions) {
    if (d.error && !errors.includes(d.error)) errors.push(d.error);
  }
  const errorCount = decisions.filter((d) => d.error).length;
  const unevaluatedCount = decisions.filter((d) => d.unevaluated).length;

  const filteredCount = decisions.filter((d) => d.filtered).length;
  const retainedCount = decisions.length - filteredCount;
  const retainedCandidates = decisions.filter((d) => !d.filtered).map((d) => d.candidate);
  const filteredCandidates = decisions.filter((d) => d.filtered).map((d) => d.candidate);

  return {
    records: params.records,
    candidates: retainedCandidates,
    retainedCandidates,
    filteredCandidates,
    retainedCandidatesByFile,
    filteredCount,
    retainedCount,
    totalCandidates: decisions.length,
    errorCount,
    errors,
    unevaluatedCount,
    decisions,
  };
}
