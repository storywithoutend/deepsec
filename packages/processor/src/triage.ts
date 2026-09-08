import fs from "node:fs";
import path from "node:path";
import { query } from "@anthropic-ai/claude-agent-sdk";
import type { FileRecord, Finding, Severity, TriagePriority } from "@deepsec/core";
import {
  completeRun,
  createRunMeta,
  dataDir,
  defaultConcurrency,
  loadAllFileRecords,
  readProjectConfig,
  writeFileRecord,
  writeRunMeta,
} from "@deepsec/core";
import {
  LevantoSageClient,
  type SageChoiceResult,
  type SageOption,
  type SageOptionProbability,
} from "./sage/client.js";

const TRIAGE_BATCH_SIZE = 30;

export const SAGE_MODEL_NAME = "levanto-sage-v0.8";
export const CLAUDE_DEFAULT_MODEL = "claude-sonnet-4-6";

export const SAGE_PRIORITY_OPTIONS: SageOption[] = [
  {
    option: "P0",
    description:
      "Fix immediately: Exploitable by external attackers with trivial effort. Direct impact on user data, auth bypass, or code execution. No mitigations in place.",
  },
  {
    option: "P1",
    description:
      "Fix soon: Real vulnerability but requires specific conditions (internal access, feature flag enabled, race condition). Moderate impact.",
  },
  {
    option: "P2",
    description:
      "Fix eventually: Low-impact or difficult to exploit. Defense-in-depth improvements. Code quality issues with security implications.",
  },
  {
    option: "skip",
    description:
      "Not actionable: False positive, already mitigated, test-only code, or too vague to act on.",
  },
];

export const SAGE_EXPLOITABILITY_OPTIONS: SageOption[] = [
  {
    option: "trivial",
    description: "Can be exploited with a single crafted HTTP request or URL",
  },
  {
    option: "moderate",
    description: "Requires some setup (valid auth, specific timing, internal network)",
  },
  {
    option: "difficult",
    description: "Requires deep knowledge, chained exploits, or unlikely conditions",
  },
];

export const SAGE_IMPACT_OPTIONS: SageOption[] = [
  {
    option: "critical",
    description: "Full auth bypass, RCE, data exfiltration across tenants",
  },
  {
    option: "high",
    description: "Single-tenant data access, privilege escalation, secret exposure",
  },
  {
    option: "medium",
    description: "Information disclosure, DoS, weak crypto",
  },
  {
    option: "low",
    description: "Cosmetic, theoretical, or minimal real-world impact",
  },
];

export interface TriageVerdict {
  id?: string;
  title: string;
  priority: TriagePriority;
  exploitability: "trivial" | "moderate" | "difficult";
  impact: "critical" | "high" | "medium" | "low";
  reasoning: string;
}

export interface TriageProgress {
  type: "batch_started" | "batch_complete" | "all_complete";
  message: string;
}

export interface TriageParams {
  projectId: string;
  severity?: Severity;
  force?: boolean;
  limit?: number;
  concurrency?: number;
  model?: string;
  provider?: "claude" | "sage";
  latencyMode?: "quality" | "fast";
  minConfidence?: number;
  fallbackToClaude?: boolean;
  sageClient?: LevantoSageClient;
  onProgress?: (progress: TriageProgress) => void;
}

export interface TriageResult {
  triaged: number;
  p0: number;
  p1: number;
  p2: number;
  skip: number;
}

/**
 * Format a finding into structured text content for evaluation by Sage.
 */
export function formatFindingForSage(finding: Finding, filePath?: string): string {
  const parts: string[] = [
    `Title: ${finding.title}`,
    filePath ? `File: ${filePath}` : null,
    `Severity: ${finding.severity}`,
    `Vulnerability Slug: ${finding.vulnSlug}`,
    finding.lineNumbers?.length ? `Lines: ${finding.lineNumbers.join(", ")}` : null,
    finding.confidence ? `Scanner Confidence: ${finding.confidence}` : null,
    `Description: ${finding.description}`,
    finding.recommendation ? `Recommendation: ${finding.recommendation}` : null,
  ].filter((p): p is string => Boolean(p));

  return parts.join("\n");
}

function defaultExploitability(priority: TriagePriority): "trivial" | "moderate" | "difficult" {
  switch (priority) {
    case "P0":
      return "trivial";
    case "P1":
      return "moderate";
    default:
      return "difficult";
  }
}

function isTriagePriority(value: unknown): value is TriagePriority {
  return value === "P0" || value === "P1" || value === "P2" || value === "skip";
}

function isExploitability(value: unknown): value is "trivial" | "moderate" | "difficult" {
  return value === "trivial" || value === "moderate" || value === "difficult";
}

function isImpact(value: unknown): value is "critical" | "high" | "medium" | "low" {
  return value === "critical" || value === "high" || value === "medium" || value === "low";
}

function formatSageProbabilities(probabilities: SageOptionProbability[] | undefined): string {
  if (!Array.isArray(probabilities)) return "";
  const parts = probabilities
    .filter(
      (p): p is SageOptionProbability =>
        Boolean(p) && typeof p.option === "string" && Number.isFinite(p.probability),
    )
    .map((p) => `${p.option}=${p.probability.toFixed(2)}`);
  return parts.length > 0 ? ` (${parts.join(", ")})` : "";
}

function defaultImpact(priority: TriagePriority): "critical" | "high" | "medium" | "low" {
  switch (priority) {
    case "P0":
      return "critical";
    case "P1":
      return "high";
    case "P2":
      return "medium";
    default:
      return "low";
  }
}

async function runClaudeTriageBatch(
  batch: { record: FileRecord; finding: Finding }[],
  model: string,
  projectInfo: string,
): Promise<{
  verdicts: TriageVerdict[];
  p0: number;
  p1: number;
  p2: number;
  skip: number;
  triaged: number;
}> {
  if (batch.length === 0) {
    return { verdicts: [], p0: 0, p1: 0, p2: 0, skip: 0, triaged: 0 };
  }

  const refFor = (item: { record: FileRecord; finding: Finding }, idx: number) =>
    item.finding.findingId ?? `${idx + 1}`;

  const findingsList = batch
    .map((item, idx) => {
      return `### ${idx + 1}. ${item.finding.title}
- **ID:** \`${refFor(item, idx)}\`
- **File:** \`${item.record.filePath}\`
- **Severity:** ${item.finding.severity}
- **Slug:** ${item.finding.vulnSlug}
- **Lines:** ${item.finding.lineNumbers.join(", ")}
- **Confidence:** ${item.finding.confidence}
- **Description:** ${item.finding.description}`;
    })
    .join("\n\n");

  const prompt = `You are a security triage expert. Given a list of vulnerability findings, classify each by priority for remediation.

${projectInfo ? `## Project Context (summary only)\n\n${projectInfo.slice(0, 2000)}\n` : ""}

## Findings to Triage

${findingsList}

## Classification Criteria

**P0 — Fix immediately:** Exploitable by external attackers with trivial effort. Direct impact on user data, auth bypass, or code execution. No mitigations in place.

**P1 — Fix soon:** Real vulnerability but requires specific conditions (internal access, feature flag enabled, race condition). Moderate impact.

**P2 — Fix eventually:** Low-impact or difficult to exploit. Defense-in-depth improvements. Code quality issues with security implications.

**skip — Not actionable:** False positive, already mitigated, test-only code, or too vague to act on.

## Exploitability scale
- **trivial**: Can be exploited with a single crafted HTTP request or URL
- **moderate**: Requires some setup (valid auth, specific timing, internal network)
- **difficult**: Requires deep knowledge, chained exploits, or unlikely conditions

## Impact scale
- **critical**: Full auth bypass, RCE, data exfiltration across tenants
- **high**: Single-tenant data access, privilege escalation, secret exposure
- **medium**: Information disclosure, DoS, weak crypto
- **low**: Cosmetic, theoretical, or minimal real-world impact

## Output

\`\`\`json
[
  {
    "id": "exact ID of the finding above",
    "title": "exact title",
    "priority": "P0" | "P1" | "P2" | "skip",
    "exploitability": "trivial" | "moderate" | "difficult",
    "impact": "critical" | "high" | "medium" | "low",
    "reasoning": "1-2 sentences"
  }
]
\`\`\``;

  let resultText = "";

  for await (const message of query({
    prompt,
    options: {
      allowedTools: [],
      permissionMode: "dontAsk",
      maxTurns: 1,
      model,
    },
  })) {
    const msg = message as Record<string, any>;
    if (msg.type === "result" && msg.subtype === "success") {
      resultText = msg.result;
    }
  }

  const jsonMatch = resultText.match(/```json\s*([\s\S]*?)```/);
  const jsonStr = jsonMatch ? jsonMatch[1].trim() : resultText.trim();
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {}
  const verdicts: TriageVerdict[] = Array.isArray(parsed) ? (parsed as TriageVerdict[]) : [];

  let p0 = 0;
  let p1 = 0;
  let p2 = 0;
  let skip = 0;
  let triaged = 0;

  const unmatched = new Map(batch.map((item, idx) => [refFor(item, idx), item]));

  for (const verdict of verdicts) {
    const priority = verdict?.priority;
    if (!isTriagePriority(priority)) continue;

    // Titles are only unique within a file, but a batch spans many files, so a
    // title-only match can bind two verdicts to the same finding.
    let ref = typeof verdict.id === "string" ? verdict.id : undefined;
    if (ref === undefined || !unmatched.has(ref)) {
      ref = undefined;
      for (const [candidateRef, candidate] of unmatched) {
        if (candidate.finding.title === verdict.title) {
          ref = candidateRef;
          break;
        }
      }
    }
    if (ref === undefined) continue;

    const item = unmatched.get(ref)!;
    unmatched.delete(ref);

    item.finding.triage = {
      priority,
      exploitability: isExploitability(verdict.exploitability)
        ? verdict.exploitability
        : defaultExploitability(priority),
      impact: isImpact(verdict.impact) ? verdict.impact : defaultImpact(priority),
      reasoning: typeof verdict.reasoning === "string" ? verdict.reasoning : "",
      triagedAt: new Date().toISOString(),
      model,
    };
    triaged++;
    if (priority === "P0") p0++;
    else if (priority === "P1") p1++;
    else if (priority === "P2") p2++;
    else skip++;
  }

  const dirtyRecords = new Set(batch.map((b) => b.record));
  for (const record of dirtyRecords) {
    writeFileRecord(record);
  }

  return { verdicts, p0, p1, p2, skip, triaged };
}

export async function triage(params: TriageParams): Promise<TriageResult> {
  const {
    projectId,
    severity = "MEDIUM",
    force = false,
    provider = "claude",
    latencyMode = "quality",
    minConfidence,
    fallbackToClaude = true,
  } = params;

  const model = provider === "sage" ? SAGE_MODEL_NAME : (params.model ?? CLAUDE_DEFAULT_MODEL);

  const emit = (progress: TriageProgress) => {
    try {
      params.onProgress?.(progress);
    } catch {}
  };

  const project = readProjectConfig(projectId);

  let projectInfo = "";
  try {
    projectInfo = fs.readFileSync(path.join(dataDir(projectId), "INFO.md"), "utf-8");
  } catch {}

  const startLoad = Date.now();
  emit({ type: "batch_started", message: `Loading file records for ${projectId}...` });
  const records = loadAllFileRecords(projectId);
  emit({
    type: "batch_complete",
    message: `Loaded ${records.length} records in ${((Date.now() - startLoad) / 1000).toFixed(1)}s`,
  });

  emit({ type: "batch_started", message: `Filtering ${severity} findings...` });
  const toTriage: { record: FileRecord; finding: Finding }[] = [];
  let totalFindings = 0;
  let alreadyTriaged = 0;

  for (const record of records) {
    for (const finding of record.findings) {
      if (finding.severity !== severity) continue;
      totalFindings++;
      if (!force && finding.triage) {
        alreadyTriaged++;
        continue;
      }
      toTriage.push({ record, finding });
    }
  }

  if (params.limit && toTriage.length > params.limit) {
    toTriage.splice(params.limit);
  }

  emit({
    type: "batch_complete",
    message: `${totalFindings} ${severity} findings total, ${alreadyTriaged} already triaged, ${toTriage.length} to process`,
  });

  if (toTriage.length === 0) {
    emit({ type: "all_complete", message: "No findings to triage" });
    return { triaged: 0, p0: 0, p1: 0, p2: 0, skip: 0 };
  }

  const meta = createRunMeta({
    projectId,
    rootPath: project.rootPath,
    type: "revalidate",
    processorConfig: { agentType: "triage", model, modelConfig: { provider } },
  });
  writeRunMeta(meta);

  let totalTriaged = 0;
  let p0 = 0;
  let p1 = 0;
  let p2 = 0;
  let skip = 0;
  let batchesCompleted = 0;
  let batchesInFlight = 0;
  const concurrency = params.concurrency ?? defaultConcurrency();

  const batches: (typeof toTriage)[] = [];
  for (let i = 0; i < toTriage.length; i += TRIAGE_BATCH_SIZE) {
    batches.push(toTriage.slice(i, i + TRIAGE_BATCH_SIZE));
  }

  const sageClient =
    provider === "sage" ? (params.sageClient ?? new LevantoSageClient()) : undefined;

  async function triageBatchWithSage(batch: typeof toTriage, batchIdx: number) {
    batchesInFlight++;
    emit({
      type: "batch_started",
      message: `Triaging batch ${batchIdx + 1}/${batches.length} with Levanto Sage (${batch.length} findings, ${batchesInFlight} in flight)`,
    });

    const dirtyRecords = new Set<FileRecord>();
    const lowConfidence: typeof toTriage = [];
    const undecided: typeof toTriage = [];
    const staged: {
      item: (typeof toTriage)[number];
      triage: NonNullable<Finding["triage"]>;
    }[] = [];

    let sageTriagedInBatch = 0;
    let batchP0 = 0;
    let batchP1 = 0;
    let batchP2 = 0;
    let batchSkip = 0;

    try {
      const requests = batch.map((item) => ({
        content: formatFindingForSage(item.finding, item.record.filePath),
        questions: [
          {
            id: "priority",
            kind: "choice" as const,
            instructions:
              "Classify the priority of this vulnerability finding for remediation: P0 (immediate), P1 (soon), P2 (eventually), or skip (not actionable).",
            options: SAGE_PRIORITY_OPTIONS,
          },
          {
            id: "exploitability",
            kind: "choice" as const,
            instructions:
              "Evaluate the exploitability of this vulnerability: trivial, moderate, or difficult.",
            options: SAGE_EXPLOITABILITY_OPTIONS,
          },
          {
            id: "impact",
            kind: "choice" as const,
            instructions:
              "Evaluate the security impact of this vulnerability: critical, high, medium, or low.",
            options: SAGE_IMPACT_OPTIONS,
          },
        ],
      }));

      const batchResponse = await sageClient!.decideBatch({
        latency_mode: latencyMode,
        requests,
      });

      for (let i = 0; i < batch.length; i++) {
        const item = batch[i];
        const groupResult = batchResponse.results?.[i];

        const priorityAnswer =
          groupResult?.answers?.find((a) => a.ok && a.result?.id === "priority") ??
          groupResult?.answers?.[0];
        const exploitabilityAnswer =
          groupResult?.answers?.find((a) => a.ok && a.result?.id === "exploitability") ??
          groupResult?.answers?.[1];
        const impactAnswer =
          groupResult?.answers?.find((a) => a.ok && a.result?.id === "impact") ??
          groupResult?.answers?.[2];

        if (!priorityAnswer?.ok) {
          // Priority decision failed — treat as candidate for fallback
          undecided.push(item);
          continue;
        }

        const priorityResult = priorityAnswer.result?.result as SageChoiceResult | undefined;
        const chosenPriority = priorityResult?.chosen;
        const confidence = priorityResult?.confidence;

        // Sage may echo an option Sage-side that is not one of ours; persisting it
        // would make the record unparseable on the next load, so treat it as undecided.
        if (!isTriagePriority(chosenPriority)) {
          undecided.push(item);
          continue;
        }

        const hasConfidence = typeof confidence === "number" && Number.isFinite(confidence);

        // Check calibrated confidence threshold. A missing or non-numeric confidence
        // cannot clear the floor.
        if (minConfidence !== undefined && !(hasConfidence && confidence >= minConfidence)) {
          lowConfidence.push(item);
          continue;
        }

        let exploitability: "trivial" | "moderate" | "difficult" =
          defaultExploitability(chosenPriority);
        if (exploitabilityAnswer?.ok) {
          const expChosen = (exploitabilityAnswer.result?.result as SageChoiceResult | undefined)
            ?.chosen;
          if (isExploitability(expChosen)) {
            exploitability = expChosen;
          }
        }

        let impact: "critical" | "high" | "medium" | "low" = defaultImpact(chosenPriority);
        if (impactAnswer?.ok) {
          const impChosen = (impactAnswer.result?.result as SageChoiceResult | undefined)?.chosen;
          if (isImpact(impChosen)) {
            impact = impChosen;
          }
        }

        const probStr = formatSageProbabilities(priorityResult?.probabilities);
        const confidenceStr = hasConfidence ? `${(confidence * 100).toFixed(0)}%` : "unknown";
        const reasoning = `Levanto Sage decision: ${chosenPriority} (confidence: ${confidenceStr}${probStr})`;

        staged.push({
          item,
          triage: {
            priority: chosenPriority,
            exploitability,
            impact,
            reasoning,
            triagedAt: new Date().toISOString(),
            model: SAGE_MODEL_NAME,
          },
        });
      }

      for (const { item, triage } of staged) {
        item.finding.triage = triage;
        dirtyRecords.add(item.record);

        sageTriagedInBatch++;
        if (triage.priority === "P0") batchP0++;
        else if (triage.priority === "P1") batchP1++;
        else if (triage.priority === "P2") batchP2++;
        else batchSkip++;
      }

      for (const record of dirtyRecords) {
        writeFileRecord(record);
      }
    } catch (err) {
      // Sage failed before any verdict was committed — the whole batch is still
      // untriaged, so it can be retried in full without double counting.
      if (fallbackToClaude) {
        emit({
          type: "batch_started",
          message: `Sage triage batch ${batchIdx + 1} failed (${err instanceof Error ? err.message : String(err)}); falling back entire batch to Claude...`,
        });

        try {
          const claudeResult = await runClaudeTriageBatch(batch, CLAUDE_DEFAULT_MODEL, projectInfo);
          totalTriaged += claudeResult.triaged;
          p0 += claudeResult.p0;
          p1 += claudeResult.p1;
          p2 += claudeResult.p2;
          skip += claudeResult.skip;

          batchesInFlight--;
          batchesCompleted++;
          emit({
            type: "batch_complete",
            message: `Batch ${batchIdx + 1}/${batches.length} (Claude fallback): ${claudeResult.triaged} triaged (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
          });
          return;
        } catch (fallbackErr) {
          emit({
            type: "batch_complete",
            message: `Claude fallback also failed for batch ${batchIdx + 1}: ${fallbackErr instanceof Error ? fallbackErr.message : String(fallbackErr)}`,
          });
        }
      }

      batchesInFlight--;
      batchesCompleted++;
      emit({
        type: "batch_complete",
        message: `Batch ${batchIdx + 1}/${batches.length} failed: ${err instanceof Error ? err.message : String(err)} (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
      });
      return;
    }

    totalTriaged += sageTriagedInBatch;
    p0 += batchP0;
    p1 += batchP1;
    p2 += batchP2;
    skip += batchSkip;

    const fallbackItems = [...lowConfidence, ...undecided];
    let fallbackNote = "";

    if (fallbackItems.length > 0) {
      const reasons = [
        lowConfidence.length > 0
          ? `${lowConfidence.length} below confidence ${minConfidence}`
          : null,
        undecided.length > 0 ? `${undecided.length} without a usable Sage decision` : null,
      ]
        .filter((r): r is string => r !== null)
        .join(", ");

      if (fallbackToClaude) {
        emit({
          type: "batch_started",
          message: `Batch ${batchIdx + 1}/${batches.length}: falling back ${fallbackItems.length} finding(s) to Claude (${reasons})...`,
        });

        try {
          const claudeResult = await runClaudeTriageBatch(
            fallbackItems,
            CLAUDE_DEFAULT_MODEL,
            projectInfo,
          );
          totalTriaged += claudeResult.triaged;
          p0 += claudeResult.p0;
          p1 += claudeResult.p1;
          p2 += claudeResult.p2;
          skip += claudeResult.skip;
          fallbackNote = `, ${claudeResult.triaged}/${fallbackItems.length} fell back to Claude`;
        } catch (fallbackErr) {
          fallbackNote = `, ${fallbackItems.length} left untriaged (Claude fallback failed)`;
          emit({
            type: "batch_complete",
            message: `Claude fallback failed for ${fallbackItems.length} finding(s): ${fallbackErr instanceof Error ? fallbackErr.message : String(fallbackErr)}`,
          });
        }
      } else {
        fallbackNote = `, ${fallbackItems.length} left untriaged (${reasons}; Claude fallback disabled)`;
      }
    }

    batchesInFlight--;
    batchesCompleted++;
    emit({
      type: "batch_complete",
      message: `Batch ${batchIdx + 1}/${batches.length}: ${sageTriagedInBatch} triaged by Sage (P0:${batchP0} P1:${batchP1} P2:${batchP2} skip:${batchSkip})${fallbackNote} (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
    });
  }

  async function triageBatchWithClaude(batch: typeof toTriage, batchIdx: number) {
    batchesInFlight++;
    emit({
      type: "batch_started",
      message: `Triaging batch ${batchIdx + 1}/${batches.length} with Claude (${batch.length} findings, ${batchesInFlight} in flight)`,
    });

    try {
      const claudeResult = await runClaudeTriageBatch(batch, model, projectInfo);
      totalTriaged += claudeResult.triaged;
      p0 += claudeResult.p0;
      p1 += claudeResult.p1;
      p2 += claudeResult.p2;
      skip += claudeResult.skip;

      batchesInFlight--;
      batchesCompleted++;
      emit({
        type: "batch_complete",
        message: `Batch ${batchIdx + 1}/${batches.length}: ${claudeResult.triaged} triaged (P0:${claudeResult.p0} P1:${claudeResult.p1} P2:${claudeResult.p2} skip:${claudeResult.skip}) (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
      });
    } catch (err) {
      batchesInFlight--;
      batchesCompleted++;
      emit({
        type: "batch_complete",
        message: `Batch ${batchIdx + 1}/${batches.length} failed: ${err instanceof Error ? err.message : String(err)} (${batchesInFlight} in flight, ${batchesCompleted}/${batches.length} done)`,
      });
    }
  }

  const batchRunner = provider === "sage" ? triageBatchWithSage : triageBatchWithClaude;

  if (concurrency <= 1) {
    for (let i = 0; i < batches.length; i++) {
      await batchRunner(batches[i], i);
    }
  } else {
    let nextIdx = 0;
    async function worker() {
      while (nextIdx < batches.length) {
        const idx = nextIdx++;
        await batchRunner(batches[idx], idx);
      }
    }
    await Promise.all(
      Array.from({ length: Math.min(concurrency, batches.length) }, () => worker()),
    );
  }

  completeRun(projectId, meta.runId, "done", {
    findingsRevalidated: totalTriaged,
  });

  emit({
    type: "all_complete",
    message: `Triage complete: ${totalTriaged} findings — P0:${p0} P1:${p1} P2:${p2} skip:${skip}`,
  });

  return { triaged: totalTriaged, p0, p1, p2, skip };
}
