import type { Severity } from "@deepsec/core";
import { readProjectConfig } from "@deepsec/core";
import { triage } from "@deepsec/processor";
import { BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW } from "../formatters.js";
import {
  applyConfiguredModelRoute,
  assertAgentCredential,
  assertSageCredential,
} from "../preflight.js";
import { resolveProjectId } from "../resolve-project-id.js";

export async function triageCommand(opts: {
  projectId?: string;
  severity?: string;
  force?: boolean;
  limit?: number;
  concurrency?: number;
  model?: string;
  provider?: string;
  minConfidence?: number;
}) {
  const projectId = resolveProjectId(opts.projectId);
  readProjectConfig(projectId);
  const severity = (opts.severity ?? "MEDIUM") as Severity;

  const hasSageKey = Boolean(process.env.SAGE_API_KEY || process.env.LEVANTO_API_KEY);
  let provider: "claude" | "sage";
  if (opts.provider) {
    if (opts.provider !== "claude" && opts.provider !== "sage") {
      throw new Error(`Invalid triage provider "${opts.provider}". Expected "claude" or "sage".`);
    }
    provider = opts.provider;
  } else {
    provider = hasSageKey ? "sage" : "claude";
  }

  const model = opts.model ?? (provider === "sage" ? "levanto-sage-v0.8" : "claude-sonnet-4-6");

  if (provider === "sage") {
    assertSageCredential();
  } else {
    // Triage uses Anthropic directly — no codex path here.
    await applyConfiguredModelRoute("claude-agent-sdk");
    assertAgentCredential("claude-agent-sdk");
  }

  console.log(
    `${BOLD}Triaging${RESET} ${severity} findings for project ${BOLD}${projectId}${RESET} using ${BOLD}${provider}${RESET}`,
  );
  console.log(`  Model: ${model} (lightweight — no code reading)`);
  if (opts.minConfidence !== undefined) {
    console.log(`  Min confidence: ${opts.minConfidence}`);
  }
  if (opts.force) console.log(`  ${YELLOW}Force re-triaging already-triaged findings${RESET}`);
  console.log();

  const result = await triage({
    projectId,
    severity,
    force: opts.force,
    limit: opts.limit,
    concurrency: opts.concurrency,
    model,
    provider,
    minConfidence: opts.minConfidence,
    onProgress(progress) {
      switch (progress.type) {
        case "batch_started":
          console.log(`${BOLD}${progress.message}${RESET}`);
          break;
        case "batch_complete":
          console.log(`  ${DIM}${progress.message}${RESET}`);
          break;
        case "all_complete":
          console.log(`\n${DIM}${progress.message}${RESET}`);
          break;
      }
    },
  });

  console.log();
  console.log(`${GREEN}Triage complete.${RESET}`);
  console.log(
    `  ${RED}P0: ${result.p0}${RESET}  ${YELLOW}P1: ${result.p1}${RESET}  ${CYAN}P2: ${result.p2}${RESET}  ${DIM}skip: ${result.skip}${RESET}`,
  );
}
