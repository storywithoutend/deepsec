import type { Severity } from "@deepsec/core";
import { readProjectConfig } from "@deepsec/core";
import { CLAUDE_DEFAULT_MODEL, SAGE_MODEL_NAME, triage } from "@deepsec/processor";
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
  latencyMode?: string;
  minConfidence?: number;
  claudeFallback?: boolean;
}) {
  const projectId = resolveProjectId(opts.projectId);
  readProjectConfig(projectId);
  const severity = (opts.severity ?? "MEDIUM") as Severity;

  if (opts.provider && opts.provider !== "claude" && opts.provider !== "sage") {
    throw new Error(`Invalid triage provider "${opts.provider}". Expected "claude" or "sage".`);
  }
  const provider: "claude" | "sage" = opts.provider === "sage" ? "sage" : "claude";

  if (opts.latencyMode && opts.latencyMode !== "quality" && opts.latencyMode !== "fast") {
    throw new Error(`Invalid latency mode "${opts.latencyMode}". Expected "quality" or "fast".`);
  }
  const latencyMode: "quality" | "fast" = opts.latencyMode === "fast" ? "fast" : "quality";

  const model = opts.model ?? (provider === "sage" ? SAGE_MODEL_NAME : CLAUDE_DEFAULT_MODEL);

  let fallbackToClaude = opts.claudeFallback !== false;

  if (provider === "sage") {
    assertSageCredential();
    // Sage routes low-confidence findings and failed batches through the Claude
    // Agent SDK, so that path needs the same model route the claude provider gets.
    if (fallbackToClaude) {
      await applyConfiguredModelRoute("claude-agent-sdk");
      try {
        assertAgentCredential("claude-agent-sdk");
      } catch (err) {
        fallbackToClaude = false;
        console.log(
          `${YELLOW}Claude fallback disabled — no Claude credentials found.${RESET}\n` +
            `  ${DIM}${err instanceof Error ? err.message.split("\n")[0] : String(err)}${RESET}`,
        );
      }
    }
  } else {
    // Triage uses Anthropic directly — no codex path here.
    await applyConfiguredModelRoute("claude-agent-sdk");
    assertAgentCredential("claude-agent-sdk");
  }

  console.log(
    `${BOLD}Triaging${RESET} ${severity} findings for project ${BOLD}${projectId}${RESET} using ${BOLD}${provider}${RESET}`,
  );
  console.log(`  Model: ${model} (lightweight — no code reading)`);
  if (provider === "sage") {
    console.log(`  Latency mode: ${latencyMode}`);
  }
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
    latencyMode,
    minConfidence: opts.minConfidence,
    fallbackToClaude,
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
