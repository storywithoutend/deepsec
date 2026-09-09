---
title: "Models"
description: "Choose Codex, Claude, or Pi for process and revalidate runs, choose Claude or Levanto Sage for triage, and compare models under the same workload."
---

deepsec talks to LLMs through interchangeable agent backends:

| Backend                     | Default model         | Used by                      |
|-----------------------------|-----------------------|------------------------------|
| `codex` (default)           | `gpt-5.5`             | `process`, `revalidate`      |
| `claude`                    | `claude-opus-4-8`     | `process`, `revalidate`      |
| `pi`                        | `zai/glm-5.2`        | `process`, `revalidate` |
| `claude` (triage)           | `claude-sonnet-4-6`   | `triage` (default)           |
| `sage` (triage)             | `levanto-sage-v0.8`   | `triage --sage`              |

Interactive one-shot setup recommends five benchmark-backed combinations:
GPT-5.6 Sol, Claude Opus 5, Kimi K3, Grok 4.5, and the current DeepSeek entry.
Deepsec fetches the latest score, reasoning level, harness, and total run cost
from [DeepSecBench](https://vercel.com/ai-gateway/leaderboards/deepsecbench/results.json),
then displays cost relative to the cheapest recommendation. A bundled snapshot
keeps onboarding usable offline and is visibly marked as cached. You can also
paste any custom model slug.

Choose the backend/model non-interactively so repository analysis and the
first processing pass use the same pair:

```bash
npx deepsec init --agent codex --model gpt-5.5
```

For benchmark-backed headless selection, use a profile:

| Profile | Selection rule |
|---|---|
| `best` | Highest compatible DeepSecBench score |
| `value` | Highest score whose run cost is at most 2.5× the cheapest recommendation |
| `budget` | Cheapest compatible recommended combination |

```bash
npx deepsec init --yes --model-profile value --output jsonl
```

Direct OpenAI and Anthropic credentials automatically restrict profiles to a
compatible Codex or Claude harness; custom routes restrict them to Pi.

The built-in backends work with Vercel AI Gateway through the linked
workspace's OIDC credential. The model credential route is independent of the
Vercel/Sandbox project link and is persisted as non-secret `ai` config. Direct
OpenAI/Anthropic and custom Pi routes are documented in
[vercel-setup](vercel-setup.md).

There is also a `local` route (`--model-auth local`, or "Use local
subscriptions" in the interactive prompt) for machines where the `claude` or
`codex` CLI is already logged in. It configures no credential at all and
disables the env-var preflight checks — the machine-wide login is used
directly. Sandbox commands are the exception: they must broker a real token,
so they still require `AI_GATEWAY_API_KEY` (or an equivalent key).

## CLI selection

```bash
# Codex (default backend), default model:
pnpm deepsec process --project-id my-app

# Claude with a specific model:
pnpm deepsec process --project-id my-app --agent claude --model claude-sonnet-4-6

# Codex backend, default model:
pnpm deepsec process --project-id my-app --agent codex

# Codex backend, specific model:
pnpm deepsec process --project-id my-app --agent codex --model gpt-5.4

# Pi backend through Vercel AI Gateway, default model:
pnpm deepsec process --project-id my-app --agent pi

# Pi with an AI SDK / AI Gateway style model id:
pnpm deepsec process --project-id my-app --agent pi --model zai/glm-5.2

# Triage on Claude (default); pass a cheaper model if you want:
pnpm deepsec triage --project-id my-app --model claude-haiku-4-5

# Triage on the Levanto Sage decision model:
pnpm deepsec triage --project-id my-app --sage
```

`--agent`, `--model`, and `--thinking-level` are also accepted on `setup` and
`revalidate`. Setup persists the interactive choice as `defaultAgent`,
`defaultModel`, and `defaultThinkingLevel`, checkpoints the exact combination,
and invalidates affected phases when it changes.

## Triage providers

`triage` buckets findings into P0/P1/P2/skip without re-reading the code,
and runs on one of two providers:

- `--provider claude` (default) — the Claude Agent SDK on
  `claude-sonnet-4-6`, or any model you pass with `--model`.
- `--provider sage` — the [Levanto Sage](https://levanto.ai) decision
  model, which classifies a finding in ~100ms and returns a calibrated
  confidence score. `--sage` is the shorthand for
  `--provider sage --model levanto-sage-v0.8`. Sage exposes exactly one
  model, so `--model` on this provider accepts no other value.

These flags apply to the sage provider only; the claude provider rejects
them rather than reporting a setting that does nothing:

| Flag | Effect |
|---|---|
| `--latency-mode <quality\|fast>` | Sage speed/quality dial. Default: `quality`. |
| `--min-confidence <0-1>` | Re-triage any Sage decision below this confidence with Claude. |
| `--no-claude-fallback` | Never re-triage with Claude; low-confidence, undecided, and failed findings are left untriaged instead. |

Each finding records the model that actually decided it, so a run with a
confidence floor writes a mix of `levanto-sage-v0.8` and
`claude-sonnet-4-6`; the confidence Sage reported is persisted on the
finding (see [data-layout](data-layout.md)). Sage triage needs
`SAGE_API_KEY` or `LEVANTO_API_KEY` (see
[configuration](configuration.md)), and that check is not skipped by the
local-subscription route. If the Claude fallback is enabled but no Claude
credential is available, deepsec warns and disables the fallback instead
of failing. A non-retryable Sage error — bad key, exhausted quota, a
rejected request — aborts the run rather than silently redirecting the
whole corpus to Claude.

## Sage candidate gate

`process --sage-gate` puts the same Levanto Sage decision model in front
of the coding agent: every scanner candidate is sent to Sage in `fast`
latency mode with its snippet, surrounding context, and the matcher's
rule description, and Sage answers one question — is this an obvious
benign false positive? Candidates it calls benign are hidden from the
agent's prompt, and a file left with no candidates is skipped entirely
instead of being handed to the agent for an open-ended review.

| Flag | Effect |
|---|---|
| `--sage-gate` | Filter obvious benign scanner candidates with Sage before agent runs. |
| `--sage-gate-confidence <0-1>` | Confidence a "benign" answer needs before a candidate is dropped. Default: `0.85`. Requires `--sage-gate`. |

The gate is fail-open and non-destructive. Anything other than a
confident benign verdict — a plausible-vulnerability answer, a missing or
below-threshold confidence, an unparseable answer, or an API error —
keeps the candidate, and the gate never deletes candidates from the file
record on disk. Candidates the gate could not evaluate are reported as
`Sage gate errors` in the run summary so a gate that silently never ran
doesn't read as "nothing was benign". `--sage-gate` needs `SAGE_API_KEY`
or `LEVANTO_API_KEY`, same as Sage triage.

What that means across runs depends on whether the gate cleared the whole
file:

- **Every candidate filtered** — the file is never handed to the agent
  and keeps whatever status it had before the run. A file that was
  pending stays pending, so it remains in the default work set: a later
  plain `process` investigates it normally, and a later `--sage-gate` run
  re-sends it to Sage and skips it again (a small repeated Sage cost,
  never an agent cost) rather than recording the verdict as decided. A
  file that was already `analyzed` — only reachable in force mode, via
  `--reinvestigate` or `process --files` — stays `analyzed`, so it keeps
  counting in `report` and `metrics` and needs `--reinvestigate` to be
  looked at again.
- **Some candidates filtered** — the agent investigates the rest and the
  file ends the run `analyzed`, which takes it out of the default work
  set. The filtered candidates are still on the record, but no later run
  picks them up on its own; use `--reinvestigate` to look at them again.

## Thinking level

`process` and `revalidate` accept `--thinking-level` to control how much
reasoning effort the agent spends per batch:

```bash
pnpm deepsec process --project-id my-app --thinking-level high
```

Accepted values: `minimal`, `low`, `medium`, `high`, `xhigh`. The
default is `xhigh`. Deepsec optimizes for finding hard bugs, not for
cost. Dial down for cheaper reinvestigation waves or quick smoke runs
over large repos.

The flag maps onto each backend's native dial:

| Backend  | Setting                                     |
|----------|---------------------------------------------|
| `codex`  | model reasoning effort (`minimal`–`xhigh`)  |
| `pi`     | thinking level (`minimal`–`xhigh`)          |
| `claude` | adaptive-thinking effort (`minimal` → `low`, `xhigh` → `max`) |

It applies to the main investigation/revalidation runs only.
Special-purpose follow-up calls (the refusal report, JSON repair) keep
their own fixed, cheap settings regardless of the flag.

Like other subcommand flags, it passes through sandbox mode unchanged:

```bash
pnpm deepsec sandbox process --project-id my-app --sandboxes 30 --thinking-level high
```

## Why these defaults

### `claude-opus-4-8` for `process` and `revalidate`

Investigating a candidate site is a multi-step reasoning task: trace
control flow, recognize an auth boundary, decide whether input is
attacker-controlled, judge severity. Stronger reasoning models pay for
themselves in lower FP rate, even at higher per-call cost. Opus is the
strongest of the Claude family at this kind of code reasoning.

If cost matters more than precision (a 10k-file repo, a quick triaged
starter list), drop to `claude-sonnet-4-6`. Same prompt, ~3× cheaper,
~10–20% higher FP rate.

### `gpt-5.5` for the Codex backend

Codex is the OpenAI-flavored agent loop: grep-heavy, fast, runs in a
strict read-only sandbox. `gpt-5.5` is the right balance of reasoning
and cost for that loop. `gpt-5.5-pro` is the most careful Codex
option at significantly higher cost; `gpt-5.4` and below are fine for
follow-up reinvestigation passes.

### Pi for alternate harness runs

Pi uses `@earendil-works/pi-coding-agent` with read-only tools
(`read`, `grep`, `find`, `ls`) and the same deepsec prompt/schema as the
other backends. Its default model is GLM 5.2 through Vercel AI Gateway:

```bash
AI_GATEWAY_API_KEY=vck_...
pnpm deepsec process --project-id my-app --agent pi
```

Normal setup pulls and uses the exact linked workspace's OIDC credential.

For OpenAI-compatible gateways such as Martian, select and persist a custom
route during setup:

```bash
MARTIAN_API_KEY=...
pnpm deepsec setup --project-id my-app \
  --agent pi \
  --model openai/gpt-5.5 \
  --model-auth custom \
  --ai-provider martian \
  --ai-base-url https://api.withmartian.com/v1 \
  --ai-api-key-env MARTIAN_API_KEY \
  --ai-credential-header authorization:bearer
```

Later `process`, `revalidate`, and Sandbox commands resolve the persisted
route. Per-command `--ai-provider`, `--ai-base-url`, `--ai-api-key-env`, and
repeatable `--ai-header name=value` remain available as Pi runtime overrides.

### `claude-sonnet-4-6` for `triage`

Triage just looks at the finding text, never the code. That's a cheap
task; Opus is overkill. Sonnet keeps `triage` at ~1¢/finding. For a
faster, confidence-scored alternative, see
[Triage providers](#triage-providers).

## Refusals

Models occasionally refuse to investigate a candidate — usually when the
source contains an exploit pattern they read as harmful, or when a path
trips a content filter. After every batch, deepsec issues a follow-up
turn asking the agent whether it skipped or declined anything:

> Looking back at the investigation: was there anything you declined
> to fully analyze, refused to look at, or skipped because the content
> or the task felt uncomfortable or out of scope?

The agent answers in a structured JSON shape (see `parseRefusalReport`
in `packages/processor/src/agents/shared.ts`). If `refused: true`, the
batch gets a `refusal` record in run metadata, the per-batch log line
shows a ⚠️ `refusal` marker, and the `refusal` field on the FileRecord
sticks around for audit. No silent skips.

Claude Opus and `gpt-5.5` refuse less than 1% of batches in practice. A
refused batch produces no false negatives — affected files stay
`pending` (revalidation keeps the original verdict), so re-running
`--reinvestigate` against the other backend picks up the dropped sites.
Findings dedupe across agents, so you don't pay twice.

If a single file consistently triggers a refusal (>5% of batches), it's
usually one path with a hard-to-disambiguate exploit pattern. Add it to
`config.json:ignorePaths`, or run that file alone with `--batch-size 1`
so the refusal doesn't take a batch of otherwise-fine files down with
it.

## Future models (e.g. Anthropic Mythos)

The model is a flag, not a baked-in choice. When a stronger reasoning
model lands — Anthropic's Mythos, a next-tier OpenAI release, an
open-weight contender — point `--model` at the new identifier and the
rest of deepsec stays unchanged:

```bash
pnpm deepsec process --project-id my-app --model anthropic-mythos-1
pnpm deepsec process --project-id my-app --agent codex --model gpt-6
pnpm deepsec process --project-id my-app --agent pi --model vercel-ai-gateway/openai/gpt-6
```

Two small integration points:

1. **The model identifier** — whatever string the provider's SDK
   accepts. deepsec passes it through unchanged. No code change needed
   to *use* a new model on either backend.
2. **Pricing for the cost-per-batch readout.** The Claude Agent SDK
   reports cost natively, so new Claude-family models drop in with
   zero code changes. Codex doesn't, so add a line to
   `MODEL_PRICING_USD_PER_M_TOKENS` in
   `packages/processor/src/agents/codex-sdk.ts` for each new
   OpenAI/Codex model. Without it, the batch still runs — the cost
   readout is simply omitted.

When a new model becomes the right default, change the relevant entry
in `packages/deepsec/src/agent-defaults.ts` (one string per backend) and
the `DEFAULT_MODEL` constant in the corresponding agent file. Existing
data and findings are unaffected — deepsec records which agent + model
produced each finding, so a model change shows up cleanly in the
`analysisHistory` of any re-investigated file.

A useful pattern when a new model lands: re-run `process` with
`--reinvestigate <N>` (a wave marker) against the existing
high-severity findings to see whether the new model overturns
verdicts. The wave marker tags the new analysis without losing the
old one.
