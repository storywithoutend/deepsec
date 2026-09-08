/**
 * Levanto Sage API Client
 *
 * Zero-dependency HTTP client for the Levanto Sage decision model API (https://sage.levanto.ai).
 * Provides structured, calibrated decision-making (choice, yes/no, scale, sort, tags)
 * for fast operations and security triage.
 */

export class LevantoSageError extends Error {
  readonly status?: number;
  readonly code?: string;
  readonly detail?: unknown;

  constructor(
    message: string,
    options?: { status?: number; code?: string; detail?: unknown; cause?: unknown },
  ) {
    super(message, { cause: options?.cause });
    this.name = "LevantoSageError";
    this.status = options?.status;
    this.code = options?.code;
    this.detail = options?.detail;
  }
}

export class LevantoSageAuthError extends LevantoSageError {
  constructor(
    message = "API key required or invalid. Provide a valid Levanto API key.",
    options?: { status?: number; detail?: unknown; cause?: unknown },
  ) {
    super(message, { ...options, code: "AUTH_ERROR", status: options?.status ?? 401 });
    this.name = "LevantoSageAuthError";
  }
}

export class LevantoSageValidationError extends LevantoSageError {
  constructor(message: string, options?: { status?: number; detail?: unknown; cause?: unknown }) {
    super(message, { ...options, code: "VALIDATION_ERROR", status: options?.status ?? 400 });
    this.name = "LevantoSageValidationError";
  }
}

export class LevantoSageQuotaError extends LevantoSageError {
  constructor(message: string, options?: { status?: number; detail?: unknown; cause?: unknown }) {
    super(message, { ...options, code: "QUOTA_EXHAUSTED", status: options?.status ?? 402 });
    this.name = "LevantoSageQuotaError";
  }
}

export class LevantoSageServerError extends LevantoSageError {
  constructor(message: string, options?: { status?: number; detail?: unknown; cause?: unknown }) {
    super(message, { ...options, code: "SERVER_ERROR", status: options?.status ?? 500 });
    this.name = "LevantoSageServerError";
  }
}

export class LevantoSageRateLimitError extends LevantoSageError {
  /** Milliseconds the server asked the caller to wait, when it sent Retry-After. */
  readonly retryAfterMs?: number;

  constructor(
    message: string,
    options?: {
      status?: number;
      detail?: unknown;
      cause?: unknown;
      retryAfterMs?: number;
    },
  ) {
    super(message, { ...options, code: "RATE_LIMITED", status: options?.status ?? 429 });
    this.name = "LevantoSageRateLimitError";
    this.retryAfterMs = options?.retryAfterMs;
  }
}

export interface SageOption {
  option: string;
  description?: string;
}

export interface SageChoiceQuestion {
  id?: string;
  kind: "choice";
  instructions?: string;
  options: SageOption[];
}

export interface SageYesNoQuestion {
  id?: string;
  kind: "yesno";
  instructions: string;
}

export interface SageScaleLevel {
  level: 0 | 1 | 2 | 3 | 4;
  description: string;
}

export interface SageScaleQuestion {
  id?: string;
  kind: "scale";
  instructions: string;
  levels: SageScaleLevel[];
}

export interface SageSortQuestion {
  id?: string;
  kind: "sort";
  instructions: string;
}

export interface SageTagItem {
  id: string;
  threshold?: number;
}

export interface SageTagsQuestion {
  id?: string;
  kind: "tags";
  tags: SageTagItem[];
}

export type SageQuestion =
  | SageChoiceQuestion
  | SageYesNoQuestion
  | SageScaleQuestion
  | SageSortQuestion
  | SageTagsQuestion;

export interface SageDecideRequest {
  content: string | { kind: string; value: unknown };
  question: SageQuestion;
  grounding?: {
    trigger?: "never" | "low_confidence" | "always";
    confidence_floor?: number;
  };
}

export interface SageOptionProbability {
  option: string;
  probability: number;
}

export interface SageChoiceResult {
  chosen: string;
  confidence: number;
  probabilities: SageOptionProbability[];
}

export interface SageDecideResponse<T = unknown> {
  id?: string;
  kind: string;
  result: T;
  meta?: {
    model?: string;
    latency_ms?: number;
    [key: string]: unknown;
  };
}

export interface SageChoiceDecision {
  chosen: string;
  confidence: number;
  probabilities: SageOptionProbability[];
  latency_ms: number;
  id?: string;
  model?: string;
}

export interface SageChoiceParams {
  content: string;
  options: Array<SageOption | string>;
  instructions?: string;
  id?: string;
}

export interface SageBatchRequestGroup {
  content: string | { kind: string; value: unknown };
  questions: SageQuestion[];
}

export interface SageBatchRequest {
  latency_mode?: "quality" | "fast";
  requests: SageBatchRequestGroup[];
}

export interface SageBatchAnswerSuccess<T = unknown> {
  ok: true;
  result: SageDecideResponse<T>;
}

export interface SageBatchAnswerError {
  ok: false;
  error: string;
}

export type SageBatchAnswer<T = unknown> = SageBatchAnswerSuccess<T> | SageBatchAnswerError;

export interface SageBatchGroupResult {
  answers: SageBatchAnswer[];
}

export interface SageBatchResponse {
  results: SageBatchGroupResult[];
  meta: {
    model?: string;
    request_count?: number;
    question_count?: number;
    latency_ms?: number;
    [key: string]: unknown;
  };
}

/** Max wait honored from a Retry-After header, so a hostile value cannot stall a run. */
const MAX_RETRY_AFTER_MS = 30_000;

function parseRetryAfterMs(header: string | null): number | undefined {
  if (!header) return undefined;
  const seconds = Number(header.trim());
  if (Number.isFinite(seconds)) {
    return Math.min(Math.max(seconds, 0) * 1000, MAX_RETRY_AFTER_MS);
  }
  const at = Date.parse(header);
  if (Number.isNaN(at)) return undefined;
  return Math.min(Math.max(at - Date.now(), 0), MAX_RETRY_AFTER_MS);
}

function isRetryable(err: unknown): err is LevantoSageServerError | LevantoSageRateLimitError {
  return err instanceof LevantoSageServerError || err instanceof LevantoSageRateLimitError;
}

export interface LevantoSageClientOptions {
  apiKey?: string;
  baseUrl?: string;
  timeoutMs?: number;
  maxRetries?: number;
  fetch?: typeof fetch;
}

export class LevantoSageClient {
  private readonly apiKey?: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly fetchFn: typeof fetch;

  constructor(options?: LevantoSageClientOptions) {
    this.apiKey = options?.apiKey || process.env.SAGE_API_KEY || process.env.LEVANTO_API_KEY;
    this.baseUrl = (options?.baseUrl ?? "https://sage.levanto.ai").replace(/\/+$/, "");
    this.timeoutMs = options?.timeoutMs ?? 30000;
    this.maxRetries = options?.maxRetries ?? 2;
    this.fetchFn = options?.fetch ?? globalThis.fetch;
  }

  private resolveApiKey(): string {
    const key = this.apiKey || process.env.SAGE_API_KEY || process.env.LEVANTO_API_KEY;
    if (!key) {
      throw new LevantoSageAuthError(
        "Missing Levanto Sage API key. Set SAGE_API_KEY or LEVANTO_API_KEY in the environment or pass apiKey in options.",
      );
    }
    return key;
  }

  private async backoff(attempt: number, retryAfterMs?: number): Promise<void> {
    const ms =
      retryAfterMs !== undefined && Number.isFinite(retryAfterMs)
        ? retryAfterMs
        : Math.min(1000, 50 * 2 ** (attempt - 1));
    await new Promise((resolve) => setTimeout(resolve, ms));
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const key = this.resolveApiKey();
    const url = `${this.baseUrl}/${path.replace(/^\/+/, "")}`;
    const maxAttempts = Math.max(1, this.maxRetries + 1);
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const response = await this.fetchFn(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${key}`,
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(this.timeoutMs),
        });

        if (response.ok) {
          return (await response.json()) as T;
        }

        const status = response.status;
        let errorBody: any = null;
        let errorText = "";
        try {
          errorText = await response.text();
          errorBody = JSON.parse(errorText);
        } catch {
          // Response body was not JSON
        }

        const detail = errorBody?.detail ?? errorBody?.message ?? errorText;

        if (status === 400) {
          throw new LevantoSageValidationError(
            `Levanto Sage validation error (HTTP 400): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
            { status, detail },
          );
        }

        if (status === 401 || status === 403) {
          throw new LevantoSageAuthError(
            `Levanto Sage authentication error (HTTP ${status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
            { status, detail },
          );
        }

        if (status === 402) {
          throw new LevantoSageQuotaError(
            `Levanto Sage quota exhausted (HTTP 402): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
            { status, detail },
          );
        }

        if (status === 429) {
          const retryAfterMs = parseRetryAfterMs(response.headers.get("retry-after"));
          const rateLimitError = new LevantoSageRateLimitError(
            `Levanto Sage rate limited (HTTP 429): ${typeof detail === "string" ? detail : errorText}`,
            { status, detail, retryAfterMs },
          );
          if (attempt < maxAttempts) {
            lastError = rateLimitError;
            await this.backoff(attempt, retryAfterMs);
            continue;
          }
          throw rateLimitError;
        }

        const isTransient = status >= 500 && status <= 599;
        if (isTransient) {
          const serverError = new LevantoSageServerError(
            `Levanto Sage server error (HTTP ${status}): ${typeof detail === "string" ? detail : errorText}`,
            { status, detail },
          );
          if (attempt < maxAttempts) {
            lastError = serverError;
            await this.backoff(attempt);
            continue;
          }
          throw serverError;
        }

        throw new LevantoSageError(
          `Levanto Sage request failed (HTTP ${status}): ${typeof detail === "string" ? detail : errorText}`,
          { status, detail },
        );
      } catch (err) {
        // Only 5xx, 429 and network/timeout failures are worth another round trip;
        // every other Sage error (400/401/402/403 and any other non-2xx status) is
        // deterministic and surfaces immediately.
        if (err instanceof LevantoSageError && !isRetryable(err)) {
          throw err;
        }
        if (isRetryable(err) && attempt >= maxAttempts) {
          throw err;
        }

        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < maxAttempts) {
          await this.backoff(
            attempt,
            err instanceof LevantoSageRateLimitError ? err.retryAfterMs : undefined,
          );
          continue;
        }

        if (err instanceof LevantoSageError) {
          throw err;
        }

        throw new LevantoSageServerError(
          `Levanto Sage request failed after ${maxAttempts} attempt(s): ${lastError.message}`,
          { cause: lastError },
        );
      }
    }

    throw lastError ?? new LevantoSageServerError("Levanto Sage request failed.");
  }

  /**
   * Check if the Sage service is ready (GET /ready, requires no auth).
   * Returns true on HTTP 200, false on 503 or error.
   */
  async isReady(): Promise<boolean> {
    try {
      const res = await this.fetchFn(`${this.baseUrl}/ready`, {
        method: "GET",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      return res.status === 200;
    } catch {
      return false;
    }
  }

  /**
   * Submit a single decision request to /decide.
   */
  async decide<T = unknown>(request: SageDecideRequest): Promise<SageDecideResponse<T>> {
    return this.post<SageDecideResponse<T>>("/decide", request);
  }

  /**
   * Submit a batch of decision requests to /decide/batch.
   */
  async decideBatch(request: SageBatchRequest): Promise<SageBatchResponse> {
    return this.post<SageBatchResponse>("/decide/batch", request);
  }

  /**
   * Evaluate a choice decision over content and options.
   * Supports 2 to 120 options.
   */
  choice(params: SageChoiceParams): Promise<SageChoiceDecision>;
  choice(
    content: string,
    options: Array<SageOption | string>,
    instructions?: string,
    id?: string,
  ): Promise<SageChoiceDecision>;
  async choice(
    contentOrParams: string | SageChoiceParams,
    optionsArg?: Array<SageOption | string>,
    instructionsArg?: string,
    idArg?: string,
  ): Promise<SageChoiceDecision> {
    let content: string;
    let options: Array<SageOption | string>;
    let instructions: string | undefined;
    let id: string | undefined;

    if (typeof contentOrParams === "object" && contentOrParams !== null) {
      content = contentOrParams.content;
      options = contentOrParams.options;
      instructions = contentOrParams.instructions;
      id = contentOrParams.id;
    } else {
      content = contentOrParams;
      options = optionsArg!;
      instructions = instructionsArg;
      id = idArg;
    }

    if (!Array.isArray(options) || options.length < 2 || options.length > 120) {
      throw new LevantoSageValidationError(
        `Choice decisions require between 2 and 120 options; received ${options?.length ?? 0}.`,
      );
    }

    const normalizedOptions: SageOption[] = options.map((opt) =>
      typeof opt === "string" ? { option: opt } : opt,
    );

    const request: SageDecideRequest = {
      content,
      question: {
        id: id ?? "choice",
        kind: "choice",
        instructions: instructions ?? "Choose the best option.",
        options: normalizedOptions,
      },
    };

    const response = await this.decide<SageChoiceResult>(request);
    return {
      chosen: response.result.chosen,
      confidence: response.result.confidence,
      probabilities: response.result.probabilities,
      latency_ms: response.meta?.latency_ms ?? 0,
      id: response.id,
      model: response.meta?.model,
    };
  }

  /**
   * Alias for choice()
   */
  decideChoice = this.choice;
}
