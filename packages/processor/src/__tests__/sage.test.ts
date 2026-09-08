import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  LevantoSageAuthError,
  LevantoSageClient,
  LevantoSageError,
  LevantoSageQuotaError,
  LevantoSageRateLimitError,
  LevantoSageServerError,
  LevantoSageValidationError,
} from "../sage/client.js";

describe("LevantoSageClient", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    delete process.env.SAGE_API_KEY;
    delete process.env.LEVANTO_API_KEY;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  describe("authentication and initialization", () => {
    it("reads apiKey from options", async () => {
      let authHeader = "";
      const mockFetch = vi.fn(async (_url, init) => {
        authHeader = (init?.headers as Record<string, string>)?.Authorization;
        return new Response(
          JSON.stringify({
            id: "q1",
            kind: "choice",
            result: {
              chosen: "P0",
              confidence: 0.95,
              probabilities: [{ option: "P0", probability: 0.95 }],
            },
            meta: { model: "levanto-sage-v0.8", latency_ms: 85 },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_option_key",
        fetch: mockFetch as unknown as typeof fetch,
      });

      const res = await client.choice({
        content: "SQL injection vulnerability",
        options: ["P0", "P1"],
      });

      expect(authHeader).toBe("Bearer lv_live_option_key");
      expect(res.chosen).toBe("P0");
    });

    it("reads apiKey from SAGE_API_KEY environment variable", async () => {
      process.env.SAGE_API_KEY = "lv_live_sage_env_key";
      let authHeader = "";
      const mockFetch = vi.fn(async (_url, init) => {
        authHeader = (init?.headers as Record<string, string>)?.Authorization;
        return new Response(
          JSON.stringify({
            id: "q1",
            kind: "choice",
            result: { chosen: "P1", confidence: 0.8, probabilities: [] },
            meta: { latency_ms: 50 },
          }),
          { status: 200 },
        );
      });

      const client = new LevantoSageClient({ fetch: mockFetch as unknown as typeof fetch });
      await client.choice({ content: "test", options: ["P0", "P1"] });

      expect(authHeader).toBe("Bearer lv_live_sage_env_key");
    });

    it("reads apiKey from LEVANTO_API_KEY environment variable if SAGE_API_KEY unset", async () => {
      process.env.LEVANTO_API_KEY = "lv_live_levanto_env_key";
      let authHeader = "";
      const mockFetch = vi.fn(async (_url, init) => {
        authHeader = (init?.headers as Record<string, string>)?.Authorization;
        return new Response(
          JSON.stringify({
            id: "q1",
            kind: "choice",
            result: { chosen: "P2", confidence: 0.7, probabilities: [] },
          }),
          { status: 200 },
        );
      });

      const client = new LevantoSageClient({ fetch: mockFetch as unknown as typeof fetch });
      await client.choice({ content: "test", options: ["P0", "P1"] });

      expect(authHeader).toBe("Bearer lv_live_levanto_env_key");
    });

    it("throws LevantoSageAuthError when no API key is provided", async () => {
      const client = new LevantoSageClient();
      await expect(client.choice({ content: "test", options: ["P0", "P1"] })).rejects.toThrow(
        LevantoSageAuthError,
      );
    });

    it("respects custom baseUrl", async () => {
      let requestedUrl = "";
      const mockFetch = vi.fn(async (url) => {
        requestedUrl = String(url);
        return new Response(
          JSON.stringify({
            id: "test",
            kind: "choice",
            result: { chosen: "P0", confidence: 0.9, probabilities: [] },
          }),
          { status: 200 },
        );
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_key",
        baseUrl: "https://custom.sage.endpoint/v2/",
        fetch: mockFetch as unknown as typeof fetch,
      });

      await client.choice({ content: "test", options: ["P0", "P1"] });
      expect(requestedUrl).toBe("https://custom.sage.endpoint/v2/decide");
    });
  });

  describe("choice decisions", () => {
    it("supports string array options and returns chosen, confidence, probabilities, latency_ms", async () => {
      let sentBody: any;
      const mockFetch = vi.fn(async (_url, init) => {
        sentBody = JSON.parse(init?.body as string);
        return new Response(
          JSON.stringify({
            id: "choice-1",
            kind: "choice",
            result: {
              chosen: "P0",
              confidence: 0.92,
              probabilities: [
                { option: "P0", probability: 0.92 },
                { option: "P1", probability: 0.15 },
                { option: "P2", probability: 0.05 },
                { option: "skip", probability: 0.01 },
              ],
            },
            meta: {
              model: "levanto-sage-v0.8",
              latency_ms: 104.5,
            },
          }),
          { status: 200 },
        );
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_key",
        fetch: mockFetch as unknown as typeof fetch,
      });

      const decision = await client.choice({
        content: "Hardcoded secret in public route handler",
        options: ["P0", "P1", "P2", "skip"],
        instructions: "Determine vulnerability triage priority",
      });

      expect(sentBody).toMatchObject({
        content: "Hardcoded secret in public route handler",
        question: {
          kind: "choice",
          instructions: "Determine vulnerability triage priority",
          options: [{ option: "P0" }, { option: "P1" }, { option: "P2" }, { option: "skip" }],
        },
      });

      expect(decision).toEqual({
        chosen: "P0",
        confidence: 0.92,
        probabilities: [
          { option: "P0", probability: 0.92 },
          { option: "P1", probability: 0.15 },
          { option: "P2", probability: 0.05 },
          { option: "skip", probability: 0.01 },
        ],
        latency_ms: 104.5,
        id: "choice-1",
        model: "levanto-sage-v0.8",
      });
    });

    it("supports structured options with descriptions and positional arguments", async () => {
      let sentBody: any;
      const mockFetch = vi.fn(async (_url, init) => {
        sentBody = JSON.parse(init?.body as string);
        return new Response(
          JSON.stringify({
            id: "choice-custom-id",
            kind: "choice",
            result: {
              chosen: "moderate",
              confidence: 0.84,
              probabilities: [{ option: "moderate", probability: 0.84 }],
            },
            meta: { latency_ms: 88 },
          }),
          { status: 200 },
        );
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_key",
        fetch: mockFetch as unknown as typeof fetch,
      });

      const decision = await client.choice(
        "CSRF on profile update",
        [
          { option: "trivial", description: "One click" },
          { option: "moderate", description: "Requires auth" },
          { option: "difficult", description: "Needs chained exploit" },
        ],
        "Rate exploitability",
        "choice-custom-id",
      );

      expect(sentBody.question.options).toHaveLength(3);
      expect(sentBody.question.options[0]).toEqual({
        option: "trivial",
        description: "One click",
      });
      expect(decision.chosen).toBe("moderate");
      expect(decision.confidence).toBe(0.84);
      expect(decision.latency_ms).toBe(88);
    });

    it("validates that options length is between 2 and 120", async () => {
      const client = new LevantoSageClient({ apiKey: "lv_live_key" });

      await expect(client.choice({ content: "test", options: ["only-one"] })).rejects.toThrow(
        LevantoSageValidationError,
      );

      const tooMany = Array.from({ length: 121 }, (_, i) => `opt-${i}`);
      await expect(client.choice({ content: "test", options: tooMany })).rejects.toThrow(
        LevantoSageValidationError,
      );
    });
  });

  describe("batch decisions", () => {
    it("submits batch requests and returns responses", async () => {
      let sentBody: any;
      const mockFetch = vi.fn(async (_url, init) => {
        sentBody = JSON.parse(init?.body as string);
        return new Response(
          JSON.stringify({
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
                        confidence: 0.95,
                        probabilities: [{ option: "P0", probability: 0.95 }],
                      },
                    },
                  },
                ],
              },
            ],
            meta: {
              model: "levanto-sage-v0.8",
              request_count: 1,
              question_count: 1,
              latency_ms: 120,
            },
          }),
          { status: 200 },
        );
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_key",
        fetch: mockFetch as unknown as typeof fetch,
      });

      const batchRes = await client.decideBatch({
        latency_mode: "quality",
        requests: [
          {
            content: "SQL injection",
            questions: [
              {
                id: "priority",
                kind: "choice",
                options: [{ option: "P0" }, { option: "P1" }],
              },
            ],
          },
        ],
      });

      expect(sentBody.requests).toHaveLength(1);
      expect(batchRes.results[0].answers[0].ok).toBe(true);
      expect(batchRes.meta.latency_ms).toBe(120);
    });
  });

  describe("error handling", () => {
    it("handles HTTP 400 validation error", async () => {
      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({ detail: "scale levels must be integers in 0..4" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_key",
        fetch: mockFetch as unknown as typeof fetch,
      });

      await expect(client.choice({ content: "test", options: ["P0", "P1"] })).rejects.toThrow(
        LevantoSageValidationError,
      );
    });

    it("handles HTTP 401 and 403 authentication errors", async () => {
      const mock401 = vi.fn(async () => {
        return new Response(JSON.stringify({ detail: "Invalid API key" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      });

      const client401 = new LevantoSageClient({
        apiKey: "invalid_key",
        fetch: mock401 as unknown as typeof fetch,
      });

      await expect(client401.choice({ content: "test", options: ["P0", "P1"] })).rejects.toThrow(
        LevantoSageAuthError,
      );

      const mock403 = vi.fn(async () => {
        return new Response(JSON.stringify({ detail: "Forbidden access" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        });
      });

      const client403 = new LevantoSageClient({
        apiKey: "forbidden_key",
        fetch: mock403 as unknown as typeof fetch,
      });

      await expect(client403.choice({ content: "test", options: ["P0", "P1"] })).rejects.toThrow(
        LevantoSageAuthError,
      );
    });

    it("handles HTTP 402 quota exhausted error", async () => {
      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({ detail: "Monthly allowance exhausted" }), {
          status: 402,
          headers: { "Content-Type": "application/json" },
        });
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_key",
        fetch: mockFetch as unknown as typeof fetch,
      });

      await expect(client.choice({ content: "test", options: ["P0", "P1"] })).rejects.toThrow(
        LevantoSageQuotaError,
      );
    });

    it("retries on transient HTTP 5xx errors and throws LevantoSageServerError on exhaustion", async () => {
      let calls = 0;
      const mockFetch = vi.fn(async () => {
        calls++;
        return new Response("Service Unavailable", { status: 503 });
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_key",
        maxRetries: 2,
        fetch: mockFetch as unknown as typeof fetch,
      });

      await expect(client.choice({ content: "test", options: ["P0", "P1"] })).rejects.toThrow(
        LevantoSageServerError,
      );

      // Initial call + 2 retries = 3 calls
      expect(calls).toBe(3);
    });

    it("retries HTTP 429 and succeeds when the rate limit clears", async () => {
      let calls = 0;
      const mockFetch = vi.fn(async () => {
        calls++;
        if (calls === 1) {
          return new Response("Too Many Requests", {
            status: 429,
            headers: { "retry-after": "0" },
          });
        }
        return new Response(
          JSON.stringify({
            id: "q1",
            kind: "choice",
            result: { chosen: "P1", confidence: 0.8, probabilities: [] },
          }),
          { status: 200 },
        );
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_key",
        maxRetries: 2,
        fetch: mockFetch as unknown as typeof fetch,
      });

      const result = await client.choice({ content: "test", options: ["P0", "P1"] });

      expect(result.chosen).toBe("P1");
      expect(calls).toBe(2);
    });

    it("throws LevantoSageRateLimitError once 429 retries are exhausted", async () => {
      let calls = 0;
      const mockFetch = vi.fn(async () => {
        calls++;
        return new Response("Too Many Requests", {
          status: 429,
          headers: { "retry-after": "0" },
        });
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_key",
        maxRetries: 2,
        fetch: mockFetch as unknown as typeof fetch,
      });

      await expect(client.choice({ content: "test", options: ["P0", "P1"] })).rejects.toThrow(
        LevantoSageRateLimitError,
      );

      expect(calls).toBe(3);
    });

    it("does not retry a non-transient non-2xx status", async () => {
      let calls = 0;
      const mockFetch = vi.fn(async () => {
        calls++;
        return new Response("Not Found", { status: 404 });
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_key",
        maxRetries: 2,
        fetch: mockFetch as unknown as typeof fetch,
      });

      await expect(client.choice({ content: "test", options: ["P0", "P1"] })).rejects.toThrow(
        LevantoSageError,
      );

      expect(calls).toBe(1);
    });

    it("succeeds if transient 5xx clears on retry", async () => {
      let calls = 0;
      const mockFetch = vi.fn(async () => {
        calls++;
        if (calls === 1) {
          return new Response("Temporarily overloaded", { status: 502 });
        }
        return new Response(
          JSON.stringify({
            id: "q1",
            kind: "choice",
            result: { chosen: "P0", confidence: 0.99, probabilities: [] },
          }),
          { status: 200 },
        );
      });

      const client = new LevantoSageClient({
        apiKey: "lv_live_key",
        maxRetries: 2,
        fetch: mockFetch as unknown as typeof fetch,
      });

      const result = await client.choice({ content: "test", options: ["P0", "P1"] });
      expect(calls).toBe(2);
      expect(result.chosen).toBe("P0");
    });
  });

  describe("readiness check", () => {
    it("returns true on HTTP 200 from /ready", async () => {
      const mockFetch = vi.fn(async () => new Response("", { status: 200 }));
      const client = new LevantoSageClient({ fetch: mockFetch as unknown as typeof fetch });
      expect(await client.isReady()).toBe(true);
    });

    it("returns false on HTTP 503 from /ready", async () => {
      const mockFetch = vi.fn(async () => new Response("", { status: 503 }));
      const client = new LevantoSageClient({ fetch: mockFetch as unknown as typeof fetch });
      expect(await client.isReady()).toBe(false);
    });
  });
});
