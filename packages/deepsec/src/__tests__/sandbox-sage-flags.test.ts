import { describe, expect, it, vi } from "vitest";
import { assertNoSageFlags } from "../commands/sandbox-process.js";

function runGuard(args: string[]): { exited: boolean; stderr: string } {
  const errors: string[] = [];
  const errorSpy = vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => {
    errors.push(a.map(String).join(" "));
  });
  const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
    throw new Error("__exit__");
  }) as never);

  let exited = false;
  try {
    assertNoSageFlags(args);
  } catch (err) {
    if (!(err instanceof Error) || err.message !== "__exit__") throw err;
    exited = true;
  } finally {
    errorSpy.mockRestore();
    exitSpy.mockRestore();
  }
  return { exited, stderr: errors.join("\n") };
}

describe("sandbox Sage flag guard", () => {
  it.each([
    ["--sage-gate"],
    ["--sage-gate-confidence"],
    ["--sage-gate=true"],
    ["--sage"],
    ["--latency-mode"],
    ["--min-confidence"],
    ["--no-claude-fallback"],
  ])("rejects %s before any sandbox is provisioned", (flag) => {
    const { exited, stderr } = runGuard(["--project-id", "p", flag]);
    expect(exited).toBe(true);
    expect(stderr).toContain("not supported in sandbox mode");
  });

  it("rejects --provider sage in both spaced and inline forms", () => {
    expect(runGuard(["--provider", "sage"]).exited).toBe(true);
    expect(runGuard(["--provider=sage"]).exited).toBe(true);
    expect(runGuard(["--provider", "claude"]).exited).toBe(false);
    expect(runGuard(["--provider=claude"]).exited).toBe(false);
  });

  it("rejects a repeated --provider whose last value is sage", () => {
    expect(runGuard(["--provider", "claude", "--provider", "sage"]).exited).toBe(true);
  });

  it("lets non-Sage passthrough flags through", () => {
    const { exited, stderr } = runGuard(["--limit", "50", "--force", "--reinvestigate", "2"]);
    expect(exited).toBe(false);
    expect(stderr).toBe("");
  });
});
