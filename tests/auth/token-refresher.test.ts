import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createTokenRefresher } from "../../src/auth/token-refresher.js";
import { loadTokens, saveTokens } from "../../src/auth/token-store.js";
import type { OAuthTokens } from "../../src/auth/token-store.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function tokenResponse(generation: number): Response {
  return jsonResponse({
    access_token: `access-${generation}`,
    refresh_token: `refresh-${generation}`,
    expires_in: 3600,
    token_type: "bearer",
    scope: "offline",
  });
}

function freshTokens(accessToken: string, refreshToken: string): OAuthTokens {
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_at: Date.now() + 3_600_000,
    token_type: "bearer",
  };
}

const EXPIRED_TOKENS: OAuthTokens = {
  access_token: "access-0",
  refresh_token: "refresh-0",
  expires_at: Date.now() - 1000,
  token_type: "bearer",
};

describe("createTokenRefresher", () => {
  let tokenDir: string;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    tokenDir = await mkdtemp(join(tmpdir(), "whoop-mcp-refresher-"));
    await saveTokens(EXPIRED_TOKENS, tokenDir);
    mockFetch = vi.fn();
    vi.stubGlobal("fetch", mockFetch);
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    await rm(tokenDir, { recursive: true });
  });

  const config = (): { clientId: string; clientSecret: string; tokenDir: string } => ({
    clientId: "id",
    clientSecret: "secret",
    tokenDir,
  });

  it("refreshes, saves the rotated tokens, and calls onRefreshed", async () => {
    mockFetch.mockResolvedValueOnce(tokenResponse(1));
    const onRefreshed = vi.fn();
    const refresher = createTokenRefresher(config(), { onRefreshed });

    await expect(refresher.refresh("access-0")).resolves.toBe("access-1");

    const saved = await loadTokens(tokenDir);
    expect(saved?.refresh_token).toBe("refresh-1");
    expect(onRefreshed).toHaveBeenCalledOnce();
  });

  it("shares one in-flight refresh between concurrent callers", async () => {
    mockFetch.mockImplementation(
      () => new Promise<Response>((resolve) => setTimeout(() => resolve(tokenResponse(1)), 20))
    );
    const refresher = createTokenRefresher(config());

    const tokens = await Promise.all(
      Array.from({ length: 5 }, () => refresher.refresh("access-0"))
    );

    expect(tokens).toEqual(Array(5).fill("access-1"));
    expect(mockFetch).toHaveBeenCalledOnce();
  });

  it("starts a new refresh once the previous one settled", async () => {
    mockFetch.mockResolvedValueOnce(tokenResponse(1)).mockResolvedValueOnce(tokenResponse(2));
    const refresher = createTokenRefresher(config());

    await refresher.refresh("access-0");
    await expect(refresher.refresh("access-1")).resolves.toBe("access-2");
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("reuses a token already refreshed by someone else instead of refreshing", async () => {
    await saveTokens(freshTokens("access-9", "refresh-9"), tokenDir);
    const refresher = createTokenRefresher(config());

    await expect(refresher.refresh("access-0")).resolves.toBe("access-9");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("falls back to tokens another process saved while its refresh failed", async () => {
    mockFetch.mockImplementationOnce(async () => {
      // Another process wins the race and rotates the refresh token first.
      await saveTokens(freshTokens("access-7", "refresh-7"), tokenDir);
      return jsonResponse({ error: "invalid_grant", error_description: "used" }, 400);
    });
    const refresher = createTokenRefresher(config());

    await expect(refresher.refresh("access-0")).resolves.toBe("access-7");
  });

  it("rethrows the refresh error when no newer tokens are on disk", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ error: "invalid_grant", error_description: "revoked" }, 400)
    );
    const refresher = createTokenRefresher(config());

    await expect(refresher.refresh("access-0")).rejects.toThrow(/Token refresh failed \(400\)/);
  });

  it("throws when no tokens are stored", async () => {
    await rm(join(tokenDir, "tokens.json"));
    const refresher = createTokenRefresher(config());

    await expect(refresher.refresh("access-0")).rejects.toThrow(/no stored tokens/i);
  });

  it("reload returns the access token currently on disk", async () => {
    const refresher = createTokenRefresher(config());

    await expect(refresher.reload()).resolves.toBe("access-0");
  });
});
