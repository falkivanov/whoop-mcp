/**
 * Integration test: parallel tool calls over the stateless HTTP transport
 * while the WHOOP access token is expired.
 *
 * WHOOP rotates refresh tokens, so concurrent refreshes with the same refresh
 * token make every caller but the first fail. All request servers share one
 * WHOOP client and one token refresher, so exactly one refresh must happen and
 * every call must succeed.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createHttpServer } from "../../src/transport/http.js";
import { createWhoopServer } from "../../src/server.js";
import { createWhoopClient } from "../../src/api/client.js";
import { createTokenRefresher } from "../../src/auth/token-refresher.js";
import { loadTokens, saveTokens } from "../../src/auth/token-store.js";
import { WHOOP_TOKEN_URL } from "../../src/api/endpoints.js";

const AUTH_TOKEN = "refresh-race-token";
const WHOOP_HOST = "https://api.prod.whoop.com";
const realFetch = globalThis.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status === 200 ? "OK" : "Error",
    headers: { "Content-Type": "application/json" },
  });
}

interface FakeWhoop {
  handle(url: string, init?: RequestInit): Promise<Response>;
  tokenCalls: number;
}

/** Fake WHOOP API: only the latest access token is valid, refresh tokens rotate. */
function createFakeWhoop(): FakeWhoop {
  let generation = 0;
  let validAccessToken: string | undefined;
  let validRefreshToken = "refresh-0";

  const fake: FakeWhoop = {
    tokenCalls: 0,
    async handle(url: string, init?: RequestInit): Promise<Response> {
      if (url === WHOOP_TOKEN_URL) {
        fake.tokenCalls++;
        const params = new URLSearchParams(String(init?.body));
        // Keep the refresh in flight long enough for the other calls to hit 401.
        await new Promise((resolve) => setTimeout(resolve, 50));
        if (params.get("refresh_token") !== validRefreshToken) {
          return jsonResponse({ error: "invalid_grant", error_description: "token used" }, 400);
        }
        generation++;
        validAccessToken = `access-${generation}`;
        validRefreshToken = `refresh-${generation}`;
        return jsonResponse({
          access_token: validAccessToken,
          refresh_token: validRefreshToken,
          expires_in: 3600,
          token_type: "bearer",
          scope: "offline",
        });
      }

      const authHeader = (init?.headers as Record<string, string> | undefined)?.Authorization;
      if (authHeader !== `Bearer ${validAccessToken}`) {
        return jsonResponse({ message: "authentication failed" }, 401);
      }
      return jsonResponse({ user_id: 42, email: "t@example.com", first_name: "T", last_name: "U" });
    },
  };
  return fake;
}

describe("HTTP transport — parallel calls with an expired WHOOP token", () => {
  let tokenDir: string;
  let fakeWhoop: FakeWhoop;
  let mcpStatuses: number[];

  beforeEach(async () => {
    tokenDir = await mkdtemp(join(tmpdir(), "whoop-mcp-race-"));
    await saveTokens(
      {
        access_token: "access-0",
        refresh_token: "refresh-0",
        expires_at: Date.now() - 1000,
        token_type: "bearer",
      },
      tokenDir
    );
    fakeWhoop = createFakeWhoop();
    mcpStatuses = [];
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.startsWith(WHOOP_HOST)) {
        return fakeWhoop.handle(url, init);
      }
      const response = await realFetch(input, init);
      if (url.endsWith("/mcp") && init?.method === "POST") {
        mcpStatuses.push(response.status);
      }
      return response;
    });
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    await rm(tokenDir, { recursive: true });
  });

  it("5 parallel tool calls all succeed with a single token refresh", async () => {
    const refresher = createTokenRefresher({ clientId: "id", clientSecret: "secret", tokenDir });
    const whoopClient = createWhoopClient({
      accessToken: "access-0",
      onTokenRefresh: refresher.refresh,
      reloadAccessToken: refresher.reload,
    });
    const http = await createHttpServer({
      authToken: AUTH_TOKEN,
      port: 0,
      createMcpServer: () => createWhoopServer(whoopClient).server,
    });
    const address = http.server.address();
    if (!address || typeof address === "string") throw new Error("Missing port");
    const client = new Client({ name: "race-test", version: "1" });

    try {
      await client.connect(
        new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${address.port}/mcp`), {
          requestInit: { headers: { Authorization: `Bearer ${AUTH_TOKEN}` } },
        })
      );
      mcpStatuses.length = 0;

      const results = await Promise.all(
        Array.from({ length: 5 }, () => client.callTool({ name: "get_profile", arguments: {} }))
      );

      for (const result of results) expect(result.isError).not.toBe(true);
      expect(mcpStatuses).toEqual([200, 200, 200, 200, 200]);
      expect(fakeWhoop.tokenCalls).toBe(1);
      expect((await loadTokens(tokenDir))?.refresh_token).toBe("refresh-1");
    } finally {
      await client.close().catch(() => {});
      await http.close();
    }
  }, 15_000);
});
