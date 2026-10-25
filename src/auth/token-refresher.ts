/**
 * Process-wide, single-flight WHOOP token refresh.
 *
 * WHOOP rotates refresh tokens: each refresh invalidates the refresh token it
 * was called with. If several requests hit a 401 at the same time and each
 * refreshes on its own, only the first wins and the rest fail with
 * "authentication failed". This module funnels every refresh in the process
 * through one in-flight promise and re-reads the token file first, so a
 * refresh already done by another request or process is reused.
 */

import { refreshAccessToken, toOAuthTokens } from "./oauth.js";
import type { OAuthConfig } from "./oauth.js";
import { isTokenExpired, loadTokens, saveTokens } from "./token-store.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TokenRefresherOptions {
  /** Called after a refresh actually produced (and saved) new tokens. */
  onRefreshed?: () => void;
}

export interface TokenRefresher {
  /**
   * Return a usable access token after `staleAccessToken` was rejected.
   * Concurrent callers share a single in-flight refresh.
   */
  refresh(staleAccessToken?: string): Promise<string>;
  /** Re-read the current access token from the token file. */
  reload(): Promise<string | undefined>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createTokenRefresher(
  config: OAuthConfig,
  options: TokenRefresherOptions = {}
): TokenRefresher {
  let inFlight: Promise<string> | undefined;

  async function doRefresh(staleAccessToken?: string): Promise<string> {
    const tokens = await loadTokens(config.tokenDir);
    if (!tokens) {
      throw new Error(
        "Token refresh failed: no stored tokens found. Re-authentication may be required."
      );
    }

    // Another request or process already refreshed — reuse its token.
    if (
      staleAccessToken !== undefined &&
      tokens.access_token !== staleAccessToken &&
      !isTokenExpired(tokens)
    ) {
      return tokens.access_token;
    }

    try {
      const refreshed = await refreshAccessToken(tokens.refresh_token, config);
      const newTokens = toOAuthTokens(refreshed, tokens.refresh_token);
      await saveTokens(newTokens, config.tokenDir);
      options.onRefreshed?.();
      return newTokens.access_token;
    } catch (error: unknown) {
      // Another process may have rotated the refresh token while ours was in flight.
      const latest = await loadTokens(config.tokenDir);
      if (latest && latest.refresh_token !== tokens.refresh_token && !isTokenExpired(latest)) {
        return latest.access_token;
      }
      throw error;
    }
  }

  return {
    refresh(staleAccessToken?: string): Promise<string> {
      inFlight ??= doRefresh(staleAccessToken).finally(() => {
        inFlight = undefined;
      });
      return inFlight;
    },

    async reload(): Promise<string | undefined> {
      const tokens = await loadTokens(config.tokenDir);
      return tokens?.access_token;
    },
  };
}
