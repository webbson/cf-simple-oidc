import { signJwt, getJwks } from "./jwt";
import {
  verifyPin,
  generateAuthCode,
  checkRateLimit,
  recordFailedAttempt,
  resetAttempts,
} from "./auth";
import {
  listProfiles,
  getProfile,
  createAuthCode,
  consumeAuthCode,
  cleanExpiredCodes,
} from "./db";
import { layout, profilePicker, pinEntry, lockoutPage } from "./html";

interface Env {
  DB: D1Database;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
  SIGNING_KEY: string;
}

export function handleDiscovery(request: Request, _env: Env): Response {
  const origin = new URL(request.url).origin;
  const doc = {
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    jwks_uri: `${origin}/jwks`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "email", "profile"],
    claims_supported: ["sub", "email", "name", "iss", "aud", "iat", "exp"],
  };
  return new Response(JSON.stringify(doc), {
    headers: { "Content-Type": "application/json" },
  });
}

export async function handleAuthorize(
  request: Request,
  env: Env
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  // GET /authorize/pin/:id — show PIN entry for a specific profile
  const pinMatch = path.match(/^\/authorize\/pin\/([^/]+)$/);
  if (pinMatch && request.method === "GET") {
    const profileId = pinMatch[1];
    const profile = await getProfile(env.DB, profileId);
    if (!profile) {
      return new Response(
        layout("Error", "<div style='max-width:420px;margin:4rem auto;padding:0 1rem;'><div class='card center'><p>Profile not found.</p></div></div>", { hideNav: true }),
        { status: 404, headers: { "Content-Type": "text/html" } }
      );
    }
    const html = layout("Enter PIN", pinEntry(profile, url.search), { hideNav: true });
    return new Response(html, { headers: { "Content-Type": "text/html" } });
  }

  if (request.method === "GET" && path === "/authorize") {
    const clientId = url.searchParams.get("client_id");
    const responseType = url.searchParams.get("response_type");

    if (clientId !== env.CLIENT_ID || responseType !== "code") {
      return new Response(
        layout("Error", "<div style='max-width:420px;margin:4rem auto;padding:0 1rem;'><div class='card center'><p>Invalid authorization request.</p></div></div>", { hideNav: true }),
        { status: 400, headers: { "Content-Type": "text/html" } }
      );
    }

    const profiles = await listProfiles(env.DB);
    const html = layout("Choose Profile", profilePicker(profiles, url.search), { hideNav: true });
    return new Response(html, { headers: { "Content-Type": "text/html" } });
  }

  if (request.method === "POST") {
    const body = await request.formData();

    const profileId = body.get("profile_id") as string;
    const pin = body.get("pin") as string;
    const clientId = body.get("client_id") as string;
    const redirectUri = body.get("redirect_uri") as string;
    const state = body.get("state") as string | null;
    const scope = body.get("scope") as string | null;
    const codeChallenge = body.get("code_challenge") as string | null;
    const codeChallengeMethod = body.get("code_challenge_method") as string | null;

    const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";

    const oidcParams = new URLSearchParams();
    oidcParams.set("client_id", clientId);
    oidcParams.set("redirect_uri", redirectUri);
    oidcParams.set("response_type", "code");
    if (state) oidcParams.set("state", state);
    if (scope) oidcParams.set("scope", scope);
    if (codeChallenge) oidcParams.set("code_challenge", codeChallenge);
    if (codeChallengeMethod) oidcParams.set("code_challenge_method", codeChallengeMethod);
    const queryString = `?${oidcParams.toString()}`;

    const rateLimit = await checkRateLimit(env.DB, profileId, ip);
    if (!rateLimit.allowed) {
      const html = layout("Locked Out", lockoutPage(rateLimit.remainingMinutes ?? 15), { hideNav: true });
      return new Response(html, {
        status: 429,
        headers: { "Content-Type": "text/html" },
      });
    }

    const profile = await getProfile(env.DB, profileId);
    if (!profile) {
      return new Response(
        layout("Error", "<div style='max-width:420px;margin:4rem auto;padding:0 1rem;'><div class='card center'><p>Profile not found.</p></div></div>", { hideNav: true }),
        { status: 400, headers: { "Content-Type": "text/html" } }
      );
    }

    const pinValid = await verifyPin(pin, profile.pin_hash, profile.pin_salt);
    if (!pinValid) {
      const result = await recordFailedAttempt(env.DB, profileId, ip);

      if (!result.allowed) {
        const html = layout("Locked Out", lockoutPage(result.remainingMinutes ?? 15), { hideNav: true });
        return new Response(html, {
          status: 429,
          headers: { "Content-Type": "text/html" },
        });
      }

      const errorMsg = `Incorrect PIN. ${result.remainingAttempts} attempt${result.remainingAttempts === 1 ? "" : "s"} remaining.`;
      const html = layout("Enter PIN", pinEntry(profile, queryString, errorMsg), { hideNav: true });
      return new Response(html, {
        status: 401,
        headers: { "Content-Type": "text/html" },
      });
    }

    await resetAttempts(env.DB, profileId, ip);
    const code = generateAuthCode();
    await createAuthCode(env.DB, {
      code,
      profile_id: profileId,
      redirect_uri: redirectUri,
      code_challenge: codeChallenge ?? undefined,
      code_challenge_method: codeChallengeMethod ?? undefined,
    });
    await cleanExpiredCodes(env.DB);

    const redirectUrl = new URL(redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (state) redirectUrl.searchParams.set("state", state);

    return Response.redirect(redirectUrl.toString(), 302);
  }

  return new Response("Method Not Allowed", { status: 405 });
}

function errorJson(error: string, description: string, status: number): Response {
  return new Response(
    JSON.stringify({ error, error_description: description }),
    { status, headers: { "Content-Type": "application/json" } }
  );
}

export async function handleToken(
  request: Request,
  env: Env
): Promise<Response> {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const body = await request.formData();

  let clientId = body.get("client_id") as string | null;
  let clientSecret = body.get("client_secret") as string | null;

  const authHeader = request.headers.get("Authorization");
  if (authHeader?.startsWith("Basic ")) {
    const decoded = atob(authHeader.slice(6));
    const colonIdx = decoded.indexOf(":");
    if (colonIdx !== -1) {
      if (!clientId) clientId = decoded.slice(0, colonIdx);
      if (!clientSecret) clientSecret = decoded.slice(colonIdx + 1);
    }
  }

  const grantType = body.get("grant_type") as string | null;
  const code = body.get("code") as string | null;
  const redirectUri = body.get("redirect_uri") as string | null;

  if (grantType !== "authorization_code") {
    return errorJson("unsupported_grant_type", "Only authorization_code grant type is supported.", 400);
  }

  if (clientId !== env.CLIENT_ID || clientSecret !== env.CLIENT_SECRET) {
    return errorJson("invalid_client", "Client authentication failed.", 401);
  }

  if (!code) {
    return errorJson("invalid_request", "Missing code parameter.", 400);
  }

  const authCode = await consumeAuthCode(env.DB, code);
  if (!authCode) {
    return errorJson("invalid_grant", "Authorization code is invalid or expired.", 400);
  }

  if (authCode.redirect_uri !== redirectUri) {
    return errorJson("invalid_grant", "redirect_uri does not match.", 400);
  }

  const profile = await getProfile(env.DB, authCode.profile_id);
  if (!profile) {
    return errorJson("invalid_grant", "Profile not found.", 400);
  }

  const origin = new URL(request.url).origin;
  const now = Math.floor(Date.now() / 1000);

  const idToken = await signJwt(
    {
      iss: origin,
      sub: profile.id,
      email: profile.email,
      name: profile.name,
      aud: env.CLIENT_ID,
      iat: now,
      exp: now + 3600,
    },
    env.SIGNING_KEY
  );

  const accessToken = crypto.randomUUID();

  return new Response(
    JSON.stringify({
      access_token: accessToken,
      id_token: idToken,
      token_type: "Bearer",
      expires_in: 3600,
    }),
    { headers: { "Content-Type": "application/json" } }
  );
}

export async function handleJwks(
  _request: Request,
  env: Env
): Promise<Response> {
  const jwks = await getJwks(env.SIGNING_KEY);
  return new Response(JSON.stringify(jwks), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=86400",
    },
  });
}
