import { hashPin, generateClientCredentials, checkAdminRateLimit, recordAdminFailedAttempt, timingSafeEqual } from "./auth";
import {
  listProfiles,
  getProfile,
  createProfile,
  updateProfile,
  deleteProfile,
  listLoginAttempts,
  unlockAttempt,
  createAdminSession,
  validateAdminSession,
  cleanExpiredSessions,
} from "./db";
import { generateKeyPair } from "./jwt";
import {
  layout,
  adminLogin,
  adminProfileList,
  adminProfileForm,
  adminAttempts,
  adminSetup,
  lockoutPage,
} from "./html";

interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
  SIGNING_KEY: string;
  ALLOWED_REDIRECT_URIS: string;
}

function getSessionToken(request: Request): string | null {
  const cookie = request.headers.get("Cookie") ?? "";
  const match = cookie.match(/(?:^|;\s*)admin_session=([^;]+)/);
  return match ? match[1] : null;
}

async function adminAuthCheck(request: Request, env: Env): Promise<boolean> {
  const token = getSessionToken(request);
  if (!token) return false;
  return validateAdminSession(env.DB, token);
}

async function generateCsrfToken(sessionToken: string): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`csrf:${sessionToken}`)
  );
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function validateCsrf(request: Request): Promise<boolean> {
  const sessionToken = getSessionToken(request);
  if (!sessionToken) return false;
  const form = await request.clone().formData();
  const token = form.get("_csrf") as string | null;
  if (!token) return false;
  const expected = await generateCsrfToken(sessionToken);
  return timingSafeEqual(token, expected);
}

function redirect(location: string): Response {
  return new Response(null, { status: 302, headers: { Location: location } });
}

function htmlResponse(body: string): Response {
  return new Response(body, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

async function requireAuth(request: Request, env: Env): Promise<Response | null> {
  if (!(await adminAuthCheck(request, env))) return redirect("/admin/login");
  return null;
}

async function getCsrfToken(request: Request): Promise<string> {
  const token = getSessionToken(request);
  return token ? generateCsrfToken(token) : "";
}

function csrfForbidden(): Response {
  return new Response("Forbidden — invalid CSRF token", { status: 403 });
}

export async function handleAdmin(
  request: Request,
  env: Env
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (path === "/admin/login" && method === "GET") {
    return htmlResponse(layout("Admin Login", adminLogin(), { hideNav: true }));
  }

  if (path === "/admin/login" && method === "POST") {
    const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
    const rateCheck = await checkAdminRateLimit(env.DB, ip);
    if (!rateCheck.allowed) {
      return htmlResponse(layout("Locked Out", lockoutPage(rateCheck.remainingMinutes ?? 60), { hideNav: true }));
    }
    const form = await request.formData();
    const password = form.get("password");
    if (typeof password !== "string" || !timingSafeEqual(password, env.ADMIN_PASSWORD)) {
      const result = await recordAdminFailedAttempt(env.DB, ip);
      if (!result.allowed) {
        return htmlResponse(layout("Locked Out", lockoutPage(result.remainingMinutes ?? 60), { hideNav: true }));
      }
      return htmlResponse(layout("Admin Login", adminLogin("Invalid password."), { hideNav: true }));
    }
    const sessionToken = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 86400 * 1000).toISOString().replace("Z", "");
    await createAdminSession(env.DB, sessionToken, expiresAt);
    await cleanExpiredSessions(env.DB);
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/admin",
        "Set-Cookie": `admin_session=${sessionToken}; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=86400`,
      },
    });
  }

  if (path === "/admin" && method === "GET") {
    const authRedirect = await requireAuth(request, env);
    if (authRedirect) return authRedirect;
    const csrf = await getCsrfToken(request);
    const profiles = await listProfiles(env.DB);
    return htmlResponse(layout("Profiles", adminProfileList(profiles, csrf)));
  }

  if (path === "/admin/profiles/new" && method === "GET") {
    const authRedirect = await requireAuth(request, env);
    if (authRedirect) return authRedirect;
    const csrf = await getCsrfToken(request);
    return htmlResponse(layout("Add Profile", adminProfileForm(null, undefined, csrf)));
  }

  if (path === "/admin/profiles/new" && method === "POST") {
    const authRedirect = await requireAuth(request, env);
    if (authRedirect) return authRedirect;
    if (!(await validateCsrf(request))) return csrfForbidden();
    const form = await request.formData();
    const name = form.get("name");
    const email = form.get("email");
    const avatar = form.get("avatar");
    const pin = form.get("pin");
    const csrf = await getCsrfToken(request);
    if (
      typeof name !== "string" || !name.trim() ||
      typeof email !== "string" || !email.trim() ||
      typeof avatar !== "string" || !avatar.trim() ||
      typeof pin !== "string" || !pin.trim()
    ) {
      return htmlResponse(layout("Add Profile", adminProfileForm(null, "All fields are required.", csrf)));
    }
    if (pin.trim().length < 4) {
      return htmlResponse(layout("Add Profile", adminProfileForm(null, "PIN must be at least 4 characters.", csrf)));
    }
    const { hash, salt } = await hashPin(pin);
    await createProfile(env.DB, {
      name: name.trim(),
      email: email.trim(),
      avatar: avatar.trim(),
      pin_hash: hash,
      pin_salt: salt,
    });
    return redirect("/admin");
  }

  const profileEditMatch = path.match(/^\/admin\/profiles\/([^/]+)$/);
  if (profileEditMatch) {
    const authRedirect = await requireAuth(request, env);
    if (authRedirect) return authRedirect;
    const id = profileEditMatch[1];

    if (method === "GET") {
      const profile = await getProfile(env.DB, id);
      if (!profile) return new Response("Not found", { status: 404 });
      const csrf = await getCsrfToken(request);
      return htmlResponse(layout("Edit Profile", adminProfileForm(profile, undefined, csrf)));
    }

    if (method === "POST") {
      if (!(await validateCsrf(request))) return csrfForbidden();
      const form = await request.formData();
      const name = form.get("name");
      const email = form.get("email");
      const avatar = form.get("avatar");
      const pin = form.get("pin");
      const csrf = await getCsrfToken(request);
      if (
        typeof name !== "string" || !name.trim() ||
        typeof email !== "string" || !email.trim() ||
        typeof avatar !== "string" || !avatar.trim()
      ) {
        const profile = await getProfile(env.DB, id);
        return htmlResponse(
          layout("Edit Profile", adminProfileForm(profile ?? null, "Name, email, and avatar are required.", csrf))
        );
      }
      const updates: Record<string, string> = {
        name: name.trim(),
        email: email.trim(),
        avatar: avatar.trim(),
      };
      if (typeof pin === "string" && pin.trim()) {
        if (pin.trim().length < 4) {
          const profile = await getProfile(env.DB, id);
          return htmlResponse(
            layout("Edit Profile", adminProfileForm(profile ?? null, "PIN must be at least 4 characters.", csrf))
          );
        }
        const { hash, salt } = await hashPin(pin.trim());
        updates.pin_hash = hash;
        updates.pin_salt = salt;
      }
      await updateProfile(env.DB, id, updates);
      return redirect("/admin");
    }
  }

  const profileDeleteMatch = path.match(/^\/admin\/profiles\/([^/]+)\/delete$/);
  if (profileDeleteMatch && method === "POST") {
    const authRedirect = await requireAuth(request, env);
    if (authRedirect) return authRedirect;
    if (!(await validateCsrf(request))) return csrfForbidden();
    await deleteProfile(env.DB, profileDeleteMatch[1]);
    return redirect("/admin");
  }

  if (path === "/admin/attempts" && method === "GET") {
    const authRedirect = await requireAuth(request, env);
    if (authRedirect) return authRedirect;
    const csrf = await getCsrfToken(request);
    const attempts = await listLoginAttempts(env.DB);
    return htmlResponse(layout("Login Attempts", adminAttempts(attempts, csrf)));
  }

  const unlockMatch = path.match(/^\/admin\/attempts\/(.+)\/unlock$/);
  if (unlockMatch && method === "POST") {
    const authRedirect = await requireAuth(request, env);
    if (authRedirect) return authRedirect;
    if (!(await validateCsrf(request))) return csrfForbidden();
    await unlockAttempt(env.DB, decodeURIComponent(unlockMatch[1]));
    return redirect("/admin/attempts");
  }

  if (path === "/admin/setup" && method === "GET") {
    const authRedirect = await requireAuth(request, env);
    if (authRedirect) return authRedirect;
    const origin = url.origin;

    if (env.SIGNING_KEY) {
      return htmlResponse(
        layout("Setup", adminSetup({
          alreadyConfigured: true,
          clientId: env.CLIENT_ID,
          clientSecret: env.CLIENT_SECRET,
          authUrl: `${origin}/authorize`,
          tokenUrl: `${origin}/token`,
          certsUrl: `${origin}/jwks`,
        }))
      );
    }

    const keyPair = await generateKeyPair();
    const { clientId, clientSecret } = generateClientCredentials();
    return htmlResponse(
      layout("Setup", adminSetup({
        alreadyConfigured: false,
        clientId,
        clientSecret,
        signingKey: keyPair.privateKeyJwk,
        authUrl: `${origin}/authorize`,
        tokenUrl: `${origin}/token`,
        certsUrl: `${origin}/jwks`,
      }))
    );
  }

  return new Response("Not found", { status: 404 });
}
