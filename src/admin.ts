import { hashPin, generateClientCredentials } from "./auth";
import {
  listProfiles,
  getProfile,
  createProfile,
  updateProfile,
  deleteProfile,
  listLoginAttempts,
  unlockAttempt,
} from "./db";
import { generateKeyPair } from "./jwt";
import {
  layout,
  adminLogin,
  adminProfileList,
  adminProfileForm,
  adminAttempts,
  adminSetup,
} from "./html";

interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
  SIGNING_KEY: string;
}

function adminAuthCheck(request: Request, env: Env): boolean {
  const cookie = request.headers.get("Cookie") ?? "";
  const match = cookie.match(/(?:^|;\s*)admin_session=([^;]+)/);
  if (!match) return false;
  return match[1] === env.ADMIN_PASSWORD;
}

function redirect(location: string): Response {
  return new Response(null, { status: 302, headers: { Location: location } });
}

function htmlResponse(body: string): Response {
  return new Response(body, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function requireAuth(request: Request, env: Env): Response | null {
  if (!adminAuthCheck(request, env)) return redirect("/admin/login");
  return null;
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
    const form = await request.formData();
    const password = form.get("password");
    if (typeof password !== "string" || password !== env.ADMIN_PASSWORD) {
      return htmlResponse(layout("Admin Login", adminLogin("Invalid password."), { hideNav: true }));
    }
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/admin",
        "Set-Cookie": `admin_session=${env.ADMIN_PASSWORD}; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=86400`,
      },
    });
  }

  if (path === "/admin" && method === "GET") {
    const authRedirect = requireAuth(request, env);
    if (authRedirect) return authRedirect;
    const profiles = await listProfiles(env.DB);
    return htmlResponse(layout("Profiles", adminProfileList(profiles)));
  }

  if (path === "/admin/profiles/new" && method === "GET") {
    const authRedirect = requireAuth(request, env);
    if (authRedirect) return authRedirect;
    return htmlResponse(layout("Add Profile", adminProfileForm(null)));
  }

  if (path === "/admin/profiles/new" && method === "POST") {
    const authRedirect = requireAuth(request, env);
    if (authRedirect) return authRedirect;
    const form = await request.formData();
    const name = form.get("name");
    const email = form.get("email");
    const avatar = form.get("avatar");
    const pin = form.get("pin");
    if (
      typeof name !== "string" || !name.trim() ||
      typeof email !== "string" || !email.trim() ||
      typeof avatar !== "string" || !avatar.trim() ||
      typeof pin !== "string" || !pin.trim()
    ) {
      return htmlResponse(layout("Add Profile", adminProfileForm(null, "All fields are required.")));
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
    const authRedirect = requireAuth(request, env);
    if (authRedirect) return authRedirect;
    const id = profileEditMatch[1];

    if (method === "GET") {
      const profile = await getProfile(env.DB, id);
      if (!profile) return new Response("Not found", { status: 404 });
      return htmlResponse(layout("Edit Profile", adminProfileForm(profile)));
    }

    if (method === "POST") {
      const form = await request.formData();
      const name = form.get("name");
      const email = form.get("email");
      const avatar = form.get("avatar");
      const pin = form.get("pin");
      if (
        typeof name !== "string" || !name.trim() ||
        typeof email !== "string" || !email.trim() ||
        typeof avatar !== "string" || !avatar.trim()
      ) {
        const profile = await getProfile(env.DB, id);
        return htmlResponse(
          layout("Edit Profile", adminProfileForm(profile ?? null, "Name, email, and avatar are required."))
        );
      }
      const updates: Record<string, string> = {
        name: name.trim(),
        email: email.trim(),
        avatar: avatar.trim(),
      };
      if (typeof pin === "string" && pin.trim()) {
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
    const authRedirect = requireAuth(request, env);
    if (authRedirect) return authRedirect;
    await deleteProfile(env.DB, profileDeleteMatch[1]);
    return redirect("/admin");
  }

  if (path === "/admin/attempts" && method === "GET") {
    const authRedirect = requireAuth(request, env);
    if (authRedirect) return authRedirect;
    const attempts = await listLoginAttempts(env.DB);
    return htmlResponse(layout("Login Attempts", adminAttempts(attempts)));
  }

  const unlockMatch = path.match(/^\/admin\/attempts\/(.+)\/unlock$/);
  if (unlockMatch && method === "POST") {
    const authRedirect = requireAuth(request, env);
    if (authRedirect) return authRedirect;
    await unlockAttempt(env.DB, decodeURIComponent(unlockMatch[1]));
    return redirect("/admin/attempts");
  }

  if (path === "/admin/setup" && method === "GET") {
    const authRedirect = requireAuth(request, env);
    if (authRedirect) return authRedirect;
    const origin = url.origin;

    if (env.SIGNING_KEY) {
      return htmlResponse(
        layout("Setup", adminSetup({
          alreadyConfigured: true,
          clientId: env.CLIENT_ID,
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
