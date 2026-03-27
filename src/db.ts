import { ulid } from "./auth";

export interface Profile {
  id: string;
  name: string;
  email: string;
  pin_hash: string;
  pin_salt: string;
  avatar: string;
  created_at: string;
}

export interface AuthCode {
  code: string;
  profile_id: string;
  redirect_uri: string;
  code_challenge: string | null;
  code_challenge_method: string | null;
  expires_at: number;
  used: number;
}

export interface LoginAttempt {
  key: string;
  attempts: number;
  locked_until: string | null;
  updated_at: string;
}

export async function listProfiles(db: D1Database): Promise<Profile[]> {
  const result = await db
    .prepare("SELECT * FROM profiles ORDER BY name ASC")
    .all<Profile>();
  return result.results;
}

export async function getProfile(
  db: D1Database,
  id: string
): Promise<Profile | null> {
  return db
    .prepare("SELECT * FROM profiles WHERE id = ?")
    .bind(id)
    .first<Profile>();
}

export async function createProfile(
  db: D1Database,
  data: {
    name: string;
    email: string;
    pin_hash: string;
    pin_salt: string;
    avatar: string;
  }
): Promise<Profile> {
  const id = ulid();
  await db
    .prepare(
      "INSERT INTO profiles (id, name, email, pin_hash, pin_salt, avatar) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(id, data.name, data.email, data.pin_hash, data.pin_salt, data.avatar)
    .run();
  const profile = await getProfile(db, id);
  if (!profile) throw new Error("Failed to create profile");
  return profile;
}

export async function updateProfile(
  db: D1Database,
  id: string,
  data: Partial<Pick<Profile, "name" | "email" | "avatar" | "pin_hash" | "pin_salt">>
): Promise<void> {
  const fields = Object.keys(data) as Array<keyof typeof data>;
  if (fields.length === 0) return;
  const setClauses = fields.map((f) => `${f} = ?`).join(", ");
  const values = fields.map((f) => data[f]);
  await db
    .prepare(`UPDATE profiles SET ${setClauses} WHERE id = ?`)
    .bind(...values, id)
    .run();
}

export async function deleteProfile(db: D1Database, id: string): Promise<void> {
  await db.prepare("DELETE FROM profiles WHERE id = ?").bind(id).run();
}

export async function createAuthCode(
  db: D1Database,
  data: {
    code: string;
    profile_id: string;
    redirect_uri: string;
    code_challenge?: string;
    code_challenge_method?: string;
  }
): Promise<void> {
  const expiresAt = Math.floor(Date.now() / 1000) + 60;
  await db
    .prepare(
      "INSERT INTO auth_codes (code, profile_id, redirect_uri, code_challenge, code_challenge_method, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(
      data.code,
      data.profile_id,
      data.redirect_uri,
      data.code_challenge ?? null,
      data.code_challenge_method ?? null,
      expiresAt
    )
    .run();
}

export async function consumeAuthCode(
  db: D1Database,
  code: string
): Promise<AuthCode | null> {
  const result = await db
    .prepare(
      "UPDATE auth_codes SET used = 1 WHERE code = ? AND used = 0 AND expires_at > unixepoch() RETURNING *"
    )
    .bind(code)
    .first<AuthCode>();
  return result ?? null;
}

export async function cleanExpiredCodes(db: D1Database): Promise<void> {
  await db
    .prepare("DELETE FROM auth_codes WHERE expires_at < unixepoch() - 300")
    .run();
}

export async function listLoginAttempts(
  db: D1Database
): Promise<LoginAttempt[]> {
  const result = await db
    .prepare(
      "SELECT * FROM login_attempts ORDER BY updated_at DESC LIMIT 50"
    )
    .all<LoginAttempt>();
  return result.results;
}

export async function unlockAttempt(
  db: D1Database,
  key: string
): Promise<void> {
  await db
    .prepare(
      "UPDATE login_attempts SET locked_until = NULL, attempts = 0 WHERE key = ?"
    )
    .bind(key)
    .run();
}

export async function createAdminSession(
  db: D1Database,
  token: string,
  expiresAt: string
): Promise<void> {
  await db
    .prepare("INSERT INTO admin_sessions (token, expires_at) VALUES (?, ?)")
    .bind(token, expiresAt)
    .run();
}

export async function validateAdminSession(
  db: D1Database,
  token: string
): Promise<boolean> {
  const row = await db
    .prepare(
      "SELECT token FROM admin_sessions WHERE token = ? AND expires_at > datetime('now')"
    )
    .bind(token)
    .first();
  return row !== null;
}

export async function cleanExpiredSessions(db: D1Database): Promise<void> {
  await db
    .prepare("DELETE FROM admin_sessions WHERE expires_at < datetime('now')")
    .run();
}

export async function cleanOldAttempts(db: D1Database): Promise<void> {
  await db
    .prepare("DELETE FROM login_attempts WHERE updated_at < datetime('now', '-10 days')")
    .run();
}
