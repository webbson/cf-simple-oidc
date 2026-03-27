const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function hexEncode(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexDecode(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

async function deriveKey(pin: string, salt: Uint8Array): Promise<ArrayBuffer> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pin),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  return crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 100_000 },
    keyMaterial,
    256
  );
}

export async function hashPin(pin: string): Promise<{ hash: string; salt: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derived = await deriveKey(pin, salt);
  return { hash: hexEncode(derived), salt: hexEncode(salt.buffer) };
}

export async function verifyPin(pin: string, hash: string, salt: string): Promise<boolean> {
  const derived = await deriveKey(pin, hexDecode(salt));
  return hexEncode(derived) === hash;
}

export function generateAuthCode(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

export function generateClientCredentials(): { clientId: string; clientSecret: string } {
  return {
    clientId: crypto.randomUUID(),
    clientSecret: crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, ""),
  };
}

export function ulid(): string {
  let t = Date.now();
  let timestamp = "";
  for (let i = 0; i < 10; i++) {
    timestamp = CROCKFORD[t % 32] + timestamp;
    t = Math.floor(t / 32);
  }
  const randBytes = crypto.getRandomValues(new Uint8Array(16));
  let randomPart = "";
  for (let i = 0; i < 16; i++) {
    randomPart += CROCKFORD[randBytes[i] % 32];
  }
  return timestamp + randomPart;
}

export interface RateLimitResult {
  allowed: boolean;
  lockedUntil?: string;
  remainingMinutes?: number;
  remainingAttempts?: number;
}

function ipKey(ip: string): string {
  return `ip:${ip}`;
}

function profileKey(profileId: string): string {
  return `profile:${profileId}`;
}

function minutesUntil(isoDate: string): number {
  const diff = new Date(isoDate + "Z").getTime() - Date.now();
  return Math.max(1, Math.ceil(diff / 60_000));
}

export async function checkRateLimit(
  db: D1Database,
  profileId: string | null,
  ip: string
): Promise<RateLimitResult> {
  const keys = [ipKey(ip)];
  if (profileId) keys.push(profileKey(profileId));

  const placeholders = keys.map(() => "?").join(", ");
  const row = await db
    .prepare(
      `SELECT locked_until FROM login_attempts
       WHERE key IN (${placeholders}) AND locked_until > datetime('now')
       ORDER BY locked_until DESC LIMIT 1`
    )
    .bind(...keys)
    .first<{ locked_until: string }>();

  if (row) {
    return {
      allowed: false,
      lockedUntil: row.locked_until,
      remainingMinutes: minutesUntil(row.locked_until),
    };
  }

  return { allowed: true };
}

export async function recordFailedAttempt(
  db: D1Database,
  profileId: string,
  ip: string
): Promise<RateLimitResult> {
  const now = new Date().toISOString().replace("Z", "");

  await db.batch([
    db
      .prepare(
        `INSERT INTO login_attempts (key, attempts, updated_at)
         VALUES (?, 1, ?)
         ON CONFLICT(key) DO UPDATE SET
           attempts = login_attempts.attempts + 1,
           locked_until = CASE WHEN login_attempts.attempts + 1 >= 5
             THEN datetime('now', '+15 minutes') ELSE login_attempts.locked_until END,
           updated_at = excluded.updated_at`
      )
      .bind(ipKey(ip), now),
    db
      .prepare(
        `INSERT INTO login_attempts (key, attempts, updated_at)
         VALUES (?, 1, ?)
         ON CONFLICT(key) DO UPDATE SET
           attempts = login_attempts.attempts + 1,
           locked_until = CASE WHEN login_attempts.attempts + 1 >= 5
             THEN datetime('now', '+15 minutes') ELSE login_attempts.locked_until END,
           updated_at = excluded.updated_at`
      )
      .bind(profileKey(profileId), now),
  ]);

  const row = await db
    .prepare(
      `SELECT attempts, locked_until FROM login_attempts
       WHERE key IN (?, ?)
       ORDER BY attempts DESC LIMIT 1`
    )
    .bind(ipKey(ip), profileKey(profileId))
    .first<{ attempts: number; locked_until: string | null }>();

  if (row?.locked_until) {
    return {
      allowed: false,
      lockedUntil: row.locked_until,
      remainingMinutes: minutesUntil(row.locked_until),
    };
  }

  return {
    allowed: true,
    remainingAttempts: row ? Math.max(0, 5 - row.attempts) : 4,
  };
}

export async function resetAttempts(
  db: D1Database,
  profileId: string,
  ip: string
): Promise<void> {
  await db.batch([
    db.prepare(`DELETE FROM login_attempts WHERE key = ?`).bind(ipKey(ip)),
    db.prepare(`DELETE FROM login_attempts WHERE key = ?`).bind(profileKey(profileId)),
  ]);
}
