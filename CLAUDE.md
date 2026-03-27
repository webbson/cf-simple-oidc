# cf-simple-oidc

Minimal OIDC identity provider for Cloudflare Zero Trust. Designed for kid-friendly PIN-based auth — kids pick their profile avatar and enter a PIN instead of using email/passkeys.

## Commands

```bash
pnpm dev              # Dev server (wrangler dev)
pnpm build            # Not needed — wrangler compiles TS at deploy time
pnpm run deploy       # wrangler deploy
pnpm typecheck        # tsc --noEmit
```

## Stack

- Cloudflare Worker (TypeScript, no framework)
- D1 (SQLite) for profiles, auth codes, login attempts
- Web Crypto API for RSA key generation, JWT signing, PIN hashing (PBKDF2)
- Plain HTML/CSS — no frontend build step, no JS framework

## Architecture

Single Worker with two route groups:

1. **OIDC endpoints** (`src/oidc.ts`) — standard OIDC provider protocol
   - `/.well-known/openid-configuration` — discovery doc
   - `/authorize` — GET shows profile picker, POST validates PIN and redirects with auth code
   - `/token` — exchanges auth code for signed JWT (called by Cloudflare server-to-server)
   - `/jwks` — public key for token verification

2. **Admin UI** (`src/admin.ts`) — password-protected profile management
   - `/admin` — profile list
   - `/admin/profiles/new`, `/admin/profiles/:id` — CRUD
   - `/admin/attempts` — rate limit monitoring + unlock
   - `/admin/setup` — first-run key generation, shows CF Zero Trust config values

### Key Files

- `src/index.ts` — Worker entry, route dispatch, Env type definition
- `src/oidc.ts` — OIDC protocol endpoints
- `src/admin.ts` — Admin UI routes
- `src/jwt.ts` — RSA keypair generation, JWT signing (RS256), JWKS export
- `src/auth.ts` — PIN hashing (PBKDF2), rate limiting, auth code generation, ULID
- `src/db.ts` — All D1 queries (single DB access layer)
- `src/html.ts` — Server-rendered HTML templates

### OIDC Flow

```
Kid visits protected app → CF Zero Trust redirects to /authorize
→ Profile picker (avatars) → PIN entry → auth code generated
→ Redirect to CF callback → CF calls /token → signed JWT returned
→ CF sets session, forwards to app with Cf-Access-Authenticated-User-Email header
```

## Database

D1 (SQLite). Tables: `profiles`, `auth_codes`, `login_attempts`.

Run migration:
```bash
wrangler d1 execute family-oidc-db --local --file=migrations/0001_init.sql
```

## Environment

- `.dev.vars` — `ADMIN_PASSWORD`, `CLIENT_ID`, `CLIENT_SECRET`, `SIGNING_KEY` (see `.dev.vars.example`)
- `wrangler.jsonc` — D1 binding (see `wrangler.jsonc.example`)
- Secrets in prod: `wrangler secret put <NAME>`

## Gotchas

- Use global wrangler, never add as project dependency
- Use pnpm, not npm or yarn
- `wrangler.jsonc` and `.dev.vars` are gitignored — use the `.example` files
- SIGNING_KEY is an RSA private key in JWK JSON format — generate via `/admin/setup`
- Auth codes are single-use, 60-second TTL — consumed atomically via `UPDATE ... RETURNING`
- Rate limiting uses key-based rows (`ip:<addr>` or `profile:<id>`) for clean ON CONFLICT upserts
- PIN hashing uses PBKDF2 with SHA-256, 100k iterations, 16-byte random salt
- Admin session is a cookie storing the password — acceptable for a family admin panel over HTTPS
- The `profilePicker` links to `/authorize/pin/:id` but the PIN form POSTs back to `/authorize` — the GET path with `/pin/` is just for displaying the PIN entry screen for a specific profile
