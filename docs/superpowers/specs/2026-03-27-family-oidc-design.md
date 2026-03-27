# Family OIDC Provider — Design Spec

## Context

AI Chatter uses Cloudflare Zero Trust for authentication, which passes the `Cf-Access-Authenticated-User-Email` header to identify users. The adults authenticate via Pocket ID with passkeys, but kids (ages 8–13) can't use this flow. We need a kid-friendly authentication method that integrates with Cloudflare Zero Trust without requiring email or passkeys.

**Solution:** Build a standalone Cloudflare Worker that acts as an OIDC identity provider. Kids see a profile picker with avatars, enter a PIN, and get authenticated through to ai-chatter with a proper email identity.

## Architecture

### OIDC Flow

```
Kid visits ai-chatter.yourdomain.com
  → CF Zero Trust redirects to family-oidc worker
  → GET /authorize renders profile picker + PIN screen
  → Kid selects profile, enters PIN
  → Worker validates PIN, generates auth code
  → Redirects to <team>.cloudflareaccess.com/cdn-cgi/access/callback?code=xxx&state=xxx
  → CF calls POST /token with auth code (server-to-server)
  → Worker returns signed JWT (RS256) with email claim
  → CF sets session cookie, forwards request to ai-chatter
  → ai-chatter sees Cf-Access-Authenticated-User-Email as usual
```

### Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/.well-known/openid-configuration` | GET | OIDC discovery document |
| `/authorize` | GET | Renders profile picker + PIN UI |
| `/authorize` | POST | Validates PIN, issues auth code, redirects to CF callback |
| `/token` | POST | Exchanges auth code for signed ID token (called by CF) |
| `/jwks` | GET | Public RSA key in JWK format for token verification |
| `/admin` | GET | Admin login page |
| `/admin/profiles` | GET/POST | List, create, edit, delete kid profiles |
| `/admin/setup` | GET | First-run: generates RSA keypair, shows client_id/secret for CF config |

### Cloudflare Zero Trust Configuration

Register as **Generic OIDC** identity provider with:
- `client_id`: generated during setup
- `client_secret`: generated during setup
- `auth_url`: `https://family-oidc.yourdomain.com/authorize`
- `token_url`: `https://family-oidc.yourdomain.com/token`
- `certs_url`: `https://family-oidc.yourdomain.com/jwks`
- `email_claim_name`: `email`
- `scopes`: `openid email`

## Data Model

D1 database (`family-oidc-db`) with three tables.

### `profiles`

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | ULID |
| `name` | TEXT NOT NULL | Display name ("Tommy") |
| `email` | TEXT UNIQUE NOT NULL | Identity CF will see (configurable per kid) |
| `pin_hash` | TEXT NOT NULL | Hashed PIN (never plaintext) |
| `avatar` | TEXT NOT NULL | Emoji or short label for profile picker |
| `created_at` | TEXT NOT NULL | ISO timestamp |

### `auth_codes`

| Column | Type | Notes |
|---|---|---|
| `code` | TEXT PK | Random string, single-use |
| `profile_id` | TEXT NOT NULL FK | Which kid authenticated |
| `redirect_uri` | TEXT NOT NULL | The CF callback URL |
| `code_challenge` | TEXT | PKCE challenge (if CF sends one) |
| `expires_at` | INTEGER NOT NULL | Unix timestamp, ~60s TTL |
| `used` | INTEGER NOT NULL DEFAULT 0 | Prevents replay |

### `login_attempts`

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | ULID |
| `profile_id` | TEXT | Which profile (nullable for IP-only tracking) |
| `ip_address` | TEXT NOT NULL | From `CF-Connecting-IP` header |
| `attempts` | INTEGER NOT NULL DEFAULT 0 | Failed count since last reset |
| `locked_until` | TEXT | ISO timestamp, NULL if not locked |

Rate limit triggers if **either** the IP or the profile hits 5 failed attempts. Lockout lasts 15 minutes.

## Endpoint Details

### GET /authorize

Query params (from CF): `client_id`, `redirect_uri`, `response_type=code`, `state`, `scope`, optionally `code_challenge` + `code_challenge_method` (PKCE).

1. Validate `client_id` matches configured value
2. Render HTML: grid of kid profiles (avatar + name)
3. Kid clicks profile → PIN input appears
4. Submit POSTs to `/authorize` with `profile_id`, `pin`, and all original query params

### POST /authorize

1. Check rate limit for IP and profile
2. If locked → render error with remaining lockout time
3. Validate PIN against stored hash
4. If wrong → increment attempts, render error
5. If correct → reset attempts, generate random auth code, store in `auth_codes`, redirect to `redirect_uri?code=xxx&state=xxx`

### POST /token

Called by Cloudflare server-to-server. Body: `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `client_secret` (or Basic auth header).

1. Validate `client_id` and `client_secret`
2. Look up auth code — must exist, not expired, not used, matching redirect_uri
3. Mark code as used
4. Sign JWT (RS256) with claims:
   - `iss`: worker URL
   - `sub`: profile ID
   - `email`: kid's configured email
   - `name`: display name
   - `aud`: client_id
   - `iat`: now
   - `exp`: now + 1 hour
5. Return: `{ access_token, id_token, token_type: "Bearer", expires_in: 3600 }`

### GET /jwks

Returns the public RSA key in standard JWK Set format (`{ keys: [...] }`). Key generated once during setup, private key stored as Worker secret.

## Admin UI

Password-protected via `ADMIN_PASSWORD` Worker secret. Basic auth or cookie session.

**Pages:**
- **Profile list** — all kids with name, email, avatar, actions (edit/delete)
- **Add/edit profile** — form: name, email, avatar, PIN (set/reset)
- **Login attempts** — table of recent attempts by IP and profile, manual unlock button
- **Setup** (first-run only) — generates RSA keypair, displays `client_id` and `client_secret` to copy into CF Zero Trust config

All server-rendered plain HTML with inline CSS. No JS framework.

## Security

- PINs hashed before storage (never plaintext)
- Auth codes: random, single-use, 60-second TTL
- Rate limiting: 5 failed attempts locks out for 15 minutes (per IP and per profile independently)
- IP logged from `CF-Connecting-IP` header
- Admin protected by password
- JWT signed with RS256, private key stored as Worker secret
- Client secret validated on token exchange

## Project Structure

```
family-oidc/
├── src/
│   ├── index.ts          — Worker entry, route dispatch
│   ├── oidc.ts           — discovery, authorize, token, jwks endpoints
│   ├── admin.ts          — admin UI routes
│   ├── auth.ts           — PIN hashing, rate limiting, code generation
│   ├── jwt.ts            — JWT signing with Web Crypto API, JWK export
│   ├── db.ts             — D1 queries
│   └── html.ts           — HTML template helpers
├── migrations/
│   └── 0001_init.sql     — profiles, auth_codes, login_attempts tables
├── wrangler.jsonc
├── package.json
└── tsconfig.json
```

No build step beyond wrangler. TypeScript compiled at deploy time. Uses Web Crypto API for RSA key generation and JWT signing (no external crypto dependencies).

## Worker Secrets & Bindings

- `ADMIN_PASSWORD` — secret, for admin UI access
- `CLIENT_ID` — secret, generated during setup
- `CLIENT_SECRET` — secret, generated during setup
- `SIGNING_KEY` — secret, RSA private key (JWK format)
- `DB` — D1 binding to `family-oidc-db`

## Verification Plan

1. Deploy worker, visit `/admin/setup` to generate keys and get client credentials
2. Add a test kid profile via `/admin/profiles`
3. Register as Generic OIDC in CF Zero Trust dashboard with the worker's URLs
4. Hit "Test" in CF Zero Trust — should redirect to profile picker
5. Select profile, enter correct PIN — should redirect back to CF with success
6. Visit ai-chatter — kid's configured email should appear as the authenticated user
7. Test wrong PIN 5 times — should get locked out for 15 minutes
8. Test expired/replayed auth codes — token endpoint should reject them
9. Verify admin UI shows login attempts with IP addresses
