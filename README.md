# cf-simple-oidc

A minimal OIDC identity provider running on Cloudflare Workers. Built for family use — lets kids authenticate to Cloudflare Zero Trust by picking their profile and entering a PIN, no email or passkeys required.

## How It Works

1. Kid visits a Zero Trust-protected app (e.g., a chat app)
2. Cloudflare redirects to this OIDC provider
3. Kid sees profile avatars, taps theirs, enters a 4-6 digit PIN
4. On success, they're redirected back and authenticated with a configurable email identity
5. The protected app sees them as a normal authenticated user via `Cf-Access-Authenticated-User-Email`

## Features

- **Kid-friendly UI** — large touch-friendly profile cards with emoji avatars
- **PIN authentication** — no passwords, no email, no passkeys
- **Rate limiting** — locks out after 5 failed attempts (per IP and per profile)
- **Admin panel** — manage profiles, reset PINs, view/unlock login attempts
- **Standard OIDC** — works with Cloudflare Zero Trust's Generic OIDC integration
- **Zero dependencies** — uses Web Crypto API for all crypto (RSA, PBKDF2, JWT)
- **Single Worker** — no external services, just D1 for storage

## Deployment

### Prerequisites

- A Cloudflare account with Zero Trust enabled
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) installed globally
- [pnpm](https://pnpm.io/) for package management

### 1. Clone and install

```bash
git clone <repo-url> cf-simple-oidc
cd cf-simple-oidc
pnpm install
```

### 2. Create D1 database

```bash
wrangler d1 create family-oidc-db
```

Copy the database ID from the output.

### 3. Configure wrangler

```bash
cp wrangler.jsonc.example wrangler.jsonc
```

Edit `wrangler.jsonc` and replace `YOUR_DATABASE_ID` with the ID from step 2. Optionally set a custom domain under `routes`.

### 4. Run migration

```bash
# Remote (production)
wrangler d1 execute family-oidc-db --remote --file=migrations/0001_init.sql
```

### 5. Deploy

```bash
pnpm run deploy
```

### 6. Set admin password

```bash
wrangler secret put ADMIN_PASSWORD
```

Enter a strong password — this protects the admin panel.

### 7. Generate OIDC credentials

1. Visit `https://your-worker.your-domain.workers.dev/admin/login`
2. Log in with your admin password
3. Go to **Setup**
4. Copy the generated **Client ID**, **Client Secret**, and **SIGNING_KEY**
5. Store them as secrets:

```bash
wrangler secret put CLIENT_ID
wrangler secret put CLIENT_SECRET
wrangler secret put SIGNING_KEY
```

> Paste the full JSON blob for SIGNING_KEY (it's an RSA private key in JWK format).

### 8. Register in Cloudflare Zero Trust

1. Go to [Cloudflare One](https://one.dash.cloudflare.com) > **Integrations** > **Identity providers**
2. Select **Add new identity provider** > **OpenID Connect**
3. Enter the values from the Setup page:

| Field | Value |
|---|---|
| Name | Family OIDC (or whatever you like) |
| Client ID | From setup page |
| Client Secret | From setup page |
| Auth URL | `https://your-worker.your-domain.workers.dev/authorize` |
| Token URL | `https://your-worker.your-domain.workers.dev/token` |
| Certificate URL | `https://your-worker.your-domain.workers.dev/jwks` |
| Email claim | `email` |

4. Click **Test** — it should redirect to the profile picker
5. Save the provider

### 9. Add kid profiles

1. Go to `/admin` > **Add Profile**
2. Enter: name, email (any email — this becomes their identity), avatar emoji, PIN
3. Repeat for each kid

### 10. Configure Access policy

In your Zero Trust application policy, add the Family OIDC provider as an allowed identity provider. You can restrict by email to only allow your configured kid emails.

## Local Development

```bash
cp .dev.vars.example .dev.vars
cp wrangler.jsonc.example wrangler.jsonc
```

Edit `.dev.vars` with test values. Generate a signing key:

```bash
node -e "
(async () => {
  const kp = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']
  );
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  jwk.kid = 'default'; jwk.alg = 'RS256'; jwk.use = 'sig';
  console.log(JSON.stringify(jwk));
})();
"
```

Paste the output as the `SIGNING_KEY` value in `.dev.vars`.

Run the local D1 migration and start the dev server:

```bash
wrangler d1 execute family-oidc-db --local --file=migrations/0001_init.sql
pnpm dev
```

## Security Notes

- PINs are hashed with PBKDF2 (SHA-256, 100k iterations, random salt) — never stored in plaintext
- Auth codes are single-use with 60-second TTL
- Rate limiting locks out after 5 failed attempts for 15 minutes (tracked per IP and per profile)
- JWTs are signed with RS256 (2048-bit RSA)
- Admin panel is password-protected with HttpOnly/Secure/SameSite cookies
- This is designed for family/small-group use, not enterprise deployment
