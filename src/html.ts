const baseStyles = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
    background: #EEF2F7;
    min-height: 100vh;
    color: #1a1a2e;
  }
  a { color: #4A90D9; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .card {
    background: #fff;
    border-radius: 16px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.08);
    padding: 2rem;
  }
  .btn {
    display: inline-block;
    background: #4A90D9;
    color: #fff;
    border: none;
    border-radius: 10px;
    padding: 0.75rem 2rem;
    font-size: 1.1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
  }
  .btn:hover { background: #357ABD; }
  .btn-danger { background: #E05252; }
  .btn-danger:hover { background: #C0392B; }
  .btn-sm { padding: 0.4rem 1rem; font-size: 0.9rem; border-radius: 8px; }
  .error-box {
    background: #FFF0F0;
    border: 1px solid #F5C6C6;
    color: #C0392B;
    border-radius: 10px;
    padding: 0.75rem 1rem;
    margin-bottom: 1.25rem;
    font-weight: 500;
  }
  .center { text-align: center; }
  input[type="text"], input[type="email"], input[type="password"] {
    width: 100%;
    padding: 0.65rem 1rem;
    border: 1.5px solid #D0DCE8;
    border-radius: 8px;
    font-size: 1rem;
    outline: none;
    transition: border-color 0.15s;
  }
  input:focus { border-color: #4A90D9; }
  label { display: block; font-weight: 600; margin-bottom: 0.3rem; font-size: 0.95rem; }
  .field { margin-bottom: 1rem; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 0.6rem 0.75rem; border-bottom: 2px solid #D0DCE8; font-size: 0.9rem; color: #555; }
  td { padding: 0.6rem 0.75rem; border-bottom: 1px solid #EEF2F7; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
`;

const navHtml = `
  <nav style="background:#fff;border-bottom:1px solid #D0DCE8;padding:0.75rem 2rem;display:flex;gap:1.5rem;align-items:center;">
    <strong style="color:#4A90D9;font-size:1.1rem;">OIDC Admin</strong>
    <a href="/admin">Profiles</a>
    <a href="/admin/attempts">Login Attempts</a>
    <a href="/admin/setup">Setup</a>
  </nav>
`;

function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function layout(title: string, body: string, options?: { hideNav?: boolean }): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escHtml(title)}</title>
  <style>${baseStyles}</style>
</head>
<body>
  ${options?.hideNav ? "" : navHtml}
  ${body}
</body>
</html>`;
}

export function profilePicker(
  profiles: Array<{ id: string; name: string; avatar: string }>,
  queryString: string,
  error?: string
): string {
  const qs = queryString.startsWith("?") ? queryString : `?${queryString}`;
  const errorHtml = error ? `<div class="error-box">${escHtml(error)}</div>` : "";
  const cards = profiles
    .map(
      (p) => `
    <a href="/authorize/pin/${escHtml(p.id)}${qs}" style="text-decoration:none;">
      <div style="
        background:#fff;
        border-radius:20px;
        box-shadow:0 4px 16px rgba(0,0,0,0.08);
        padding:2rem 1.5rem;
        display:flex;
        flex-direction:column;
        align-items:center;
        gap:0.75rem;
        cursor:pointer;
        transition:transform 0.12s,box-shadow 0.12s;
        min-width:140px;
      "
      onmouseover="this.style.transform='translateY(-4px)';this.style.boxShadow='0 8px 28px rgba(74,144,217,0.18)'"
      onmouseout="this.style.transform='';this.style.boxShadow='0 4px 16px rgba(0,0,0,0.08)'">
        <span style="font-size:3.5rem;line-height:1;">${escHtml(p.avatar)}</span>
        <span style="font-size:1.1rem;font-weight:700;color:#1a1a2e;">${escHtml(p.name)}</span>
      </div>
    </a>`
    )
    .join("");

  return `
    <div style="max-width:700px;margin:3rem auto;padding:0 1rem;">
      <div class="card">
        <h1 style="text-align:center;margin-bottom:0.5rem;font-size:1.8rem;">Who are you?</h1>
        <p style="text-align:center;color:#666;margin-bottom:1.5rem;">Tap your picture to sign in</p>
        ${errorHtml}
        <div style="display:flex;flex-wrap:wrap;gap:1.25rem;justify-content:center;">
          ${cards}
        </div>
      </div>
    </div>`;
}

export function pinEntry(
  profile: { id: string; name: string; avatar: string },
  queryString: string,
  error?: string
): string {
  const qs = queryString.startsWith("?") ? queryString : `?${queryString}`;
  const params = new URLSearchParams(queryString.replace(/^\?/, ""));
  const hiddenFields = [
    "client_id",
    "redirect_uri",
    "response_type",
    "state",
    "scope",
    "code_challenge",
    "code_challenge_method",
  ]
    .map((k) => {
      const v = params.get(k);
      return v ? `<input type="hidden" name="${escHtml(k)}" value="${escHtml(v)}" />` : "";
    })
    .join("");
  const errorHtml = error ? `<div class="error-box">${escHtml(error)}</div>` : "";

  return `
    <div style="max-width:420px;margin:3rem auto;padding:0 1rem;">
      <div class="card center">
        <span style="font-size:4rem;line-height:1;display:block;margin-bottom:0.5rem;">${escHtml(profile.avatar)}</span>
        <h2 style="margin-bottom:1.5rem;font-size:1.5rem;">${escHtml(profile.name)}</h2>
        ${errorHtml}
        <form method="POST" action="/authorize">
          <input type="hidden" name="profile_id" value="${escHtml(profile.id)}" />
          ${hiddenFields}
          <div class="field">
            <label for="pin">Enter your PIN</label>
            <input
              id="pin"
              name="pin"
              type="password"
              inputmode="numeric"
              pattern="[0-9]*"
              autocomplete="current-password"
              style="font-size:2rem;letter-spacing:0.5rem;text-align:center;"
              required
              autofocus
            />
          </div>
          <button type="submit" class="btn" style="width:100%;margin-top:0.5rem;">Sign In</button>
        </form>
        <p style="margin-top:1.25rem;">
          <a href="/authorize${qs}">&larr; Back</a>
        </p>
      </div>
    </div>`;
}

export function lockoutPage(remainingMinutes: number): string {
  return `
    <div style="max-width:420px;margin:4rem auto;padding:0 1rem;">
      <div class="card center">
        <div style="font-size:3rem;margin-bottom:1rem;">&#x1F512;</div>
        <h2 style="margin-bottom:0.75rem;">Too many attempts!</h2>
        <p style="color:#555;font-size:1.1rem;">
          Please try again in <strong>${remainingMinutes} minute${remainingMinutes === 1 ? "" : "s"}</strong>.
        </p>
      </div>
    </div>`;
}

export function adminLogin(error?: string): string {
  const errorHtml = error ? `<div class="error-box">${escHtml(error)}</div>` : "";

  return `
    <div style="max-width:380px;margin:4rem auto;padding:0 1rem;">
      <div class="card">
        <h2 style="margin-bottom:1.5rem;text-align:center;">Admin Login</h2>
        ${errorHtml}
        <form method="POST" action="/admin/login">
          <div class="field">
            <label for="password">Password</label>
            <input id="password" name="password" type="password" required autofocus />
          </div>
          <button type="submit" class="btn" style="width:100%;">Login</button>
        </form>
      </div>
    </div>`;
}

export function adminProfileList(
  profiles: Array<{ id: string; name: string; email: string; avatar: string; created_at: string }>
): string {
  const rows = profiles
    .map(
      (p) => `
    <tr>
      <td style="font-size:1.5rem;">${escHtml(p.avatar)}</td>
      <td>${escHtml(p.name)}</td>
      <td>${escHtml(p.email)}</td>
      <td style="font-size:0.85rem;color:#666;">${escHtml(p.created_at)}</td>
      <td>
        <a href="/admin/profiles/${escHtml(p.id)}" class="btn btn-sm" style="margin-right:0.4rem;">Edit</a>
        <form method="POST" action="/admin/profiles/${escHtml(p.id)}/delete" style="display:inline;"
          onsubmit="return confirm('Delete ${escHtml(p.name)}?')">
          <button type="submit" class="btn btn-sm btn-danger">Delete</button>
        </form>
      </td>
    </tr>`
    )
    .join("");

  return `
    <div style="max-width:900px;margin:2rem auto;padding:0 1rem;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem;">
        <h2>Profiles</h2>
        <a href="/admin/profiles/new" class="btn">+ Add Profile</a>
      </div>
      <div class="card" style="padding:0;overflow:hidden;">
        <table>
          <thead>
            <tr>
              <th>Avatar</th><th>Name</th><th>Email</th><th>Created</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
}

export function adminProfileForm(
  profile?: { id: string; name: string; email: string; avatar: string } | null,
  error?: string
): string {
  const isEdit = profile != null;
  const action = isEdit ? `/admin/profiles/${escHtml(profile.id)}` : "/admin/profiles/new";
  const title = isEdit ? "Edit Profile" : "Add Profile";
  const errorHtml = error ? `<div class="error-box">${escHtml(error)}</div>` : "";

  return `
    <div style="max-width:480px;margin:2rem auto;padding:0 1rem;">
      <div style="margin-bottom:1rem;">
        <a href="/admin">&larr; Back to Profiles</a>
      </div>
      <div class="card">
        <h2 style="margin-bottom:1.5rem;">${escHtml(title)}</h2>
        ${errorHtml}
        <form method="POST" action="${action}">
          <div class="field">
            <label for="name">Name</label>
            <input id="name" name="name" type="text" required value="${isEdit ? escHtml(profile.name) : ""}" />
          </div>
          <div class="field">
            <label for="email">Email</label>
            <input id="email" name="email" type="text" required value="${isEdit ? escHtml(profile.email) : ""}" />
          </div>
          <div class="field">
            <label for="avatar">Avatar</label>
            <input id="avatar" name="avatar" type="text" placeholder="Enter an emoji" required value="${isEdit ? escHtml(profile.avatar) : ""}" />
          </div>
          <div class="field">
            <label for="pin">PIN${isEdit ? " (leave blank to keep current)" : ""}</label>
            <input id="pin" name="pin" type="password" inputmode="numeric" pattern="[0-9]*" ${isEdit ? "" : "required"} />
          </div>
          <button type="submit" class="btn" style="width:100%;">${isEdit ? "Save Changes" : "Create Profile"}</button>
        </form>
      </div>
    </div>`;
}

export function adminAttempts(
  attempts: Array<{
    key: string;
    attempts: number;
    locked_until: string | null;
    updated_at: string;
  }>
): string {
  const rows = attempts
    .map((a) => {
      const lockedCell = a.locked_until
        ? `<span style="color:#E05252;font-weight:600;">${escHtml(a.locked_until)}</span>`
        : '<span style="color:#888;">&mdash;</span>';
      const unlockBtn = a.locked_until
        ? `<form method="POST" action="/admin/attempts/${encodeURIComponent(a.key)}/unlock" style="display:inline;">
             <button type="submit" class="btn btn-sm">Unlock</button>
           </form>`
        : "";
      return `
      <tr>
        <td><code>${escHtml(a.key)}</code></td>
        <td>${a.attempts}</td>
        <td>${lockedCell}</td>
        <td style="font-size:0.82rem;color:#666;">${escHtml(a.updated_at)}</td>
        <td>${unlockBtn}</td>
      </tr>`;
    })
    .join("");

  return `
    <div style="max-width:960px;margin:2rem auto;padding:0 1rem;">
      <h2 style="margin-bottom:1.25rem;">Login Attempts</h2>
      <div class="card" style="padding:0;overflow:hidden;">
        <table>
          <thead>
            <tr>
              <th>Key</th><th>Attempts</th><th>Locked Until</th><th>Last Updated</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
}

export interface SetupData {
  alreadyConfigured: boolean;
  clientId: string;
  clientSecret?: string;
  signingKey?: string;
  authUrl: string;
  tokenUrl: string;
  certsUrl: string;
}

export function adminSetup(data: SetupData): string {
  function row(label: string, value: string): string {
    return `
      <tr>
        <td style="font-weight:600;white-space:nowrap;padding-right:1rem;">${escHtml(label)}</td>
        <td><code style="background:#EEF2F7;padding:0.25rem 0.5rem;border-radius:6px;font-size:0.95rem;word-break:break-all;">${escHtml(value)}</code></td>
      </tr>`;
  }

  const secretRows = data.alreadyConfigured
    ? ""
    : `
      ${row("Client Secret", data.clientSecret ?? "")}
      ${data.signingKey ? row("SIGNING_KEY", data.signingKey) : ""}`;

  const warning = data.alreadyConfigured
    ? `<div style="background:#E8F5E9;border:1px solid #A5D6A7;border-radius:10px;padding:1rem 1.25rem;color:#2E7D32;">
        <strong>Setup complete.</strong> Your OIDC provider is configured. Store secrets via <code>wrangler secret put</code>.
      </div>`
    : `<div style="background:#FFF8E1;border:1px solid #FFE082;border-radius:10px;padding:1rem 1.25rem;color:#7A5C00;">
        <strong>Important:</strong> Copy these values now. Store them as Worker secrets:<br/>
        <code>wrangler secret put CLIENT_ID</code><br/>
        <code>wrangler secret put CLIENT_SECRET</code><br/>
        <code>wrangler secret put SIGNING_KEY</code>
      </div>`;

  return `
    <div style="max-width:680px;margin:2rem auto;padding:0 1rem;">
      <h2 style="margin-bottom:1.25rem;">OIDC Setup</h2>
      <div class="card" style="margin-bottom:1.5rem;">
        <h3 style="margin-bottom:1rem;">Cloudflare Zero Trust Configuration</h3>
        <p style="color:#555;margin-bottom:1rem;">Enter these values when adding a Generic OIDC provider in Zero Trust.</p>
        <table>
          <tbody>
            ${row("Auth URL", data.authUrl)}
            ${row("Token URL", data.tokenUrl)}
            ${row("Certs URL", data.certsUrl)}
            ${row("Client ID", data.clientId)}
            ${secretRows}
          </tbody>
        </table>
      </div>
      ${warning}
    </div>`;
}
