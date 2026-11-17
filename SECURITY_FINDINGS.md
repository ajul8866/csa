# Security Review Findings — ajul8866/csa

Validated MEDIUM+ issues with complete attack chains. Verified via source tracing (not live exploitation).

---

## CRITICAL-01 — Unauthenticated arbitrary file read/write (Next.js web API)

| Field | Value |
| --- | --- |
| Severity | CRITICAL |
| Location | `web/app/api/files/read/route.ts` (also `web/app/api/files/write/route.ts`) |
| Title | Unauthenticated filesystem read/write via `/api/files/*` |
| Verified | Yes — code tracing |

**Description:** The Next.js App Router handlers accept a caller-controlled `path`, resolve it with `path.resolve`, and read/write with no authentication, no allowlist, and no root jail. There is no `middleware.ts`.

**Impact:** Remote arbitrary file read (secrets, keys, source) and arbitrary file write (RCE via overwriting startup scripts, `authorized_keys`, app code, etc.) on any host that serves the `web/` Next app.

**Attack path:**
1. Attacker sends `GET /api/files/read?path=/etc/passwd` (or any absolute path).
2. Or `POST /api/files/write` with `{"path":"/home/ubuntu/.ssh/authorized_keys","content":"..."}`.
3. Server performs `fs.readFile` / `fs.writeFile` on the resolved path and returns success/content.

**Evidence:**
```21:44:web/app/api/files/read/route.ts
  const resolvedPath = path.resolve(filePath);
  // ...
      const buffer = await fs.readFile(resolvedPath);
  // ...
    const content = await fs.readFile(resolvedPath, "utf-8");
```
```21:24:web/app/api/files/write/route.ts
  const resolvedPath = path.resolve(filePath);
  try {
    await fs.writeFile(resolvedPath, content, "utf-8");
```

**Remediation:** Require auth; jail all paths under a configured workspace root using `path.resolve` + `rel.startsWith(root + sep)`; deny absolute paths and `..`; disable write in production unless explicitly needed.

---

## CRITICAL-02 — PTY spawn copies full `process.env` into every user session

| Field | Value |
| --- | --- |
| Severity | CRITICAL |
| Location | `src/server/web/pty-server.ts` |
| Title | Multi-tenant secret disclosure via PTY environment inheritance |
| Verified | Yes — code tracing |

**Description:** Every WebSocket-backed PTY is spawned with `env: { ...process.env, ... }`. In OAuth/token multi-user mode this exposes server secrets (`OAUTH_CLIENT_SECRET`, `SESSION_SECRET`, `AUTH_TOKEN`, `ANTHROPIC_API_KEY`, cloud creds, etc.) to every authenticated tenant. Claude Code’s BashTool (or any subprocess) can read them.

**Impact:** Full compromise of server credentials; session forgery (`SESSION_SECRET`); OAuth app takeover; Anthropic key theft/billing abuse; lateral movement via cloud env vars.

**Attack path:**
1. Deploy PTY server with `AUTH_PROVIDER=oauth` (or token) and secrets in the process environment.
2. Attacker authenticates as a normal user and opens `/ws`.
3. In the Claude session, run Bash: `printenv` / `env | grep -E 'SECRET|TOKEN|KEY|AWS'`.
4. Use stolen `SESSION_SECRET` / `OAUTH_CLIENT_SECRET` / API keys as needed.

**Evidence:**
```83:96:src/server/web/pty-server.ts
    return spawn(CLAUDE_BIN, [], {
      name: "xterm-256color",
      cols,
      rows,
      cwd: process.env.WORK_DIR ?? home,
      env: {
        ...process.env,
        TERM: "xterm-256color",
        COLORTERM: "truecolor",
        HOME: home,
        ...(user?.apiKey ? { ANTHROPIC_API_KEY: user.apiKey } : {}),
      },
    });
```

**Remediation:** Build a minimal allowlisted env for PTY children; never forward `*_SECRET`, `*_TOKEN`, `SESSION_SECRET`, provider client secrets, or host cloud credentials. Inject only per-user `ANTHROPIC_API_KEY` (apikey mode) or a dedicated scoped key.

---

## CRITICAL-03 — Default bind `0.0.0.0` with optional auth → unauthenticated RCE

| Field | Value |
| --- | --- |
| Severity | CRITICAL |
| Location | `src/server/web/pty-server.ts` |
| Title | Insecure defaults: public bind + auth optional admits admin PTY |
| Verified | Yes — code tracing |

**Description:** `HOST` defaults to `0.0.0.0`. Default `AUTH_PROVIDER=token` with unset `AUTH_TOKEN` authenticates every caller as `id: "default", isAdmin: true`. Docker Compose publishes port 3000 and does not require `AUTH_TOKEN`. A reachable PTY is interactive Claude Code (shell via tools) = RCE.

**Impact:** Unauthenticated remote code execution on the host/container; admin API access; use of the server’s `ANTHROPIC_API_KEY`.

**Attack path:**
1. Operator runs `docker compose up` / `pty-server` without `AUTH_TOKEN` (documented default path).
2. Attacker connects to `ws://<host>:3000/ws` with no credentials.
3. `TokenAuthAdapter.authenticate` returns admin user; session is created; attacker drives Claude/Bash on the server.

**Evidence:**
```20:31:src/server/web/pty-server.ts
const PORT = parseInt(process.env.PORT ?? "3000", 10);
const HOST = process.env.HOST ?? "0.0.0.0";
// ...
const AUTH_PROVIDER = process.env.AUTH_PROVIDER ?? "token";
```
```30:33:src/server/web/auth/token-auth.ts
  authenticate(req: IncomingMessage): AuthUser | null {
    if (!this.token) {
      return { id: "default", isAdmin: true };
    }
```
```7:11:docker/docker-compose.yml
    ports:
      - "${PORT:-3000}:3000"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - AUTH_TOKEN=${AUTH_TOKEN:-}
```

**Remediation:** Default `HOST=127.0.0.1`; refuse to listen when `AUTH_TOKEN`/OAuth/API-key auth is unset in non-dev; make entrypoint fail closed without auth; keep Compose from publishing without auth.

---

## HIGH-01 — Stored XSS in admin dashboard (OAuth name/email/userId)

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Location | `src/server/web/admin.ts` |
| Title | Stored XSS via unsanitized user fields in admin `innerHTML` |
| Verified | Yes — code tracing |

**Description:** `/admin` builds table rows with `innerHTML`, interpolating `u.id`, `u.email`, `u.name`, and `s.userId` with no HTML encoding. OAuth `name`/`email`/`sub` flow into `userStore.touch` then `/admin/users`.

**Impact:** Any authenticated OAuth user can execute JS in an admin’s browser: kill sessions, call admin APIs, phishing, further pivoting (HttpOnly blocks cookie theft but same-origin credentialed fetches work).

**Attack path:**
1. Attacker sets IdP display name / email local-part (or `sub` where allowed) to `"><img src=x onerror="fetch('/admin/sessions/'+id,{method:'DELETE'})">`.
2. Attacker opens a WebSocket session so `userStore.touch` persists the payload.
3. Admin loads `/admin`; `load()` assigns attacker strings into `innerHTML`.
4. Payload runs with admin privileges.

**Evidence:**
```161:167:src/server/web/admin.ts
      ub.innerHTML = users.length === 0 ? '<tr><td colspan="4">No connected users</td></tr>' :
        users.map(u => \`<tr>
          <td><code>\${u.id}</code></td>
          <td>\${u.email || u.name || '—'}</td>
          <td><span class="badge">\${u.sessionCount}</span></td>
          <td>\${new Date(u.firstSeenAt).toLocaleTimeString()}</td>
        </tr>\`).join('');
```
```274:275:src/server/web/pty-server.ts
    userStore.touch(user.id, { email: user.email, name: user.name });
```

**Remediation:** Stop using `innerHTML` for untrusted data; use `textContent`/DOM APIs; HTML-encode all interpolated values; set a strict CSP.

---

## HIGH-02 — `userHomeDir` path traversal via unsanitized `userId`

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Location | `src/server/web/pty-server.ts` |
| Title | Path traversal in per-user HOME via OAuth `sub` |
| Verified | Yes — code tracing |

**Description:** `userHomeDir` does `path.join(USER_HOME_BASE, userId)` with no sanitization. OAuth sets `user.id` from IdP `sub`. Values like `../otheruser` or `../../tmp/pwn` escape the home base (`path.join('/home/claude/users','../../root')` → `/home/root`).

**Impact:** Cross-tenant home access/overwrite; writing `.claude` outside the intended base; privilege boundary break in multi-user OAuth deployments (esp. custom OIDC where `sub`/username can contain `/` or `..`).

**Attack path:**
1. Authenticate via OAuth with `sub` containing path separators (custom IdP, misissued subject, etc.).
2. Open `/ws`; server sets `HOME` / cwd to the traversed path and `mkdirSync(..., { recursive: true })`.
3. Attacker reads/writes another user’s files or escapes the users directory.

**Evidence:**
```68:75:src/server/web/pty-server.ts
function userHomeDir(userId: string): string {
  const dir = path.join(USER_HOME_BASE, userId);
  try {
    mkdirSync(path.join(dir, ".claude"), { recursive: true });
  } catch {
    // Already exists or no permission — fail silently; PTY spawn will surface any real issue.
  }
  return dir;
}
```
```192:197:src/server/web/auth/oauth-auth.ts
        const sessionId = this.store.create({
          userId: userInfo.sub,
          email: userInfo.email,
          name: userInfo.name ?? userInfo.preferred_username,
          isAdmin,
        });
```

**Remediation:** Allowlist `userId` to `[A-Za-z0-9_-]+`; reject `.`, `..`, `/`, `\`; resolve and assert `path.resolve(dir).startsWith(path.resolve(USER_HOME_BASE) + sep)`.

---

## HIGH-03 — MCP `safePath` prefix check bypass (sibling path read)

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Location | `mcp-server/src/server.ts` |
| Title | `startsWith(SRC_ROOT)` path jail bypass |
| Verified | Yes — code tracing + local path simulation |

**Description:** `safePath` uses `resolved.startsWith(SRC_ROOT)` without a trailing-separator check. For `SRC_ROOT=/app/src`, inputs like `../src.env` or `../src_backup/secrets.json` resolve to `/app/src.env` / `/app/src_backup/...`, which still pass the prefix test. MCP HTTP auth is optional (`MCP_API_KEY` unset ⇒ open).

**Impact:** Unauthenticated (by default) read of files outside `src/` that share the `src` string prefix (e.g. `src.env`, `src_secrets/`, backup trees), enabling secret/source disclosure on hosted explorer deployments.

**Attack path:**
1. Reach MCP HTTP (`POST /mcp`) with no `MCP_API_KEY`.
2. Call `read_source_file` with `path: "../src.env"` (or resource `claude-code://source/../src_backup/x`).
3. Server returns file contents if present on disk.

**Evidence:**
```83:88:mcp-server/src/server.ts
function safePath(relPath: string): string | null {
  const resolved = path.resolve(SRC_ROOT, relPath);
  if (!resolved.startsWith(SRC_ROOT)) return null;
  return resolved;
}
```
```29:34:mcp-server/src/http.ts
function authMiddleware(...): void {
  if (!API_KEY) return next();
  // ...
}
```

**Remediation:** Compare with `resolved === SRC_ROOT || resolved.startsWith(SRC_ROOT + path.sep)`; require `MCP_API_KEY` in non-local deploys; use `path.relative` and reject `..` prefixes.

---

## MEDIUM-01 — Open redirect after API-key login (`next` query)

| Field | Value |
| --- | --- |
| Severity | MEDIUM |
| Location | `src/server/web/auth/apikey-auth.ts` |
| Title | Protocol-relative open redirect via `next.startsWith("/")` |
| Verified | Yes — code tracing |

**Description:** Post-login redirect allows any string starting with `/`, including `//evil.com` (protocol-relative).

**Impact:** Phishing / OAuth-style trust abuse after login; credential phishing on a lookalike site while the real session cookie remains on the victim host.

**Attack path:**
1. Send victim to `/auth/login?next=//evil.com`.
2. Victim posts API key; server sets session cookie then `res.redirect("//evil.com")`.
3. Browser navigates to attacker-controlled site.

**Evidence:**
```95:96:src/server/web/auth/apikey-auth.ts
        const next = (req.query as Record<string, string>)?.next;
        res.redirect(next && next.startsWith("/") ? next : "/");
```

**Remediation:** Allow only relative paths: must start with `/`, must not start with `//`, reject `\`, and prefer an allowlist of known routes.

---

## MEDIUM-02 — Client-controlled `X-Forwarded-For` bypasses IP rate limit

| Field | Value |
| --- | --- |
| Severity | MEDIUM |
| Location | `src/server/web/pty-server.ts` |
| Title | Spoofable `X-Forwarded-For` disables connection rate limiting |
| Verified | Yes — code tracing |

**Description:** Rate limiting keys off the first `X-Forwarded-For` hop with no trusted-proxy configuration. Direct clients can send arbitrary values.

**Impact:** Bypass of the 5-conn/min IP limiter → session-slot exhaustion / DoS against `MAX_SESSIONS`; amplifies unauthenticated or weakly authenticated deployments.

**Attack path:**
1. Connect repeatedly to `/ws` with a fresh `X-Forwarded-For: <random>` each time.
2. `rateLimiter.allow(ip)` always sees a new IP; per-IP limit never trips.
3. Exhaust global/user session capacity.

**Evidence:**
```201:209:src/server/web/pty-server.ts
    const ip =
      (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ??
      req.socket.remoteAddress ??
      "unknown";
    if (!rateLimiter.allow(ip)) {
```

**Remediation:** Use `req.socket.remoteAddress` unless behind a known proxy; if proxied, take the rightmost trusted hop / configure Express `trust proxy` correctly.

---

## MEDIUM-03 — Share passwords stored/compared in plaintext; unauthenticated revoke

| Field | Value |
| --- | --- |
| Severity | MEDIUM |
| Location | `web/lib/share-store.ts` (also `web/app/api/share/[shareId]/route.ts`) |
| Title | Plaintext share passwords and unauthenticated share DELETE |
| Verified | Yes — code tracing |

**Description:** Comment claims “bcrypt-style hash” but `passwordHash` stores the raw password and `verifySharePassword` uses `===`. `DELETE /api/share/:shareId` has no auth.

**Impact:** Memory/process disclosure yields share passwords; anyone who learns/guesses a share id can revoke shares (availability) or, with password shares, offline password use if memory is dumped.

**Attack path:**
1. Create password-protected share (password stored plaintext in module `Map`).
2. Attacker with share id calls `DELETE /api/share/<id>` → share removed without auth.
3. Or dump process memory / debug endpoint → recover password strings.

**Evidence:**
```17:18:web/lib/share-store.ts
  passwordHash?: string; // bcrypt-style hash; plain comparison used here for simplicity
```
```51:51:web/lib/share-store.ts
    passwordHash: params.password ?? undefined,
```
```74:77:web/lib/share-store.ts
export function verifySharePassword(shareId: string, password: string): boolean {
  const entry = store.get(shareId);
  if (!entry || entry.visibility !== "password") return false;
  return entry.passwordHash === password;
}
```
```33:40:web/app/api/share/[shareId]/route.ts
export async function DELETE(_req: NextRequest, { params }: RouteContext) {
  const { shareId } = params;
  const deleted = revokeShare(shareId);
```

**Remediation:** Hash with bcrypt/scrypt/argon2; authenticate revoke (owner session or revoke token); rate-limit password attempts.

---

## Out of scope / not reported

- Local CLI BashTool/File tools used by the machine owner (by design).
- `-p` skipping trust for `awsAuthRefresh` / project hooks (documented trust model).
- Missing rate limits without a concrete exploit chain beyond the XFF issue above.
- Hardcoded example placeholders in `.env.example`.
