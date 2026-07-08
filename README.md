# authx

Plug-and-play authentication for Sova apps. Refresh tokens with rotation,
family-level reuse detection, multi-device support, and a silent-refresh
frontend hook - all layered on Sova's built-in wire session mechanism.

authx does not decide how you store users, hash passwords, or shape your
claims. It handles the parts that are mechanically the same across every
application (rotation, reuse detection, cookie plumbing, retry-on-401 on
the client) and hands you back building blocks for the parts that vary.

## Why authx

Sova already has a wire session cookie and `wire(authn: true)` for
gating handlers. That covers a single browser tab logging in and staying
logged in until the tab closes. Real applications need more:

- **Silent refresh** so users are not kicked out when the access
  window expires while they are actively using the app.
- **Multi-device management** so users can list where they are signed
  in and sign a specific device out.
- **Token rotation with reuse detection** so a stolen refresh token
  cannot ride alongside the legitimate rotation chain undetected.
- **Password-change / sign-out-from-everywhere** flows that immediately
  revoke every live session.

authx is the smallest possible layer that gives you those four without
making assumptions about the shape of your user table.

## Package layout

| Package         | Side     | What lives here                                                              |
|-----------------|----------|------------------------------------------------------------------------------|
| `authx`         | shared   | `Principal`, `TokenPair`, `isAnonymous` - types shared across the boundary   |
| `authx/refresh` | backend  | `Record`, `Store` interface, `Config`, `issue` / `rotate` / `revoke` / `list`|
| `authx/server`  | backend  | `Kit`, fluent `Builder`, cookie helpers, `mintRefresh` / `tryRotate`         |
| `authx/client`  | frontend | `install` / `installWith` for silent-refresh via `std/rpc`                    |

Each sub-package can be imported on its own - a service that only needs
to read refresh records from another process can import `authx/refresh`
without dragging in HTTP or cookies.

## Installation

Add authx to your project's `sova.toml`:

```toml
[dependencies]
authx = "0.1"
```

For local development against an unpublished authx checkout, point
`.sova/local-links.toml` at the folder:

```toml
[links]
authx = "/path/to/authx"
```

## Quick start

The minimum end-to-end wiring is around 40 lines of Sova. Everything
below assumes an application that has its own user table and its own
password backend; authx never inspects either.

### 1. Implement `refresh.Store` against your database

The Store interface is 7 methods. Every method returns a total answer
(`none` for "not found", `false` for "write failed") - authx never
looks at error strings.

```sova
package myapp on backend

import "authx/refresh"

type PgStore implements refresh.Store {
    // fields for a pool handle, a table name, whatever fits

    func save(rec: refresh.Record): option<refresh.Record> { ... }
    func findByHash(hash: string): option<refresh.Record>   { ... }
    func markRevoked(id: string): bool                       { ... }
    func revokeFamily(family: string): bool                  { ... }
    func listByUser(subject: string): []refresh.Record       { ... }
    func revokeByUser(subject: string): bool                 { ... }
    func revokeByDevice(subject: string, deviceId: string): bool { ... }
}
```

See [Implementing `refresh.Store`](#implementing-refreshstore) for the
full contract of each method.

### 2. Build a Kit at boot

The `Builder` is the recommended entry point. Chain zero or more
setters, call `.build()`:

```sova
import "authx/server" as auth

let kit = auth.builder(new PgStore())
    .refreshTtl(60 * 60 * 24 * 30)   // 30 days (the default)
    .cookieSecure(true)               // false only for localhost dev
    .cookieSameSite("Lax")
    .build()
```

Every setter is optional. `builder(store).build()` is a valid config.

### 3. Write the three wire handlers

authx does not ship pre-baked signIn / refresh / signOut endpoints. It
gives you the building blocks and lets you decide the response shape,
the error semantics, the logging, and the additional business logic
(rate limiting, MFA, audit trails). The handlers below are what a
typical setup looks like.

**Sign-in.** Verify credentials, mint a refresh token, populate Sova's
session via `@.authenticate(...)`, attach the refresh cookie.

```sova
import "authx"
import "authx/server" as auth
import "std/http"
import "std/password"
import "std/uuid"

wire(authn: false, method: "POST", path: "/api/signIn")
func signIn(email: string, plaintext: string): http.Status<SignInResult> {
    let user = findUserByEmail(email)
    if user == none || !password.verify(plaintext, user!.passwordHash) {
        return errResult(401, "invalid credentials")
    }
    let u = user!

    let p = new authx.Principal()
    p.subject = u.id
    p.deviceId = uuid.v4()
    p.claims = { "email": u.email, "roles": u.roles }

    let token = auth.mintRefresh(kit, p, "browser")
    if token == "" {
        return errResult(500, "internal error")
    }

    // Populate Sova session so subsequent wire(authn: true) accept the
    // request. Must live in the wire body; authx cannot call `@` on
    // your behalf because `@` is only legal inside wire handlers.
    @.authenticate(p.subject, p.claims)
    @.setRoles(u.roles)

    let r = new http.Status<SignInResult>()
    r.body = SignInResult { ok: true }
    r.status = 200
    r.setCookie(auth.refreshCookieName(kit), token, auth.refreshCookieOpts(kit))
    return r
}
```

**Refresh.** Raw wire because we need to read the refresh cookie off
the request. Rotates the cookie and re-authenticates the session.

```sova
wire(authn: false, transport: "raw", method: "POST", path: "/api/authx/refresh")
func refreshEndpoint(req: http.Request, res: http.Response) {
    let outcome = auth.tryRotate(kit, req)
    if outcome == none {
        res.setStatus(401)
        return
    }
    let bundle = outcome!

    // Materialise a fresh Principal - claims may have changed since
    // the token was originally minted.
    let user = findUserById(bundle.record.subject)
    if user == none {
        res.setStatus(401)
        return
    }
    let u = user!
    let claims = { "email": u.email, "roles": u.roles }

    @.authenticate(u.id, claims)
    @.setRoles(u.roles)

    res.setCookie(
        auth.refreshCookieName(kit), bundle.token,
        2592000, true, true, "Lax", "/"
    )
    res.setStatus(200)
}
```

**Sign-out.** Revoke the current device's refresh record, clear the
Sova session, drop the refresh cookie.

```sova
wire(authn: true, transport: "raw", method: "POST", path: "/api/signOut")
func signOutEndpoint(req: http.Request, res: http.Response) {
    let presented = auth.readRefreshFromRequest(kit, req)
    auth.revokeCurrentDevice(kit, presented)
    @.logout()
    res.setCookie(auth.refreshCookieName(kit), "", -1, true, true, "Lax", "/")
    res.setStatus(204)
}
```

### 4. Install the frontend interceptor

One line at frontend boot. Every wire call that comes back with a 401
now silently POSTs to `/api/authx/refresh` and retries on success.

```sova
import "authx/client" as authClient

func boot() {
    authClient.install("/api/authx/refresh")
    // ... rest of your app's boot
}
```

For handling refresh failures (typical: redirect to the sign-in screen):

```sova
authClient.installWith(
    "/api/authx/refresh",
    func() { /* onSuccess: analytics ping, cache refresh, etc */ },
    func() { navigate("/signin") }
)
```

That is the complete integration. The rest of the README digs into the
pieces.

## Core concepts

### `authx.Principal`

`Principal` is the shape authx uses to describe an authenticated user
during signIn and refresh:

```sova
type Principal {
    subject: string = ""             // stable user identifier (DB id)
    deviceId: string = ""             // opaque per-login identifier
    claims: map<string, any> = {}     // arbitrary application data
}
```

- `subject` is whatever your application uses as the user's stable
  identifier - typically a UUID or bigint from the users table.
  authx stores it on every refresh Record so `revokeByUser(subject)`
  can find every session at once.
- `deviceId` groups every request from one login instance. Different
  logins from the same browser (after signing out and back in) get
  different `deviceId` values so they can be revoked independently.
  Applications can use a UUID (recommended), a browser fingerprint,
  a native-app device id - authx never inspects it.
- `claims` becomes `@.Claims` on the Sova session. Populate it with
  whatever the rest of your application wants to see on `@` -
  email, roles, tenant id, feature flags.

`authx.isAnonymous(p)` returns `true` when `p.subject == ""`. Useful
as a "credentials rejected" sentinel without allocating an
`option<Principal>`.

### `refresh.Record`

The Record is what a Store persists for each refresh token:

```sova
type Record {
    id: string             // your Store mints this (or authx does; see save())
    hash: string           // SHA-256 hex of the plaintext token
    family: string         // random id shared across the rotation chain
    parentId: string       // previous record in the chain, "" for initial
    subject: string        // Principal.subject
    deviceId: string       // Principal.deviceId
    deviceLabel: string    // human-readable label for "list my devices"
    createdAtUnix: int
    expiresAtUnix: int
    revoked: bool
}
```

Two things worth noting:

- **The plaintext token is never persisted.** Only its SHA-256 hash.
  A full Store dump does not let an attacker mint valid sessions.
- **`family` is the reuse-detection anchor.** Every token rotated from
  the same original signIn shares one family. If a caller ever presents
  a token whose Record is already revoked, authx revokes the entire
  family in one shot - a stolen token cannot live in parallel with the
  legitimate rotation.

### `refresh.Store`

The persistence adapter you provide. 7 methods, described in detail
below. authx never touches your database; you never touch authx's
in-memory state.

### `server.Kit`

An opaque handle constructed via `builder(...).build()`. Passed to
every `authx/server` function that needs configuration. Hold on to
one Kit for the lifetime of your process - it is cheap to construct
but there is no reason to build a new one per request.

## Building blocks reference

### `authx/refresh`

| Function                                             | Purpose                                                              |
|------------------------------------------------------|----------------------------------------------------------------------|
| `issue(cfg, subject, deviceId, deviceLabel)`         | Mint a fresh token + persist a Record. Initial issuance.             |
| `rotate(cfg, presented)`                             | Swap presented for a new pair. Detects reuse and revokes the family. |
| `revoke(cfg, presented)`                             | Mark presented as revoked without minting a replacement. Sign-out.   |
| `revokeByDevice(cfg, subject, deviceId)`             | Revoke every record for one (subject, deviceId) pair.                |
| `revokeByUser(cfg, subject)`                         | Revoke every record for one subject. Sign-out-from-everywhere.       |
| `list(cfg, subject)`                                 | Non-revoked records for a subject. "List my devices" data source.    |

All returns are total: `option<TokenAndRecord>` for the token-returning
ones, `bool` for the revokes, `[]Record` for the list.

### `authx/server`

The Kit + cookie plumbing + the three composable primitives you call
from your handlers.

**Building a Kit.**

| Function                                | Purpose                                                       |
|-----------------------------------------|---------------------------------------------------------------|
| `builder(store): Builder`               | Fluent-API entry point. Chain setters, end with `.build()`.   |
| `newKit(cfg): Kit`                      | Escape hatch when you already have a fully-shaped KitConfig.  |

**Builder methods** (each returns the same Builder, all optional):

| Method                     | Default             | Notes                                                 |
|----------------------------|---------------------|-------------------------------------------------------|
| `.refreshTtl(seconds)`     | 2 592 000 (30 days) | Server-side lifetime of a refresh Record.             |
| `.refreshTokenBytes(n)`    | 32                  | Cryptographic-random bytes per minted token.          |
| `.cookieName(name)`        | `"authx_refresh"`   | Refresh cookie name.                                  |
| `.cookieMaxAge(seconds)`   | 2 592 000           | Browser-side lifetime. Should match `refreshTtl`.     |
| `.cookiePath(path)`        | `"/"`               | Cookie Path attribute.                                |
| `.cookieDomain(domain)`    | `""`                | Empty = same-origin. Set to parent domain for subs.   |
| `.cookieSecure(bool)`      | `true`              | Set `false` only on localhost dev over plain HTTP.    |
| `.cookieSameSite(str)`     | `"Lax"`             | `"Lax"`, `"Strict"`, `"None"`, or `""`.               |
| `.build()`                 | -                   | Returns the finished Kit.                             |

**Cookie helpers.**

| Function                            | Purpose                                                    |
|-------------------------------------|------------------------------------------------------------|
| `refreshCookieName(kit)`            | The configured cookie name.                                |
| `refreshCookieOpts(kit)`            | `CookieOpts` for attaching the refresh cookie.             |
| `clearRefreshCookieOpts(kit)`       | Same shape but with `maxAge = -1`. Sign-out.               |
| `readRefreshFromRequest(kit, req)`  | Read the cookie value from a raw-wire `http.Request`.      |

**Flow primitives.**

| Function                                  | Purpose                                                      |
|-------------------------------------------|--------------------------------------------------------------|
| `mintRefresh(kit, principal, deviceLabel)`| Sign-in step: persist a Record, return plaintext token.      |
| `tryRotate(kit, req)`                     | Refresh step: read cookie, rotate, return `TokenAndRecord`.  |
| `revokeCurrentDevice(kit, presentedToken)`| Sign-out step: revoke this device's Record only.             |

### `authx/client`

The frontend is intentionally minimal because the interesting state
(refresh token, session) lives HttpOnly on the browser - the client
never sees or stores it.

| Function                                             | Purpose                                                                |
|------------------------------------------------------|------------------------------------------------------------------------|
| `install(refreshUrl): func()`                        | Register the `std/rpc.onUnauthorized` hook. Returns unregister.        |
| `installWith(refreshUrl, onSuccess, onFailure)`      | Same, plus callbacks. Use `onFailure` to route to the sign-in screen.  |

Both variants return the unregister closure from `std/rpc` - keep it
if you need dynamic teardown, discard it for permanent registration.

## Implementing `refresh.Store`

The full contract of each method, with sample SQL to illustrate the
intent (adapt for your DB of choice).

### `save(record: Record): option<Record>`

Persist a fresh Record. If `record.id == ""` at call time, mint an id
(UUID, sequence, whatever) and populate it on the returned Record.
The returned Record must have every field populated (in particular
`id` - callers rely on it for later `markRevoked` calls).

```sql
INSERT INTO refresh_tokens (id, hash, family, parent_id, subject,
                            device_id, device_label, created_at, expires_at, revoked)
VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8), to_timestamp($9), false)
RETURNING *;
```

Return `none` on any failure (constraint violation, connection error,
timeout). authx treats "no record returned" as "sign-in failed" and
surfaces the corresponding error to the client.

### `findByHash(hash: string): option<Record>`

Look up a Record by the SHA-256 hex of a presented refresh token.
Callers pass the hash, not the token - the Store never sees plaintext.

```sql
SELECT * FROM refresh_tokens WHERE hash = $1 LIMIT 1;
```

Return `none` when no such record exists. Return the record even if
`revoked = true` - authx uses the revoked flag to detect reuse.

### `markRevoked(id: string): bool`

Flip `revoked = true` on the Record with the given id. Idempotent -
revoking an already-revoked record is a no-op success.

```sql
UPDATE refresh_tokens SET revoked = true WHERE id = $1;
```

Return `true` when the row exists (and is now revoked), `false` when
the id is unknown.

### `revokeFamily(family: string): bool`

Mark every Record with matching `family` as revoked, atomically if
your Store supports it. Triggered by reuse detection inside `rotate`.

```sql
UPDATE refresh_tokens SET revoked = true WHERE family = $1;
```

Return `true` when at least one row was affected.

### `listByUser(subject: string): []Record`

Every non-revoked, non-expired Record for the subject. Basis for a
"list my devices" endpoint.

```sql
SELECT * FROM refresh_tokens
WHERE subject = $1
  AND revoked = false
  AND expires_at > NOW();
```

Return an empty slice on any error - authx projects the result into
the response body, empty is a valid answer.

### `revokeByUser(subject: string): bool`

Every Record for `subject` becomes revoked. Called from sign-out-from-
everywhere flows and after password changes.

```sql
UPDATE refresh_tokens SET revoked = true WHERE subject = $1;
```

### `revokeByDevice(subject: string, deviceId: string): bool`

Every Record matching (subject, deviceId) becomes revoked. Called from
the "sign this laptop out" flow driven by another device.

```sql
UPDATE refresh_tokens SET revoked = true
WHERE subject = $1 AND device_id = $2;
```

## Multi-device support

The refresh Record carries `deviceId` and `deviceLabel`. Combined with
`refresh.list` and `refresh.revokeByDevice`, that is enough for a full
device-management UI:

```sova
type DeviceInfo {
    id: string = ""
    deviceId: string = ""
    deviceLabel: string = ""
    createdAtUnix: int = 0
    expiresAtUnix: int = 0
}

wire(method: "GET", path: "/api/me/devices")
func listDevices(): []DeviceInfo {
    let subject = @.user as string
    let out: []DeviceInfo = []
    for _, rec in refresh.list(kit.cfg.refresh, subject) {
        let d = new DeviceInfo()
        d.id = rec.id
        d.deviceId = rec.deviceId
        d.deviceLabel = rec.deviceLabel
        d.createdAtUnix = rec.createdAtUnix
        d.expiresAtUnix = rec.expiresAtUnix
        out = out + [d]
    }
    return out
}

wire(method: "POST", path: "/api/me/devices/:deviceId/revoke")
func revokeOne(deviceId: string): bool {
    return refresh.revokeByDevice(kit.cfg.refresh, @.user as string, deviceId)
}
```

The `deviceLabel` you pass to `mintRefresh` is what shows up here.
Typical values: `"MacBook Pro (Chrome)"`, `"iPhone (Safari)"`,
`"CLI (curl)"`. authx does not autofill this - your signIn endpoint
should read the `User-Agent` or ask the client to send an explicit
label.

## What authx does not do

- **Password hashing.** Use `std/password` (Argon2id / bcrypt). authx
  never sees your plaintext or hashes.
- **User model.** No opinion on the shape of your users table. authx
  only sees `subject`, `deviceId`, and `claims`.
- **DB schema.** You provide `refresh.Store`. In-memory, Postgres,
  SQLite, Redis, DynamoDB - all fine, all authx cares about is the 7
  methods.
- **Role definitions.** Sova's built-in `wire(authz: [...])` mechanism
  does the enforcement. authx just makes sure `@.setRoles(...)` is
  called with your roles during signIn / refresh.
- **JWTs.** For the standard same-origin SPA setup, Sova's session
  cookie is the auth artefact and JWTs add no security. If you have
  a cross-origin or mobile client that needs a Bearer token, you can
  compose that on top of authx by calling `std/jwt.signHS256` yourself
  during signIn - authx does not fight this.
- **CSRF.** Sova's session cookie is `SameSite=Lax` by default, which
  neutralises classic CSRF for browser SPAs. If your setup needs
  `SameSite=None`, add a double-submit CSRF token layer on top.

## Design notes

### Why does authx not call `@.authenticate` for me?

Sova enforces at compile time that `@` (the current-session expression)
only appears in the body of a wire handler on the backend side. Library
code cannot legally use `@`. authx therefore returns the ingredients
(a plaintext token, a `TokenAndRecord`, a Principal) and lets you call
`@.authenticate(...)` yourself in the wire handler body. That keeps the
integration explicit and matches the shape Sova expects.

### Why is refresh a raw wire?

The refresh endpoint needs to read the HttpOnly refresh cookie off the
request. Sova's typed wires do not expose `http.Request` to user code;
that access is only available inside `wire(transport: "raw")` handlers.
The signIn wire can stay typed because it only sets cookies (via
`http.Status<T>`) rather than reading them.

### Why does authx not just use a single `SessionStore`?

Sova already ships one: the wire session cookie. authx layers the
long-lived rotation-and-revocation story on top. Merging the two would
force every application onto authx's refresh mechanism even for the
throwaway "log in and use the app for a few minutes then close the
tab" flow that Sova's session cookie already handles perfectly.

## License

Same license as the enclosing Sova project.
