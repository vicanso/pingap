# oidc

Lets in who has logged in at an OpenID Connect provider (Keycloak, Authentik,
Dex, Google, Microsoft Entra ID, Okta, ...). The usual way to put a login in
front of an internal site that has none of its own.

A browser that asks for a page without a session is sent to the provider. It
comes back with a code, which Pingap trades at the provider for an ID token;
the token is verified with the provider's keys and a session is made of what it
says of the user. The session lives in an encrypted cookie: nothing is stored
on the proxy, and every instance that has the same `cookie_secret` reads it.

- **Step:** `request` (fixed)
- **Registered as:** `oidc`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `oidc`. |
| `issuer` | string | — | **Required.** The url of the provider, as it names itself. `<issuer>/.well-known/openid-configuration` is read from it. |
| `client_id` | string | — | **Required.** The id this site is registered under at the provider. |
| `client_secret` | string | — | The secret that goes with it. Empty for a public client. |
| `cookie_secret` | string | — | **Required.** What sessions are encrypted with, 16 characters at least. The same on every instance. |
| `redirect_path` | string | `/oauth2/callback` | The path the provider sends the browser back to. |
| `redirect_url` | string | — | The full address of `redirect_path` as browsers see it, when that is not what the request says. |
| `logout_path` | string | — | A path that ends the session. None when unset. |
| `scopes` | string[] | `[]` | Scopes asked for besides `openid`, which is always asked for. |
| `cookie_name` | string | `pingap_oidc` | The name of the session cookie. Not one that begins with `__Host-`. |
| `session_ttl` | duration | `12h` | How long a login lasts. At least `1m`. |
| `claims_to_headers` | string[] | `[]` | `claim:Header-Name` entries: what the provider says of the user, sent to the upstream. The header is what follows the last colon, so a claim named `https://example.com/roles` works. Not `Host`, `Connection`, `Content-Length` or `Transfer-Encoding`. |

`client_secret` and `cookie_secret` are credentials: they are masked in what is
logged of a change of the configuration, and can be written `$ENV:NAME` or
`$FILE:/path`.

## Example

```toml
[plugins.login]
category = "oidc"
issuer = "https://id.example.com/realms/staff"
client_id = "wiki"
client_secret = "$ENV:WIKI_OIDC_SECRET"
cookie_secret = "$FILE:/run/secrets/wiki-cookie"
scopes = ["email", "profile"]
claims_to_headers = ["email:X-User-Email", "groups:X-User-Groups"]
logout_path = "/oauth2/logout"

[locations.wiki]
upstream = "wiki"
host = "wiki.example.com"
plugins = ["login"]
```

At the provider, register `https://wiki.example.com/oauth2/callback` as the
redirect address of the client.

## What happens to a request

- **With a session:** it goes on to the upstream. For each entry of
  `claims_to_headers` the claim is put into its header; a header of that name
  the client wrote itself is removed first, with or without a session - and so
  is one that differs only in `_` for `-` (`X_User_Email`), which is the same
  variable to an upstream behind CGI, WSGI, Rack or PHP. A client can not take
  such a header away either, by naming it in `Connection`. A claim that is
  text, a number or a boolean is sent as it is, a list of those joined with
  commas; anything else, and a claim the user does not have, sends no header.
- **Without one, a browser going to a page** (`GET` with
  `Sec-Fetch-Mode: navigate`, or, from a browser that does not send that, with
  `text/html` in `Accept`): redirected to the provider.
- **Without one, anything else** (a script that fetches, a form that is
  posted, an API client): `401 Login required`. Such a request can not follow
  to a login page, and a posted form would lose what it posted.
- **`redirect_path`:** the end of a login, see below.
- **`logout_path`:** the session cookie is taken away and the browser is sent
  to where the provider ends its own session (`end_session_endpoint`, with the
  `client_id`), when it has such a place; otherwise the answer is a plain
  `Logged out`. Any request to the path does it, whatever its method and
  wherever it comes from: another site can log a user out by sending the
  browser there, and nothing more than that.

`redirect_path` (and `logout_path`) have to reach a location that has this
plugin - the one the pages are served by, or another with the same plugin.
They are compared with the path as the client sent it, and the page a login
goes back to is the address as the client sent it: a `rewrite` of the location
does not change either.

## The login

1. The browser is redirected to the provider's `authorization_endpoint` with
   `response_type=code`, the client, the scopes, a random `state` and `nonce`,
   and a PKCE challenge (`S256`). What belongs to that login - the state, the
   nonce, the PKCE verifier, the page the browser was going to - is kept in an
   encrypted cookie for `redirect_path`, good for ten minutes. Two tabs that
   log in at once each have their own; a login that is finished clears the
   cookies of the ones that were left. A page whose address is too long to
   keep in a cookie (about 2.6 KB) is not gone back to: that login ends at `/`.
2. The provider sends the browser back to `redirect_path` with `code` and
   `state`. A request that does not carry the cookie of a login with that
   state is answered `400`, and the provider is not asked anything.
3. The code is traded at the `token_endpoint` (with the PKCE verifier; the
   client authenticates with `client_secret_basic`, or `client_secret_post`
   when the provider says it does not take the former).
4. The ID token has to be signed with one of the provider's keys
   (`jwks_uri`; asymmetric algorithms only), issued by `issuer`, for this
   `client_id`, not expired, and carry the `nonce` of this login. Anything
   else is `502 Login failed`, with the reason in the log
   (`oidc login failed`).
5. The session is `sub` and the claims named in `claims_to_headers`, good
   for `session_ttl`, in a cookie that is `HttpOnly`, `SameSite=Lax` and, on a
   site reached over TLS, `Secure`. The browser is sent to the page it was
   going to - a path of this site, never another site.

A provider that refuses (`error=access_denied`) is answered `403`.

## Notes

- **The session is what the provider said at login.** It is not asked again
  until `session_ttl` is over: a user removed at the provider, or taken out of
  a group, keeps the session until then. Keep `session_ttl` as short as that
  may take. There is no refresh token and no back-channel logout.
- **`cookie_secret`.** Whoever has it can make a session for anybody. Changing
  it ends every session. A session can not be ended on its own before its
  time, short of that.
- **The size of the session.** It has to fit a cookie (about 3.8 KB sealed).
  A user with hundreds of groups in a claim that goes to a header does not
  fit, and the login fails with `the session does not fit a cookie` in the
  log.
- **Behind another proxy or a CDN** the address the provider is told to come
  back to is made from the request: `https` when the connection to Pingap is
  TLS, and the `Host` of the request. When that is not the address browsers
  use, set `redirect_url`; the cookies are then `Secure` when it is `https`.
- **What the provider says of itself** is read on the first request that
  needs it and kept for an hour; its keys are kept for an hour and read again
  when a token names a key that is not among them. A provider that can not be
  reached does not affect requests that have a session. While it can not be
  reached it is asked once in a while - ten seconds after an attempt is over -
  and not by every request: the others are answered `502` at once.
- **With `cache`:** put this plugin before it, as with every plugin that says
  who may ask. A response from the cache is for whoever has a session, not
  for one user: mark what is one user's `Cache-Control: private` at the
  upstream.
- **Several locations, one login.** The cookie is for the host. Locations of
  one host that share the plugin share the session; a second plugin with
  another `cookie_name` and `redirect_path` keeps a login of its own.
