# Postwright

A secure, multi-domain mail server written entirely in Rust. It's the server-side companion to [Mailwright](https://github.com/Tonyscodehub/Mailwright).

One binary provides:

- **SMTP inbound (MX)** on port 25, with SPF, DKIM, and DMARC verification
- **Authenticated submission** on 587 (STARTTLS) and 465 (implicit TLS), with DKIM signing
- **IMAP4rev1** on 143 (STARTTLS) and 993 (TLS), with IDLE push, MOVE, UIDPLUS, and SPECIAL-USE
- **CalDAV calendars with sharing** over HTTPS on 443
- **Out-of-office auto-replies** and **server-stored signatures**
- **A settings web page and JSON API**, plus Thunderbird-style **autoconfig**
- An **outbound queue** with MX failover, retries with back-off, and bounce reports

It works with Mailwright, Thunderbird, Apple Mail and Calendar, Outlook (IMAP), iOS, Android (K-9, FairEmail, DAVx5), and anything else that speaks the standards.

## Security model

- **No unauthenticated access to anything that matters.** Port 25 only accepts mail *for* domains hosted here (it can never be used as a relay), and offers no AUTH. Submission, IMAP, CalDAV, and the API all require a login.
- **Credentials only travel encrypted.** SMTP AUTH is refused before STARTTLS (`538 5.7.11`), and IMAP advertises `LOGINDISABLED` until TLS is up. HTTP is HTTPS-only.
- **No sender spoofing.** Authenticated users can only send as their own address or an alias that delivers to them, checked on both the envelope and the `From:` header.
- **Passwords are hashed with Argon2id.** Logins take constant time whether or not the account exists, and concurrent hashing is bounded so a login flood can't exhaust memory.
- **Brute-force protection.** After 5 failed logins in 15 minutes (configurable) an IP is blocked on every protocol.
- **Connection limits.** These apply per listener and per IP, along with idle timeouts and line and literal size caps.
- **Protocol hardening:**
  - STARTTLS command-injection defence: pipelined plaintext is discarded.
  - SMTP smuggling defence: only `<CRLF>.<CRLF>` ends DATA.
  - Forged `Authentication-Results` headers are stripped.
  - Inbound mail failing DMARC with `p=reject` is rejected.
- **TLS 1.2 and 1.3 only**, via rustls. No OpenSSL.

## Quick start

```sh
postwright init --hostname mail.example.com      # writes postwright.toml (+ a self-signed cert)
postwright domain add example.com                # generates a DKIM key and prints the DNS records
postwright domain add example.co.uk              # as many domains as you like
postwright user add tony@example.com             # prompts for the password
postwright alias add hello@example.co.uk tony@example.com
postwright serve
```

Then open `https://mail.example.com/` to set out of office, signature, calendars, and password.

### Connecting Mailwright or any mail app

| | Server | Port | Security | Username |
|---|---|---|---|---|
| IMAP | mail.example.com | 993 | SSL/TLS | full email address |
| SMTP | mail.example.com | 465 | SSL/TLS | full email address |
| SMTP (alternative) | mail.example.com | 587 | STARTTLS | full email address |
| Calendars (CalDAV) | `https://mail.example.com/dav/` | 443 | TLS | full email address |

Thunderbird (and Mailwright, if it uses the same lookup) can configure itself from just the email address. Postwright serves `/.well-known/autoconfig/mail/config-v1.1.xml`. Point an `autoconfig.<domain>` CNAME at the server for each domain, and the SRV records printed by `domain dns` cover clients that use RFC 6186.

## DNS

`postwright domain dns example.com` prints everything a domain needs:

- **MX** pointing at your host name
- **SPF** (`v=spf1 mx -all`)
- **DKIM** (`pw1._domainkey`, 2048-bit RSA)
- **DMARC**
- **SRV** records for client autodiscovery

You also need one A/AAAA record for the host name. You also need **reverse DNS (PTR)** for your public IP that matches the host name; your ISP or VPS provider sets that.

## TLS certificates

Use a real certificate before going live. With Let's Encrypt:

```sh
certbot certonly --standalone -d mail.example.com --deploy-hook "systemctl reload postwright"
```

Then set `tls.cert = "/etc/letsencrypt/live/mail.example.com/fullchain.pem"` and the matching `privkey.pem` in `postwright.toml`. Postwright reloads the certificate on `SIGHUP` (Unix) and every 12 hours on every platform, so renewals need no restart.

## Outbound reputation

If the server has a static IP with matching reverse DNS (PTR), it sends direct to recipients' MX hosts. With DKIM, SPF, and DMARC in place, mail is accepted by Gmail, Outlook, and the rest.

On a connection without that (dynamic or residential ranges, or blocked outbound port 25), route outbound mail through a smarthost. Postwright still DKIM-signs everything itself, so DMARC alignment stays intact:

```toml
[queue]
relay_host = "smtp.relay-provider.com:587"
relay_username = "..."
relay_password = "..."
```

## Out of office

Replies follow RFC 3834:

- Each sender gets at most one reply every 4 days.
- Replies use a null envelope sender, so they can't loop.
- No replies go to mailing lists, bulk mail, `noreply` addresses, bounces, or other auto-replies.
- Replies come from the address the mail was actually sent to (so aliases work), and are DKIM-signed.
- Optional start and end dates, and an "internal senders only" option.

Users set this from the web page or API. Admins can set it too:

```sh
postwright user vacation tony@example.com --message "Back Monday" --until 2026-11-23
postwright user vacation tony@example.com --off
```

## Signatures

Signatures are stored on the server so every device shows the same one (fetch it from `GET /api/v1/settings`). Optionally the server appends it to outgoing mail when the client hasn't. Postwright edits plain-text and HTML parts (7bit, 8bit, and quoted-printable), skips attachments and base64-encoded bodies, and never adds the signature twice.

## Calendars and sharing

Every user gets a default calendar and can create more from their calendar app, the web page, or the CLI. Calendars can be shared view-only or editable. Shared calendars appear automatically in the other person's calendar app.

```sh
postwright calendar create tony@example.com "Poffles rota"
postwright calendar share tony@example.com poffles-rota amy@example.co.uk --write
postwright calendar list amy@example.co.uk
```

Each calendar can also be downloaded as a single `.ics` with `GET` on its URL.

## Settings API

All endpoints use HTTP Basic auth (email and password) over HTTPS. State-changing calls must send `Content-Type: application/json`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/me` | Account, quota, and connection settings |
| GET / PUT | `/api/v1/settings` | `{ vacation: {enabled, subject, body, start, end, internal_only}, signature: {text, html, append} }` |
| POST | `/api/v1/password` | `{ current, new }` |
| GET / POST | `/api/v1/calendars` | List (with shares), or create `{ name, color }` |
| DELETE | `/api/v1/calendars/{slug}` | Delete (owner) or leave (sharee) |
| POST | `/api/v1/calendars/{slug}/shares` | `{ user, write }` |
| DELETE | `/api/v1/calendars/{slug}/shares/{user}` | Stop sharing |

## Administration

```text
postwright domain   add | list | remove | dns | catch-all
postwright user     add | passwd | list | remove | disable | enable | vacation | signature
postwright alias    add | remove | list
postwright calendar list | create | share | unshare
postwright queue    list | flush
```

**Address routing**, in order:

1. Exact user
2. Aliases (which can fan out, or forward externally)
3. Sub-addressing (`tony+shop@` goes to `tony@`)
4. Per-domain catch-all

Unknown recipients are rejected at RCPT time, so you never generate backscatter.

## Scalability

- **Fully async (Tokio)**, with no thread per connection. Thousands of concurrent IMAP IDLE sessions cost very little.
- **SQLite in WAL mode** for metadata, with a connection pool. Disk work runs off the network threads.
- **Content-addressed message storage.** One copy per unique message, however many recipients or folders, with reference-counted clean-up.
- **The outbound queue** runs N deliveries in parallel and survives restarts and crashes.
- **IDLE pushes are instant.** New mail and flag changes reach other sessions straight away.

Measured on a small sandbox VM (release build): about 1,400 messages a second inbound over TLS, with 25 concurrent IMAP sessions open. Memory stayed under 100 MB.

This scales **vertically** on a single host, which is plenty for many thousands of mailboxes. Horizontal scaling across several servers would need the storage layer swapped for a shared database and object store. All storage goes through one module (`store.rs`), which is where that would happen.

## Deployment

- **Linux:** see `deploy/postwright.service` (systemd, with sandboxing) and `deploy/Dockerfile`.
- **Windows:** `postwright.exe serve` runs as-is. Use NSSM or `sc.exe` to run it as a service.

## Not yet included

- CardDAV contacts
- Server-side filtering rules (Sieve)
- Content spam scoring (SPF, DKIM, and DMARC checks are in)
- POP3
- IMAP CONDSTORE/QRESYNC
- JMAP

## Building

```sh
cargo build --release
# Windows from Linux:
rustup target add x86_64-pc-windows-gnu && cargo build --release --target x86_64-pc-windows-gnu
```

## Licence

MIT
