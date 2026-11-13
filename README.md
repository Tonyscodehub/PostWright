# Postwright

A secure, multi-domain mail server written entirely in Rust. It's the server-side companion to [Mailwright](https://github.com/Tonyscodehub/Mailwright).

One binary provides:

- **SMTP inbound (MX)** on port 25, with SPF, DKIM, and DMARC verification
- **Authenticated submission** on 587 (STARTTLS) and 465 (implicit TLS), with DKIM signing
- **IMAP4rev1** on 143 (STARTTLS) and 993 (TLS), with IDLE push, MOVE, UIDPLUS, and SPECIAL-USE
- **CalDAV calendars with sharing** over HTTPS on 443
- **Out-of-office auto-replies** and **server-stored signatures**
- **A settings web page and JSON API**, plus Thunderbird-style **autoconfig**
- **An admin console**, both in the browser at `/admin` and as a Windows desktop app (**Postwright Admin**)
- An **outbound queue** with MX failover, retries with back-off, and bounce reports
- **Antispam and antivirus filtering**: built-in checks, plus ClamAV, Rspamd, and SpamAssassin plugins
- **One-command migration from iRedMail**, keeping passwords, DKIM keys, mail, and calendars

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

Postwright watches its certificate files and **switches to a renewed certificate within seconds, with no restart**, on Windows and Linux alike. If the files are caught mid-update (for example a new certificate but the old key), it keeps the current certificate until both match. It also warns in the log when expiry is under 14 days.

### Pushed from OPNsense (recommended)

Postwright includes a small **upload-only SFTP receiver** (port 2222 by default). OPNsense's ACME client can push renewals straight to it with its standard automation. There's no OpenSSH server to install on Windows and no root SSH access to grant on Linux.

1. In OPNsense, go to **Services > ACME Client > Automations** and add an automation with **Run Command: Upload certificate via SFTP**. Fill in:
   - **Host:** Postwright's LAN address
   - **Port:** `2222`
   - **Username:** `acme`
   - **Remote path:** leave blank
   - **Identity type:** any
2. Click **Show identity** and allow that key in Postwright, either on the console's **Certificate** page or with:
   ```sh
   postwright cert key-add 'from="192.168.1.1",restrict ssh-rsa AAAA… root@OPNsense'
   ```
   Paste the whole line OPNsense shows. Postwright ignores the restriction prefix.
3. Click **Test Connect**. Compare the host key OPNsense records with the fingerprint shown by `postwright cert status` or the Certificate page.
4. Attach the automation to the certificate under **Certificates**, then click **Run automations** once.

Every upload is checked before it's used:

- The private key must match the certificate.
- The certificate must not have expired.
- It must cover the server's host name (turn this off with `certs.require_hostname_match = false`).

A rejected upload leaves the current certificate in place and logs why.

**How the receiver is locked down:**

- Public-key logins only, for keys you've allowed, and only from `security.admin_networks`.
- There's no shell or command execution, and nothing can be downloaded.
- Uploads are held in memory, and only certificate files are acted on.
- Failed logins count towards the same brute-force block as mail logins.

### Other ways

- **Copy the files into place** (certbot deploy hook, SMB share, scp to a Linux box). They're picked up automatically.
- **From the console:** paste a full chain and key on the Certificate page.
- **From the command line:** `postwright cert install --fullchain fullchain.pem --key privkey.pem`

These also validate the certificate and key before installing them.

```toml
[certs]
sftp_listen = ["0.0.0.0:2222"]   # [] to disable the receiver
sftp_user = "acme"
require_hostname_match = true
```

## Outbound reputation

If the server has a static IP with matching reverse DNS (PTR), it sends direct to recipients' MX hosts. With DKIM, SPF, and DMARC in place, mail is accepted by Gmail, Outlook, and the rest.

On a connection without that (dynamic or residential ranges, or blocked outbound port 25), route outbound mail through a smarthost. Postwright still DKIM-signs everything itself, so DMARC alignment stays intact:

```toml
[queue]
relay_host = "smtp.relay-provider.com:587"
relay_username = "..."
relay_password = "..."
```

## Antispam and antivirus

Filtering happens inside the SMTP conversation, so spam and malware are refused before Postwright accepts responsibility for them. That means no backscatter and no bounces to forged senders.

**Built in** (pure Rust, always available):

- DNS blocklists (Spamhaus ZEN and SpamCop by default)
- Pre-greeting "early talker" detection: spambots talk before the banner
- Forward-confirmed reverse DNS
- HELO sanity checks
- Scoring of SPF, DKIM, and DMARC results

Senders' own `X-Spam-*` and forged `Authentication-Results` headers are stripped.

**Plugins**: add a section to enable each one.

```toml
[filter]
junk_score = 5.0      # delivered to the Junk folder at or above this
reject_score = 12.0   # refused at or above this

[filter.clamav]
address = "unix:/run/clamav/clamd.ctl"    # or "127.0.0.1:3310"
on_fail = "tempfail"                     # scanner down: defer mail rather than let it through

[filter.rspamd]
url = "http://127.0.0.1:11333"
password = "..."                          # controller password, for learning

[filter.spamassassin]
address = "127.0.0.1:783"
learn = true                              # needs spamd --allow-tell
```

- **Viruses** are refused, both inbound and from your own users.
- **Spam** scoring combines the built-in checks with the plugins' scores. Rspamd's `reject` action is honoured, and so is its greylisting, for inbound mail only.
- **Learning:** when a user moves a message into Junk, Rspamd and SpamAssassin learn it as spam. Moving it back out of Junk teaches them it's ham.
- **Outbound mail** is scanned for malware and for spam an engine says to reject (a compromised account), but a user's own mail is never junk-filed.

Spamhaus refuses queries arriving via large public resolvers such as Cloudflare or Google. Point the server at your own recursive resolver (Unbound on OPNsense works), or use a Spamhaus DQS zone.

## Migrating from iRedMail

Run the importer **on the iRedMail server, as root**. It uses the credentials iRedMail already configured, so nothing needs opening up. The Linux release is a static binary and runs on Rocky, Alma, RHEL, Debian, or Ubuntu.

```sh
postwright init --hostname mail.example.com --data-dir /var/lib/postwright
postwright import iredmail --dry-run     # shows the detected backend and what it found
postwright import iredmail               # do it
```

**What it does:**

- **Detects the backend** (MariaDB/MySQL, PostgreSQL, or OpenLDAP) from Postfix's configuration.
- **Domains and alias domains:** imported with their **existing DKIM keys and selectors** (from amavisd). DNS needs no changes.
- **Users:** keep their **current passwords**. iRedMail's SSHA512, BCRYPT, SHA512-CRYPT, and other hashes are verified once and then silently upgraded to Argon2id.
- **Aliases, forwarding, and alias accounts:** imported, including "forward and keep a copy" versus "forward only".
- **Mail:** every Maildir folder, with read, flagged, answered, and draft flags, Dovecot keywords, and received dates. **Dovecot's IMAP UIDs and UIDVALIDITY are preserved**, so mail apps don't re-download everything after cutover.
- **SOGo calendars, and who they're shared with**, become Postwright calendars and shares.

It's safe to run repeatedly: anything already imported is skipped.

**Cutover plan:**

1. Do a bulk import while iRedMail is still live.
2. Check it, with Postwright on other ports or another machine.
3. At cutover, stop Postfix and Dovecot, run the import once more to catch the last few minutes, and start Postwright on the standard ports.

Not imported:

- SOGo contacts (no CardDAV yet)
- mlmmj list archives (list members do become aliases)
- Sieve filter rules

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

### Admin console and desktop app

Give an account admin rights first:

```sh
postwright user admin tony@example.com
```

Then use either:

- **Web console:** `https://mail.example.com/admin`, which works in any browser.
- **Postwright Admin:** the Windows desktop app (`postwright-admin.exe`). Sign in with the server name, your email, and your password. If the server uses a self-signed certificate, the app shows its SHA-256 fingerprint and asks you to trust it once. After that it only accepts that exact certificate. When the certificate is renewed, the app either notices it's now publicly trusted and stops pinning, or shows the new fingerprint for you to check. Your password is never saved.

Both offer the same tools:

- **Overview:** counts, storage, scanner health, and the server's DNS and reverse DNS.
- **Domains:** add a domain (DKIM key generated), add an alias domain, set a catch-all, and remove a domain. A live DNS check shows each MX, SPF, DKIM, and DMARC record to publish, whether it's live, and a copy button.
- **Users:** search, add, set quotas, reset passwords, enable or disable, and grant admin rights. Shows usage, out-of-office status, and imported passwords.
- **Aliases:** add and remove.
- **Mail queue:** see retries and errors, retry now, or delete a message.
- **Spam and antivirus:** thresholds, blocklists, and whether each scanner is responding.
- **Certificate:** expiry and names, step-by-step OPNsense setup values, the keys allowed to push certificates, and manual install.
- **Import from iRedMail:** dry run or full import, with live output.
- **Logs:** the last 2,000 lines, with a filter and live updates.

**Security:**

- Only accounts with the admin flag can use the console or app.
- They only work **from the networks in `security.admin_networks`**: loopback and private ranges by default, so it isn't exposed to the internet.
- State-changing requests need JSON or an `X-Requested-With` header, which blocks cross-site attacks.
- You can't remove your own admin rights, disable yourself, or delete yourself.

### Command line

```text
postwright domain   add | alias | list | remove | dns | catch-all
postwright cert     status | key-add | key-list | key-remove | install
postwright import   iredmail
postwright user     add | passwd | list | remove | disable | enable | admin | vacation | signature
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

- **Linux:** the release binary is fully static (musl), so it runs on any x86-64 distribution. See `deploy/postwright.service` (systemd, with sandboxing) and `deploy/Dockerfile`.
- **Windows:** `postwright.exe serve` runs as-is. Use NSSM or `sc.exe` to run it as a service. Allow ports 25, 465, 587, 993, 443, and 2222 (from OPNsense only) in Windows Firewall.

## Not yet included

- CardDAV contacts
- Server-side filtering rules (Sieve)
- POP3
- IMAP CONDSTORE/QRESYNC
- JMAP

## Building

```sh
cargo build --release                       # server and desktop app (workspace)
# Static Linux binary (runs on any distribution):
rustup target add x86_64-unknown-linux-musl && cargo build --release --target x86_64-unknown-linux-musl
# Windows from Linux:
rustup target add x86_64-pc-windows-gnu && cargo build --release --target x86_64-pc-windows-gnu --workspace
```

## Licence

MIT
