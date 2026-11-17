# Postwright

A secure, multi-domain mail server written entirely in Rust. It's the server-side companion to [Mailwright](https://github.com/Tonyscodehub/Mailwright).

One binary provides:

- **SMTP inbound (MX)** on port 25, with SPF, DKIM, and DMARC verification
- **Authenticated submission** on 587 (STARTTLS) and 465 (implicit TLS), with DKIM signing
- **IMAP4rev1** on 143 (STARTTLS) and 993 (TLS), with IDLE push, MOVE, UIDPLUS, and SPECIAL-USE
- **CalDAV calendars and CardDAV contacts**, both shareable, plus an automatic company **Directory** address book
- **Out-of-office auto-replies** and **server-stored signatures**
- **Two-step verification** with any authenticator app (QR code set-up), plus app passwords and recovery codes
- **Shared mailboxes and delegation**: open other people's mailboxes, and **send on behalf of** or **send as** them
- **Webmail** at `https://your-server/`: mail, calendar, and contacts in any browser, on desktop or phone
- **A settings web page and JSON API**, plus Thunderbird-style **autoconfig**
- **An admin console**, both in the browser at `/admin` and as a Windows desktop app (**Postwright Admin**)
- An **outbound queue** with MX failover, retries with back-off, and bounce reports
- **Antispam and antivirus filtering**: built-in checks, plus ClamAV, Rspamd, and SpamAssassin plugins
- **A first-run setup wizard** in the browser: no command lines needed
- **Migrations** from Microsoft 365, Google Workspace, Exchange Server, any IMAP server, Google Takeout and other exported files, and iRedMail (keeping passwords and DKIM keys)

It works with Mailwright, Thunderbird, Apple Mail and Calendar, Outlook (IMAP), iOS, Android (K-9, FairEmail, DAVx5), and anything else that speaks the standards.

## Security model

- **No unauthenticated access to anything that matters.** Port 25 only accepts mail *for* domains hosted here (it can never be used as a relay), and offers no AUTH. Submission, IMAP, CalDAV, and the API all require a login.
- **Credentials only travel encrypted.** SMTP AUTH is refused before STARTTLS (`538 5.7.11`), and IMAP advertises `LOGINDISABLED` until TLS is up. HTTP is HTTPS-only.
- **Two-step verification** (TOTP, RFC 6238) for every user who turns it on. Once it's on, the account password alone opens nothing: mail apps use app passwords, and Mailwright uses a revocable device token. See [Two-step verification](#two-step-verification).
- **No sender spoofing.** Authenticated users can only send as their own address, an alias that delivers to them, or a mailbox they've been given send rights to. This is checked on both the envelope and the `From:` header.
- **Passwords are hashed with Argon2id.** Logins take constant time whether or not the account exists, and concurrent hashing is bounded so a login flood can't exhaust memory.
- **Brute-force protection.** After 5 failed logins in 15 minutes (configurable) an IP is blocked on every protocol.
- **Connection limits.** These apply per listener and per IP, along with idle timeouts and line and literal size caps.
- **Protocol hardening:**
  - STARTTLS command-injection defence: pipelined plaintext is discarded.
  - SMTP smuggling defence: only `<CRLF>.<CRLF>` ends DATA.
  - Forged `Authentication-Results` headers are stripped.
  - Inbound mail failing DMARC with `p=reject` is rejected.
- **TLS 1.2 and 1.3 only**, via rustls. No OpenSSL.

## System requirements

Postwright itself is light. Almost all the memory goes to the optional ClamAV and spam-filter plugins.

**Postwright on its own** (measured):

- **Memory:** about 12 MB at idle, under 100 MB under load. Password checks use about 19 MB each by design, and they're capped at 2 to 8 at a time (depending on CPU cores), so memory stays flat under a login flood.
- **CPU:** any x86-64 processor. One core is plenty for a household or small business; it handled about 1,400 messages a second over TLS in testing.
- **Disk:** your mail plus a few percent for the database. An SSD is recommended. Identical messages are stored only once.

**Optional scanners** (typical figures):

| Component | RAM |
|---|---|
| ClamAV | about 1.5 GB, roughly double while it reloads virus definitions (set `ConcurrentDatabaseReload no` in `clamd.conf` to avoid the spike) |
| Rspamd | 200 to 500 MB |
| SpamAssassin | 150 to 300 MB (normally use Rspamd *or* SpamAssassin, not both) |

**Suggested specs:**

| Setup | CPU | RAM | Disk |
|---|---|---|---|
| Postwright only (built-in spam checks) | 1 core | 512 MB to 1 GB | SSD, mail size + 25% |
| With ClamAV and Rspamd (recommended) | 2 cores | 4 GB | SSD, mail size + 25% |
| Busier (dozens of users, heavy mail) | 4 cores | 8 GB | SSD, mail size + 25% |

**Platforms:**

- **Linux:** the static x86-64 binary runs on any distribution, including Rocky, Alma, RHEL, Debian, and Ubuntu.
- **Windows:** Windows 10, 11, or Server 2016 and later, x86-64.
- **Desktop app:** Postwright Admin needs Windows 10 or later with OpenGL 2 or newer, which any current graphics driver provides.

ClamAV and Rspamd are Linux services. With Postwright on Windows, run them on a small Linux VM or container and point Postwright at their network addresses. The built-in checks still run locally.

## Quick start

1. Put Postwright on the server: copy `postwright.exe` into a folder of its own on Windows, or `postwright` to `/usr/local/bin` on Linux.
2. Start it:
   - **Windows:** right-click `postwright.exe` → **Run as administrator**.
   - **Linux:** `sudo postwright`
3. The first time, it opens a **setup page** in your browser (on Linux, open the link it prints). The browser will warn about the certificate: that's expected until a real one is installed, so continue to the page.

The wizard walks through each step in order, checking as it goes:

1. **Server name:** for example `mail.yourcompany.com`, with a live check of its DNS, reverse DNS, and whether outgoing port 25 is blocked.
2. **Your mail today:** starting fresh, iRedMail on this machine, or another system.
3. **Domains:** add each one; DKIM keys are generated.
4. **Your administrator account**, or make an imported account an administrator.
5. **Certificate:** OPNsense ACME push (it shows the exact values to enter), paste one you have, or later.
6. **Spam and viruses:** ClamAV, Rspamd and SpamAssassin are found automatically if they're running.
7. **DNS records:** each record to publish, with copy buttons and a live check.
8. **Bring mail across** from Microsoft 365, Google, Exchange, IMAP or files (see [Migrations](#migrations)).
9. **Finish:** installs Postwright as a **service that starts automatically at boot** (a Windows service, or a systemd service on Linux) and restarts itself if it ever stops, then hands over to it and takes you to the sign-in page.

The setup page is protected by a one-time code printed in Postwright's window (it's already in the link it opens) and only answers on your local network. If Postwright is running as a service, the code is in `setup-code.txt` (and `postwright.log` on Windows) in the data folder: `C:\ProgramData\Postwright` on Windows, `/var/lib/postwright` on Linux. Once an administrator exists and setup is finished, it's gone.

Everything can also be done from the command line, for scripting:

```sh
postwright init --hostname mail.example.com      # writes the settings (+ a self-signed cert)
postwright domain add example.com                # generates a DKIM key and prints the DNS records
postwright user add tony@example.com             # prompts for the password
postwright user admin tony@example.com
postwright serve
```

### Connecting Mailwright or any mail app

| | Server | Port | Security | Username |
|---|---|---|---|---|
| IMAP | mail.example.com | 993 | SSL/TLS | full email address |
| SMTP | mail.example.com | 465 | SSL/TLS | full email address |
| SMTP (alternative) | mail.example.com | 587 | STARTTLS | full email address |
| Calendars (CalDAV) | `https://mail.example.com/dav/` | 443 | TLS | full email address |
| Contacts (CardDAV) | `https://mail.example.com/dav/` | 443 | TLS | full email address |

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

- SOGo contacts (export them from SOGo as .vcf and import them on the settings page)
- mlmmj list archives (list members do become aliases)
- Sieve filter rules

## Webmail

Users sign in at `https://your-server/` with their email address and password (and their two-step code, if they've turned that on). It works on desktop and phone browsers, and everything in it is the same mailbox, calendar, and contacts that Outlook, phones, and Thunderbird see, so changes show up everywhere straight away.

- **Mail:**
  - folders with unread counts, searching, and an unread-only filter;
  - reading with attachments;
  - writing with formatting, attachments (drag and drop, up to 25 MB), Cc/Bcc, and address suggestions from your contacts and the Directory;
  - replying, replying to all, and forwarding (with the original attachments);
  - drafts, saved automatically every minute;
  - moving (or dragging onto a folder), Junk, flags, read/unread, deleting, and downloading as `.eml`;
  - creating, renaming, and deleting folders;
  - sending from your aliases, and **as** or **on behalf of** someone who has given you that right.
- **Calendar:** day, week, and month views across your own and shared calendars.
  - Create, edit, and delete events, including all-day and repeating ones; delete a single occurrence or the whole series.
  - **Invite people.** They get a standard invitation that works in Outlook, Apple Calendar, Gmail, and Postwright. Their answers update your copy of the event, and deleting the meeting tells them it's cancelled.
  - Invitations you receive show **Accept / Maybe / Decline**, which add the event to your calendar and tell the organiser.
- **Contacts:** browse and search all your address books (including the Directory), and add, edit, or delete contacts.
- **Keyboard shortcuts** in mail: `n` new, `r` reply, `a` reply all, `f` forward, `Delete`, and `j`/`k` (or the arrow keys) for the next and previous message.

**Safety:**
- Messages are shown in a sandboxed frame where scripts can't run.
- Pictures from the internet (often used to track opening) are hidden until you click **Show pictures**, and are never shown for mail in Junk.
- Attachments always download rather than open in the page, apart from images and PDFs.
- Mail sent from the browser gets the same treatment as mail from an email app: sender checks, outbound virus and spam scanning, your server-side signature, DKIM signing, and a copy in **Sent**.

The settings page (out of office, signature, two-step verification, app passwords, sharing) is at `/settings`, linked from the menu under your name.

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

## Migrations

Under **Administration → Migration** (or step 8 of the setup wizard), choose where the mail is now:

| From | How Postwright reads it | Mail | Calendars | Contacts |
|---|---|---|---|---|
| **Microsoft 365 / Exchange Online** | An app registration with read-only Graph permissions (the page shows the five steps). Lists every mailbox for you. | ✓ | ✓ | ✓ |
| **Google Workspace** | A service account with domain-wide delegation (the page shows the steps). Lists every user for you. | ✓ | ✓ | ✓ |
| **Exchange Server (on-premises)** | IMAP with one administrator account that has Full Access to the mailboxes | ✓ | via .ics | via .vcf |
| **Any IMAP server** (cPanel, Plesk, Dovecot, Zimbra, Gmail, Yahoo, iCloud, Fastmail…) | Each user's password or app password, or a Dovecot master user | ✓ | via .ics | via .vcf |
| **Exported files** | Google Takeout (Gmail labels become folders), mbox from Thunderbird or Apple Mail, .ics, .vcf | ✓ | ✓ | ✓ |
| **iRedMail** | Directly from its database and Maildirs, keeping passwords and DKIM keys (see below) | ✓ | ✓ | |

**What's kept:** folders (including subfolders and non-English names), read, flagged, answered and draft status, received dates, repeating meetings with their exceptions and cancelled occurrences, reminders, attendees, and contact details.

**What's left behind:** Exchange's Sync Issues, Outbox and other system folders; Gmail's All Mail, Important and Starred views (Gmail labels are kept as folders instead); other people's calendars that were only shared with the user.

**Accounts** that don't exist yet are created (and their domains added, with DKIM keys). They get new random passwords, because Microsoft and Google don't reveal the old ones: download them as a CSV when the migration finishes, and hand them out. Display names come across too.

**Nothing is changed on the old system**, and a migration can be **run again** at any time: only what's new is copied. So:

1. Run the migration while the old system is still live (it can take hours for large mailboxes; it runs in the background).
2. Switch your MX records to Postwright.
3. Click **Run again (catch up)** the next day to copy anything that arrived at the old system in the meantime.
4. Remove the app registration or service account you created.

Up to three mailboxes are copied at once, with automatic back-off when Microsoft or Google ask it to slow down.

From the command line, a migration is a JSON file:

```json
{
  "source": { "kind": "exchange_online", "tenant": "contoso.onmicrosoft.com", "client_id": "...", "client_secret": "..." },
  "mailboxes": [ { "source": "amy@contoso.com", "target": "amy@contoso.com" } ],
  "options": { "mail": true, "calendars": true, "contacts": true, "create_users": true, "since": null }
}
```

```sh
postwright migrate discover job.json      # list the mailboxes on the old system
postwright migrate run job.json           # copy (run again to catch up)
postwright migrate files ./Takeout --user amy@contoso.com
```

Other sources: `{"kind": "google", "service_account": "<JSON key text>", "admin_email": "admin@company.com"}`, or `{"kind": "imap", "host": "mail.old.com", "port": 993, "security": "tls", "admin": {"user": "admin", "password": "...", "style": "plain"}}` (`"style": "dovecot"` for a Dovecot master user; leave out `admin` and give each mailbox a `password` instead).

## Contacts

Every user has a **Contacts** address book, can create more, and can share them view-only or editable, just like calendars. Phones, Thunderbird, Apple Contacts and DAVx5 find them automatically from the server name.

There's also a read-only **Directory** address book listing everyone in the same email domain, with their aliases. It updates itself as people join and leave. Set `directory = "all"` under `[contacts]` to list everyone on the server, or `"off"` to hide it. Each person can set the name shown there under "Your name" on their settings page.

Contacts can be imported from a .vcf file on the settings page, and each address book downloads as one .vcf.

## Calendars and sharing

Every user gets a default calendar and can create more from their calendar app, the web page, or the CLI. Calendars can be shared view-only or editable. Shared calendars appear automatically in the other person's calendar app.

```sh
postwright calendar create tony@example.com "Poffles rota"
postwright calendar share tony@example.com poffles-rota amy@example.co.uk --write
postwright calendar list amy@example.co.uk
```

Each calendar can also be downloaded as a single `.ics` with `GET` on its URL.

## Two-step verification

Each user turns it on themselves from their settings page (`https://mail.example.com/`):

1. Click **Set up an authenticator app** and scan the QR code with Microsoft Authenticator, Google Authenticator, Authy, 1Password, Bitwarden, or any other TOTP app. The key is also shown as text for apps that can't scan.
2. Type the 6-digit code to confirm. Nothing changes until this step succeeds, so a mis-scan can't lock anyone out.
3. Save the 10 **recovery codes** it shows. Each one works once in place of a code if the phone is lost. A fresh set can be made at any time.

After that:

| Where | How you sign in |
|---|---|
| Settings page, admin console | Password, then a code from the app |
| Postwright Admin (desktop) | Password, then a code from the app |
| Mailwright | Password and code once; it then keeps a device token (see below) |
| Outlook, Thunderbird, phone mail apps, calendar apps | An **app password** made on the settings page. The account password no longer works for IMAP, SMTP or CalDAV. |

**App passwords** look like `abcd-efgh-jkmn-pqrs`. Make one per app, so a lost laptop can be cut off without changing anything else. The settings page shows when each was last used. They can't be used to sign in to the web pages.

**Signed-in browsers and apps** are listed on the settings page, and any of them can be signed out. Web sessions expire after 12 hours idle (7 days at most). Changing your password, turning on two-step verification, or an admin reset signs out everything else.

**Lost phone and recovery codes?** An administrator resets it from the console (Users → Edit → *Reset two-step verification*), the desktop app, or `postwright user mfa-reset <email>`. That also signs the user out everywhere and removes their app passwords, so they start clean.

To insist that administrators use it, set `require_mfa_for_admins = true` under `[security]`: the console and admin API then refuse admins who haven't turned it on.

Codes are checked with ±30 seconds of clock drift allowed, and each code can be used only once. Secrets are generated on the server and never leave it after set-up. Recovery codes and app passwords are stored only as hashes.

### Mailwright token sign-in

Mailwright can sign in once with the password and code, then use a long-lived **device token** for IMAP, SMTP and CalDAV, so the user never needs an app password for it:

1. `POST /api/v1/login` with `{"email", "password", "code", "kind": "device", "name": "Mailwright on LAPTOP"}`.
   - If two-step verification is on and no code was sent, the reply is `401 {"mfa_required": true}`: ask for the code and send again.
   - On success the reply contains `{"token": "..."}`. Store it in the OS credential store.
2. Sign in to IMAP and SMTP with SASL **OAUTHBEARER** (RFC 7628) or **XOAUTH2**, using the token as the bearer token. Both are advertised once TLS is up. CalDAV and the settings API accept `Authorization: Bearer <token>`.
3. The token stays valid while it's used at least once every 90 days. It appears on the user's *Signed-in browsers and apps* list, where it can be revoked, and it stops working after a password change or an admin reset. When IMAP or SMTP rejects it, sign in again from step 1.

## Shared mailboxes and send on behalf

An administrator can let one user into another's mailbox, and separately let them send from it. Use the console's **Mailbox access** page, the desktop app, or:

```sh
postwright delegate grant amy@example.com tony@example.com --mailbox full --send on-behalf
postwright delegate list
postwright delegate revoke amy@example.com tony@example.com
```

**Mailbox access:**

- **Read only:** read and search everything, but change nothing. Opening mail doesn't mark it as read for the owner.
- **Full access:** also flag, file, delete, and add mail.

The mailbox appears in the user's mail app under **Other Users/amy@example.com/** (announced through IMAP NAMESPACE, so Thunderbird, Outlook and Mailwright show it as a separate tree). Changes show up in the owner's apps straight away. Only the owner can create, rename or delete folders. Every time someone opens another person's folder, it's written to the log.

**Sending:**

- **Send on behalf:** Tony can put `From: Amy` on a message. Postwright adds `Sender: tony@example.com` (replacing any `Sender:` the app wrote), so recipients see "Tony on behalf of Amy". This is the usual choice for assistants.
- **Send as:** the message looks exactly as if Amy had sent it. Use it for shared addresses like a team mailbox.

In both cases the message is DKIM-signed for Amy's domain, so it passes DMARC. Users can see what's been shared with them on their settings page.

## Settings API

Sign in with `POST /api/v1/login` (`kind: "web"` sets a session cookie; `"app"` or `"device"` returns a bearer token). All other endpoints need that cookie or `Authorization: Bearer <token>`. HTTP Basic auth is only accepted for CalDAV and CardDAV. State-changing calls must send `Content-Type: application/json`.

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/login` | `{ email, password, code?, kind, name? }`. Returns `401 {mfa_required: true}` when a code is needed |
| POST | `/api/v1/logout` | End this session |
| GET | `/api/v1/me` | Account, quota, and connection settings |
| GET / PUT | `/api/v1/settings` | `{ vacation: {enabled, subject, body, start, end, internal_only}, signature: {text, html, append} }` |
| POST | `/api/v1/password` | `{ current, new }` |
| GET / POST | `/api/v1/calendars` | List (with shares), or create `{ name, color }` |
| DELETE | `/api/v1/calendars/{slug}` | Delete (owner) or leave (sharee) |
| POST | `/api/v1/calendars/{slug}/shares` | `{ user, write }` |
| DELETE | `/api/v1/calendars/{slug}/shares/{user}` | Stop sharing |
| GET / POST | `/api/v1/addressbooks` | List (with counts and shares), or create `{ name }` |
| DELETE | `/api/v1/addressbooks/{slug}` | Delete (owner) or leave (sharee) |
| POST / DELETE | `/api/v1/addressbooks/{slug}/shares[/{user}]` | Share `{ user, write }` or stop sharing |
| POST | `/api/v1/addressbooks/{slug}/import` | `{ vcf }`: import a .vcf file's contents |
| PUT | `/api/v1/name` | `{ name }`: your display name |
| GET | `/api/v1/mfa` | Two-step verification status |
| POST | `/api/v1/mfa/setup` | Start set-up: returns `{ secret, uri, qr_svg }` |
| POST | `/api/v1/mfa/confirm` | `{ code }`. Turns it on and returns `{ recovery_codes }` |
| POST | `/api/v1/mfa/recovery-codes` | `{ code }`. Replaces the recovery codes |
| POST | `/api/v1/mfa/disable` | `{ password, code }` |
| GET / POST | `/api/v1/app-passwords` | List, or create `{ name }` (the password is returned once) |
| DELETE | `/api/v1/app-passwords/{id}` | Remove an app password |
| GET | `/api/v1/devices` | Signed-in browsers and apps |
| DELETE | `/api/v1/devices/{id}` | Sign one out |
| GET | `/api/v1/shared` | Mailboxes shared with me, and my send rights |

## Administration

### Admin console and desktop app

Give an account admin rights first:

```sh
postwright user admin tony@example.com
```

Then use either:

- **Web console:** `https://mail.example.com/admin`, which works in any browser.
- **Postwright Admin:** the Windows desktop app (`postwright-admin.exe`). Sign in with the server name, your email, and your password (and a code, if you use two-step verification). If the server uses a self-signed certificate, the app shows its SHA-256 fingerprint and asks you to trust it once. After that it only accepts that exact certificate. When the certificate is renewed, the app either notices it's now publicly trusted and stops pinning, or shows the new fingerprint for you to check. Your password is never saved.

Both offer the same tools:

- **Overview:** counts, storage, scanner health, and the server's DNS and reverse DNS.
- **Domains:** add a domain (DKIM key generated), add an alias domain, set a catch-all, and remove a domain. A live DNS check shows each MX, SPF, DKIM, and DMARC record to publish, whether it's live, and a copy button.
- **Users:** search, add, set quotas, reset passwords, enable or disable, grant admin rights, and reset two-step verification. Shows usage, out-of-office, two-step status, and imported passwords.
- **Mailbox access:** who can open whose mailbox (read only or full), and who can send on behalf of or as whom.
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
postwright service  install | uninstall | start | stop | status
postwright migrate  run | discover | files
postwright import   iredmail
postwright user     add | passwd | list | remove | disable | enable | admin | mfa-reset | vacation | signature
postwright delegate grant | revoke | list
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
- **Windows:** run `postwright.exe` as administrator; the setup wizard's last step installs it as a Windows service (**Postwright mail server** in Services) that starts at boot, before anyone signs in, and restarts itself after a failure. Its log is `C:\ProgramData\Postwright\postwright.log`. Allow ports 25, 465, 587, 993, 443, and 2222 (from OPNsense only) in Windows Firewall.
- **Both:** the service can also be managed from the command line:

```sh
postwright service install --start    # install (or update) and start; starts at every boot
postwright service status
postwright service stop | start
postwright service uninstall
```

On Windows, `service install` also adds Windows Firewall rules for ports 25, 465, 587, 143, 993 and 443, and 2222 from the local network (`service uninstall` removes them). **Upgrading on Windows:** unzip the new version into a folder of its own and double-click its `postwright.exe`. The settings and mail are in the registry and `C:\ProgramData\Postwright`, so it carries on with them. If the service is running the older version, it offers to switch the service to the new one.

The service runs the program from where it was installed, so keep that folder (or run `service install` again from the new one). Double-clicking `postwright.exe` while the service is running just opens the admin console.

## Where settings and data are kept

| | Settings | Mail, certificates, logs |
|---|---|---|
| **Windows** | Registry: `HKEY_LOCAL_MACHINE\SOFTWARE\Postwright` | `C:\ProgramData\Postwright` (`data`, `postwright.log`) |
| **Linux** (root, or a service) | `/etc/postwright/postwright.toml` | `/var/lib/postwright` (logs go to the journal) |
| **Linux** (an ordinary user) | `~/.config/postwright/postwright.toml` | `~/.local/share/postwright` |
| **`-c FILE`** (any platform) | that file | `data` next to it, unless the file says otherwise |

In the registry, each `[section]` of the settings is a subkey: text is `REG_SZ`, lists of text are `REG_MULTI_SZ`, on/off settings and whole numbers are `REG_DWORD`, decimals are `REG_SZ`, and lists of sections (such as `filter\dnsbl`) are numbered subkeys. Anything missing takes its default. Changes made in `regedit` apply when Postwright restarts. A plain copy, `settings-backup.toml`, is written to `C:\ProgramData\Postwright` each time Postwright saves the settings, for reference and recovery only.

```sh
postwright config where              # where the settings and data are
postwright config show               # print the settings
postwright config export backup.toml
postwright config import backup.toml # checked first; nothing changes if it's not valid
```

**Coming from an earlier version on Windows** (0.5.6 and before kept `postwright.toml` next to the program): the first time a newer version runs, it finds that file (next to itself, in a neighbouring version folder, or the one the installed service uses), moves the settings into the registry and the mail folder into `C:\ProgramData\Postwright\data`, and renames the old file to `postwright.toml.migrated`. If the service used it, the service is stopped for the move, switched to the new program and started again. It needs **Run as administrator**; without it, Postwright keeps using the old file until it's next run as administrator. On Linux, an existing `postwright.toml` in the current folder keeps working, and the systemd unit already names its file.

The desktop admin app keeps its server, email address and approved certificates in `HKEY_CURRENT_USER\Software\Postwright\Admin` on Windows and `~/.config/postwright-admin/settings.json` on Linux; settings from earlier versions are moved there the first time it runs.

## Not yet included

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
