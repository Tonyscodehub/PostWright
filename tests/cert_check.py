"""Certificate push tests: replays OPNsense's SFTP automation with OpenSSH's sftp client."""
import os, subprocess, sys, time, hashlib, ssl, socket
B = os.environ.get("PW_BIN", "/home/claude/postwright-repo/target/" + os.environ.get("PROFILE", "release") + "/postwright")
CFG = "/tmp/pwtest/filter.toml"
W = "/tmp/certtest"
R = []

def check(n, c, i=""):
    R.append(bool(c)); print(("PASS " if c else "FAIL ") + n + (f"  [{i}]" if i and not c else ""))

def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)

def served_fp(port=1993):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port)) as s, ctx.wrap_socket(s) as t:
        return hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest().upper()

def make_cert(name, cn, ca_key, ca_crt):
    sh(f"openssl req -newkey rsa:2048 -nodes -keyout {W}/{name}.key -subj /CN={cn} -addext subjectAltName=DNS:{cn} -out {W}/{name}.csr")
    sh(f"printf 'subjectAltName=DNS:{cn}' > {W}/{name}.ext")
    sh(f"openssl x509 -req -in {W}/{name}.csr -CA {ca_crt} -CAkey {ca_key} -CAcreateserial -days 90 -extfile {W}/{name}.ext -out {W}/{name}.crt")
    return open(f"{W}/{name}.crt", "rb").read()

def der_fp(pem_path):
    out = sh(f"openssl x509 -in {pem_path} -noout -fingerprint -sha256").stdout
    return out.split("=", 1)[1].strip().replace(":", "")

def sftp(batch, key=f"{W}/acme_rsa", user="acme"):
    open(f"{W}/batch", "w").write(batch)
    return sh(f"sftp -b {W}/batch -P 2222 -i {key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new "
              f"-o UserKnownHostsFile={W}/known_hosts {user}@127.0.0.1", cwd=W)

sh(f"rm -rf {W}"); os.makedirs(W)
# OPNsense-style RSA identity, shown with a from= restriction prefix
sh(f"ssh-keygen -q -t rsa -b 3072 -N '' -C root@OPNsense.internal -f {W}/acme_rsa")
sh(f"ssh-keygen -q -t ed25519 -N '' -C intruder -f {W}/other")
pub = open(f"{W}/acme_rsa.pub").read().strip()
r = sh(f"{B} -c {CFG} cert key-add 'from=\"127.0.0.1\",restrict {pub}'")
check("cert key-add accepts OPNsense identity line", r.returncode == 0 and "SHA256:" in r.stdout, r.stdout + r.stderr)

# A private CA and certificates
sh(f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {W}/ca.key -subj '/CN=Test ACME CA' -days 365 -out {W}/ca.crt")
make_cert("good", "mail.test.local", f"{W}/ca.key", f"{W}/ca.crt")
make_cert("wrong", "other.example", f"{W}/ca.key", f"{W}/ca.crt")
os.makedirs(f"{W}/upload", exist_ok=True)
open(f"{W}/upload/cert.pem", "wb").write(open(f"{W}/good.crt", "rb").read())
open(f"{W}/upload/ca.pem", "wb").write(open(f"{W}/ca.crt", "rb").read())
open(f"{W}/upload/fullchain.pem", "wb").write(open(f"{W}/good.crt", "rb").read() + open(f"{W}/ca.crt", "rb").read())
open(f"{W}/upload/key.pem", "wb").write(open(f"{W}/good.key", "rb").read())

before = served_fp()
# OPNsense "Test connect": pwd, cd, upload a test file, remove it
r = sftp("pwd\ncd /home/acme\nput /etc/hostname .acme-sftp-test\nrm .acme-sftp-test\n")
check("OPNsense 'Test connect' sequence succeeds", r.returncode == 0, r.stderr)
# OPNsense upload: cd into remote path, mkdir {{name}}, put ca, cert, fullchain, key (key last), chmod
r = sftp("pwd\n-mkdir mail.test.local\ncd mail.test.local\nls -la\nput upload/ca.pem ca.pem\nput upload/cert.pem cert.pem\n"
         "put upload/fullchain.pem fullchain.pem\nput upload/key.pem key.pem\nchmod 440 cert.pem\nchmod 400 key.pem\n")
check("OPNsense upload sequence succeeds", r.returncode == 0, r.stderr + r.stdout)
time.sleep(1.5)
now = served_fp()
check("new certificate served immediately on IMAPS", now == der_fp(f"{W}/good.crt") and now != before, (before[:16], now[:16]))
check("installed files written to the TLS paths", open("/tmp/pwtest/data/tls/key.pem").read() == open(f"{W}/good.key").read())
st = sh(f"{B} -c {CFG} cert status").stdout
check("cert status shows new certificate and expiry", "mail.test.local" in st and "Test ACME CA" in st and ("89 days" in st or "90 days" in st), st)

# Wrong host name: refused, current certificate kept
open(f"{W}/upload/fullchain.pem", "wb").write(open(f"{W}/wrong.crt", "rb").read())
open(f"{W}/upload/key.pem", "wb").write(open(f"{W}/wrong.key", "rb").read())
r = sftp("put upload/fullchain.pem fullchain.pem\nput upload/key.pem key.pem\n")
time.sleep(1.5)
check("certificate for another host refused, old one kept", served_fp() == der_fp(f"{W}/good.crt"))
log = open("/tmp/pwtest/server.log").read()
check("refusal explained in the log", "does not cover mail.test.local" in log)

# Mismatched key: refused
open(f"{W}/upload/fullchain.pem", "wb").write(open(f"{W}/good.crt", "rb").read())
r = sftp("put upload/fullchain.pem fullchain.pem\nput upload/key.pem key.pem\n")
time.sleep(1.5)
check("mismatched key refused", served_fp() == der_fp(f"{W}/good.crt") and "does not match the certificate" in open("/tmp/pwtest/server.log").read())

# Security: no reading back, no shell/exec, unknown key and wrong user rejected
r = sftp("get key.pem /tmp/stolen.pem\n")
check("files can't be downloaded", r.returncode != 0 and not os.path.exists("/tmp/stolen.pem"))
r = sh(f"ssh -p 2222 -i {W}/acme_rsa -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile={W}/known_hosts -o BatchMode=yes acme@127.0.0.1 id")
check("command execution refused", r.returncode != 0 and "uid=" not in r.stdout)
r = sftp("pwd\n", key=f"{W}/other")
check("unapproved key rejected", r.returncode != 0)
r = sftp("pwd\n", user="root")
check("wrong user name rejected", r.returncode != 0)
r = sh(f"ssh -p 2222 -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=0 "
       f"-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile={W}/known_hosts acme@127.0.0.1 true")
check("password logins not offered", r.returncode != 0)

# Watcher: replacing the files any other way is picked up without a restart
make_cert("renew", "mail.test.local", f"{W}/ca.key", f"{W}/ca.crt")
open(f"{W}/renew-full.pem", "wb").write(open(f"{W}/renew.crt", "rb").read() + open(f"{W}/ca.crt", "rb").read())
r = sh(f"{B} -c {CFG} cert install --fullchain {W}/renew-full.pem --key {W}/renew.key")
check("cert install validates and writes", r.returncode == 0, r.stderr)
for _ in range(20):
    time.sleep(1)
    if served_fp() == der_fp(f"{W}/renew.crt"):
        break
check("file watcher reloads within seconds (no restart, no signal)", served_fp() == der_fp(f"{W}/renew.crt"))
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
