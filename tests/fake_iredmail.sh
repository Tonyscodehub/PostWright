#!/bin/sh
# Builds a realistic iRedMail (MariaDB backend) environment on this machine for testing
# `postwright import iredmail`. Schema follows iRedMail 1.x (vmail + SOGo combined tables).
set -e

mysql <<'SQL'
DROP DATABASE IF EXISTS vmail; CREATE DATABASE vmail; USE vmail;
CREATE TABLE domain (domain VARCHAR(255) PRIMARY KEY, active TINYINT(1) NOT NULL DEFAULT 1);
CREATE TABLE alias_domain (alias_domain VARCHAR(255) PRIMARY KEY, target_domain VARCHAR(255), active TINYINT(1) DEFAULT 1);
CREATE TABLE mailbox (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255), name VARCHAR(255), storagebasedirectory VARCHAR(255),
  storagenode VARCHAR(255), maildir VARCHAR(255), quota BIGINT DEFAULT 0, active TINYINT(1) DEFAULT 1);
CREATE TABLE forwardings (id INT AUTO_INCREMENT PRIMARY KEY, address VARCHAR(255), forwarding VARCHAR(255), domain VARCHAR(255),
  dest_domain VARCHAR(255), is_maillist TINYINT(1) DEFAULT 0, is_list TINYINT(1) DEFAULT 0, is_forwarding TINYINT(1) DEFAULT 0,
  is_alias TINYINT(1) DEFAULT 0, active TINYINT(1) DEFAULT 1);
INSERT INTO domain VALUES ('legacy.test',1),('shop.test',1);
INSERT INTO alias_domain VALUES ('legacy-alias.test','legacy.test',1);
-- SSHA512 of 'OldPassword1' with salt 'saltsalt', and BCRYPT of 'AmyPass123' (generated below by python)
INSERT INTO mailbox VALUES
 ('dave@legacy.test','__SSHA__','Dave','/var/vmail','vmail1','legacy.test/d/a/v/dave-2019/',500,1),
 ('erin@legacy.test','__BCRYPT__','Erin','/var/vmail','vmail1','legacy.test/e/r/i/erin-2020/',0,1),
 ('gone@shop.test','__SSHA__','Old','/var/vmail','vmail1','shop.test/g/o/n/gone-2018/',0,0);
INSERT INTO forwardings (address, forwarding, is_forwarding, is_alias, is_list) VALUES
 ('dave@legacy.test','dave@legacy.test',1,0,0),
 ('sales@shop.test','dave@legacy.test',0,0,0),
 ('sales@shop.test','erin@legacy.test',0,0,0),
 ('d@legacy.test','dave@legacy.test',0,1,0),
 ('erin@legacy.test','erin.home@example.org',1,0,0);

DROP DATABASE IF EXISTS sogo; CREATE DATABASE sogo; USE sogo;
CREATE TABLE sogo_folder_info (c_folder_id INT AUTO_INCREMENT PRIMARY KEY, c_path VARCHAR(255), c_path1 VARCHAR(255), c_path2 VARCHAR(255),
  c_path3 VARCHAR(255), c_path4 VARCHAR(255), c_foldername VARCHAR(255), c_location VARCHAR(2048), c_quick_location VARCHAR(2048),
  c_acl_location VARCHAR(2048), c_folder_type VARCHAR(255));
CREATE TABLE sogo_store (c_folder_id INT, c_name VARCHAR(255), c_content MEDIUMTEXT, c_creationdate INT, c_lastmodified INT, c_version INT, c_deleted INT);
CREATE TABLE sogo_acl (c_folder_id INT, c_object VARCHAR(255), c_uid VARCHAR(255), c_role VARCHAR(80));
INSERT INTO sogo_folder_info (c_path, c_path1, c_path2, c_path3, c_path4, c_foldername, c_folder_type) VALUES
 ('/Users/dave@legacy.test/Calendar/personal','Users','dave@legacy.test','Calendar','personal','Personal Calendar','Appointment'),
 ('/Users/dave@legacy.test/Calendar/1A2B-3C','Users','dave@legacy.test','Calendar','1A2B-3C','Shop rota','Appointment'),
 ('/Users/dave@legacy.test/Contacts/personal','Users','dave@legacy.test','Contacts','personal','Personal Address Book','Contact');
INSERT INTO sogo_store VALUES
 (1,'ev-1.ics','BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:ev-1\r\nDTSTART:20261201T090000Z\r\nDTEND:20261201T100000Z\r\nSUMMARY:Dentist\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n',0,0,0,NULL),
 (1,'gone.ics','BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:gone\r\nDTSTART:20261201T090000Z\r\nSUMMARY:Deleted\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n',0,0,0,1),
 (2,'rota-1.ics','BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:rota-1\r\nDTSTART:20261205T080000Z\r\nDTEND:20261205T160000Z\r\nRRULE:FREQ=WEEKLY\r\nSUMMARY:Saturday shift\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n',0,0,0,NULL);
INSERT INTO sogo_acl VALUES (2,'/Users/dave@legacy.test/Calendar/1A2B-3C','erin@legacy.test','ObjectEditor'),
 (2,'/Users/dave@legacy.test/Calendar/1A2B-3C','<default>','PublicViewer');
CREATE USER IF NOT EXISTS 'sogo'@'localhost' IDENTIFIED BY 'S0go!pass';
GRANT ALL ON sogo.* TO 'sogo'@'localhost';
SQL

SSHA=$(python3 -c "import hashlib,base64;s=b'saltsalt';print('{SSHA512}'+base64.b64encode(hashlib.sha512(b'OldPassword1'+s).digest()+s).decode())")
BCRYPT=$(htpasswd -nbB x AmyPass123 2>/dev/null | cut -d: -f2)
[ -z "$BCRYPT" ] && BCRYPT='{CRYPT}$2y$05$abcdefghijklmnopqrstuuJfOsR1JrcTLtkymYvXeYTV0uJQ2eD6' # fallback
mysql vmail -e "UPDATE mailbox SET password='$SSHA' WHERE password='__SSHA__'; UPDATE mailbox SET password='{CRYPT}$BCRYPT' WHERE password='__BCRYPT__';"

# Config files iRedMail leaves behind
mkdir -p /etc/postfix /etc/amavisd /etc/sogo /var/lib/dkim
cat > /etc/postfix/main.cf <<'EOF'
virtual_mailbox_domains = proxy:mysql:/etc/postfix/mysql/virtual_mailbox_domains.cf
EOF
openssl genrsa -traditional -out /var/lib/dkim/legacy.test.pem 2048 2>/dev/null || openssl genrsa -out /var/lib/dkim/legacy.test.pem 2048
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /var/lib/dkim/shop.test.pem 2>/dev/null
cat > /etc/amavisd/amavisd.conf <<'EOF'
dkim_key('legacy.test', 'dkim', '/var/lib/dkim/legacy.test.pem');
#dkim_key('commented.test', 'x', '/nope');
dkim_key("shop.test", "s2019", "/var/lib/dkim/shop.test.pem");
EOF
cat > /etc/sogo/sogo.conf <<'EOF'
{
    SOGoProfileURL = "mysql://sogo:S0go%21pass@127.0.0.1:3306/sogo/sogo_user_profile";
    OCSFolderInfoURL = "mysql://sogo:S0go%21pass@127.0.0.1:3306/sogo/sogo_folder_info";
    OCSStoreURL = "mysql://sogo:S0go%21pass@127.0.0.1:3306/sogo/sogo_store";
    OCSAclURL = "mysql://sogo:S0go%21pass@127.0.0.1:3306/sogo/sogo_acl";
}
EOF

# Maildirs (Maildir++ with Dovecot uidlist and keywords), LF line endings as on disk
mk() { mkdir -p "$1/cur" "$1/new" "$1/tmp"; }
D=/var/vmail/vmail1/legacy.test/d/a/v/dave-2019/Maildir
rm -rf /var/vmail; mk $D; mk "$D/.Sent"; mk "$D/.Projects.2024"; mk "$D/.Junk"
printf 'From: a@example.org\nTo: dave@legacy.test\nSubject: Old one\nMessage-ID: <m1@example.org>\n\nhello dave\n' > "$D/cur/1600000000.M1P1.mail,S=100,W=105:2,S"
printf 'From: b@example.org\nTo: dave@legacy.test\nSubject: Flagged keyword\n\nimportant\n' > "$D/cur/1600000100.M2P1.mail,S=90,W=94:2,FRa"
printf 'From: c@example.org\nTo: dave@legacy.test\nSubject: Unread new\n\nnew mail\n' > "$D/new/1600000200.M3P1.mail,S=80,W=84"
touch -d '2020-09-13 12:26:40' "$D/cur/1600000000.M1P1.mail,S=100,W=105:2,S"
printf '3 V1600000000 N4 G1234\n1 :1600000000.M1P1.mail,S=100,W=105\n2 :1600000100.M2P1.mail,S=90,W=94\n3 :1600000200.M3P1.mail,S=80,W=84\n' > "$D/dovecot-uidlist"
printf '0 $Important\n' > "$D/dovecot-keywords"
printf 'From: dave@legacy.test\nTo: x@example.org\nSubject: Sent thing\n\nsent body\n' > "$D/.Sent/cur/1600000300.M4P1.mail:2,S"
printf 'From: dave@legacy.test\nSubject: Project file\n\nproject\n' > "$D/.Projects.2024/cur/1600000400.M5P1.mail:2,S"
E=/var/vmail/vmail1/legacy.test/e/r/i/erin-2020/Maildir; mk $E
printf 'From: z@example.org\nSubject: Erin mail\n\nfor erin\n' > "$E/cur/1600000500.M6P1.mail:2,"
echo "fake iRedMail ready"
