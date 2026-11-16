"""Minimal fake Microsoft Graph and Google APIs for migration tests.
Serves both on http://127.0.0.1:9911 (Graph under /graph, login under /login,
Google under /google)."""
import base64, json, re, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

def mime(subject, frm, to, body, date="Mon, 02 Nov 2026 09:00:00 +0000", mid=None):
    mid = mid or f"<{abs(hash(subject))}@fake>"
    return (f"From: {frm}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: {mid}\r\n"
            f"Content-Type: text/plain\r\n\r\n{body}\r\n").encode()

# ------------------------------------------------------------------ Graph data
G_USERS = [
    {"id": "u1", "displayName": "Carol Graph", "mail": "carol@graph.test", "userPrincipalName": "carol@graph.test", "accountEnabled": True},
    {"id": "u2", "displayName": "Shared Sales", "mail": "sales@graph.test", "userPrincipalName": "sales@graph.test", "accountEnabled": False},
    {"id": "u3", "displayName": "No Mail", "mail": None, "userPrincipalName": "nomail@graph.test", "accountEnabled": True},
]
G_FOLDERS = {
    "f-inbox": {"displayName": "Inbox", "children": ["f-proj"]},
    "f-proj": {"displayName": "Projects", "children": []},
    "f-sent": {"displayName": "Sent Items", "children": []},
    "f-cal": {"displayName": "Conversation History", "children": []},
    "f-sync": {"displayName": "Sync Issues", "children": []},
}
G_WK = {"inbox": "f-inbox", "sentitems": "f-sent", "syncissues": "f-sync"}
G_MSGS = {
    "f-inbox": [
        {"id": "m1", "isRead": True, "isDraft": False, "flag": {"flagStatus": "flagged"}, "receivedDateTime": "2026-10-01T10:00:00Z",
         "raw": mime("Graph hello", "x@ext.test", "carol@graph.test", "one")},
        {"id": "m2", "isRead": False, "isDraft": False, "flag": {"flagStatus": "notFlagged"}, "receivedDateTime": "2026-10-02T10:00:00Z",
         "raw": mime("Graph unread", "y@ext.test", "carol@graph.test", "two")},
    ],
    "f-proj": [{"id": "m3", "isRead": True, "isDraft": False, "flag": {}, "receivedDateTime": "2026-09-01T10:00:00Z",
                "raw": mime("Project plan", "z@ext.test", "carol@graph.test", "three")}],
    "f-sent": [{"id": "m4", "isRead": True, "isDraft": False, "flag": {}, "receivedDateTime": "2026-10-03T10:00:00Z",
                "raw": mime("Sent by Carol", "carol@graph.test", "x@ext.test", "four")}],
    "f-sync": [{"id": "m5", "isRead": True, "isDraft": False, "flag": {}, "receivedDateTime": "2026-10-03T10:00:00Z",
                "raw": mime("Sync junk", "a@b", "c@d", "x")}],
}
G_EVENTS = [
    {"id": "e1", "type": "singleInstance", "iCalUId": "graph-e1", "subject": "Dentist", "isAllDay": False,
     "originalStartTimeZone": "GMT Standard Time",
     "start": {"dateTime": "2026-11-20T09:00:00.0000000", "timeZone": "UTC"}, "end": {"dateTime": "2026-11-20T09:30:00.0000000", "timeZone": "UTC"},
     "location": {"displayName": "High St"}},
    {"id": "e2", "type": "seriesMaster", "iCalUId": "graph-e2", "subject": "Team call", "isAllDay": False,
     "originalStartTimeZone": "GMT Standard Time",
     "start": {"dateTime": "2026-10-02T08:00:00.0000000", "timeZone": "UTC"}, "end": {"dateTime": "2026-10-02T08:30:00.0000000", "timeZone": "UTC"},
     "recurrence": {"pattern": {"type": "weekly", "interval": 1, "daysOfWeek": ["friday"]}, "range": {"type": "numbered", "startDate": "2026-10-02", "numberOfOccurrences": 3}}},
]
G_INSTANCES = {"e2": [{"type": "occurrence", "originalStart": "2026-10-02T08:00:00Z"}, {"type": "occurrence", "originalStart": "2026-10-16T08:00:00Z"}]}
G_CONTACTS = [{"id": "c1", "displayName": "Dave Contact", "givenName": "Dave", "surname": "Contact", "emailAddresses": [{"address": "dave@ext.test"}], "mobilePhone": "07700 900123"}]

# ----------------------------------------------------------------- Google data
GO_USERS = [{"primaryEmail": "erin@gw.test", "name": {"fullName": "Erin Google"}, "suspended": False}]
GO_LABELS = [{"id": "INBOX", "name": "INBOX", "type": "system"}, {"id": "Label_1", "name": "Receipts/2026", "type": "user"}]
GO_MSGS = {
    "g1": {"labelIds": ["INBOX", "UNREAD"], "raw": mime("Gmail inbox", "q@ext.test", "erin@gw.test", "g1"), "internalDate": "1790000000000"},
    "g2": {"labelIds": ["SENT"], "raw": mime("Gmail sent", "erin@gw.test", "q@ext.test", "g2"), "internalDate": "1790000100000"},
    "g3": {"labelIds": ["Label_1", "STARRED", "INBOX"], "raw": mime("Gmail receipt", "shop@ext.test", "erin@gw.test", "g3"), "internalDate": "1790000200000"},
    "g4": {"labelIds": [], "raw": mime("Gmail archived", "old@ext.test", "erin@gw.test", "g4"), "internalDate": "1790000300000"},
    "g5": {"labelIds": ["SPAM", "UNREAD"], "raw": mime("Gmail spam", "spam@ext.test", "erin@gw.test", "g5"), "internalDate": "1790000400000"},
}
GO_EVENTS = [
    {"id": "ge1", "iCalUID": "ge1@google.com", "status": "confirmed", "summary": "Yoga", "start": {"dateTime": "2026-11-03T18:00:00Z", "timeZone": "Europe/London"},
     "end": {"dateTime": "2026-11-03T19:00:00Z", "timeZone": "Europe/London"}, "recurrence": ["RRULE:FREQ=WEEKLY;BYDAY=TU"]},
    {"id": "ge1_x", "recurringEventId": "ge1", "status": "cancelled", "originalStartTime": {"dateTime": "2026-11-10T18:00:00Z", "timeZone": "Europe/London"}},
]
GO_PEOPLE = [{"resourceName": "people/c9", "names": [{"displayName": "Frank Person", "givenName": "Frank", "familyName": "Person"}],
              "emailAddresses": [{"value": "frank@ext.test", "type": "work"}]}]

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, obj, code=200, raw=None):
        body = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json" if raw is None else "message/rfc822")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(n).decode())
        if self.path.startswith("/login/"):
            if form.get("client_secret", [""])[0] != "s3cret":
                return self.send({"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."}, 401)
            return self.send({"access_token": "graph-token", "expires_in": 3600})
        if self.path == "/google/token":
            if form.get("grant_type", [""])[0] != "urn:ietf:params:oauth:grant-type:jwt-bearer":
                return self.send({"error": "bad"}, 400)
            jwt = form["assertion"][0].split(".")
            claims = json.loads(base64.urlsafe_b64decode(jwt[1] + "=="))
            return self.send({"access_token": "google:" + claims["sub"] + ":" + claims["scope"], "expires_in": 3600})
        self.send({"error": "no"}, 404)

    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)
        auth = self.headers.get("Authorization", "")
        if p.startswith("/graph/"):
            if auth != "Bearer graph-token":
                return self.send({"error": {"code": "InvalidAuthenticationToken", "message": "no"}}, 401)
            return self.graph(p[len("/graph"):], q)
        if p.startswith("/google/"):
            return self.google(p[len("/google"):], q, auth)
        self.send({}, 404)

    def graph(self, p, q):
        if p == "/users":
            # Two pages to exercise nextLink.
            if "page2" in q:
                return self.send({"value": G_USERS[2:]})
            return self.send({"value": G_USERS[:2], "@odata.nextLink": "http://127.0.0.1:9911/graph/users?page2=1"})
        m = re.match(r"^/users/([^/]+)/(.*)$", p)
        if not m:
            return self.send({}, 404)
        user, rest = unquote(m.group(1)), m.group(2)
        if user == "nomail@graph.test":
            return self.send({"error": {"code": "MailboxNotEnabledForRESTAPI", "message": "no mailbox"}}, 404)
        if user == "sales@graph.test":
            if rest.startswith("mailFolders") and "/" not in rest:
                return self.send({"value": []})
            return self.send({"value": []}) if "messages" not in rest else self.send({"value": []})
        mm = re.match(r"^mailFolders/([a-z]+)$", rest)
        if mm and mm.group(1) in G_WK:
            return self.send({"id": G_WK[mm.group(1)]})
        if mm:
            return self.send({"error": {"code": "ErrorFolderNotFound", "message": "nope"}}, 404)
        if rest == "mailFolders":
            return self.send({"value": [{"id": k, "displayName": v["displayName"]} for k, v in G_FOLDERS.items() if k != "f-proj"]})
        mm = re.match(r"^mailFolders/([^/]+)/childFolders$", rest)
        if mm:
            return self.send({"value": [{"id": c, "displayName": G_FOLDERS[c]["displayName"]} for c in G_FOLDERS[mm.group(1)]["children"]]})
        mm = re.match(r"^mailFolders/([^/]+)/messages$", rest)
        if mm:
            return self.send({"value": [{k: v for k, v in x.items() if k != "raw"} for x in G_MSGS.get(mm.group(1), [])]})
        mm = re.match(r"^messages/([^/]+)/\$value$", rest)
        if mm:
            for msgs in G_MSGS.values():
                for x in msgs:
                    if x["id"] == mm.group(1):
                        return self.send(None, raw=x["raw"])
            return self.send({}, 404)
        if rest == "calendars":
            return self.send({"value": [{"id": "cal1", "name": "Calendar", "isDefaultCalendar": True, "owner": {"address": "carol@graph.test"}},
                                        {"id": "cal2", "name": "Boss calendar", "isDefaultCalendar": False, "owner": {"address": "boss@graph.test"}}]})
        if rest == "calendars/cal1/events":
            return self.send({"value": G_EVENTS})
        mm = re.match(r"^events/([^/]+)/instances$", rest)
        if mm:
            return self.send({"value": G_INSTANCES.get(mm.group(1), [])})
        if rest == "contacts":
            return self.send({"value": G_CONTACTS})
        if rest == "contactFolders":
            return self.send({"value": []})
        return self.send({"error": {"code": "NotFound", "message": rest}}, 404)

    def google(self, p, q, auth):
        if not auth.startswith("Bearer google:"):
            return self.send({"error": {"code": 401, "message": "no", "status": "UNAUTHENTICATED"}}, 401)
        sub, scope = auth[len("Bearer google:"):].split(":", 1)
        if p == "/admin/directory/v1/users":
            assert "admin.directory" in scope and sub == "boss@gw.test"
            return self.send({"users": GO_USERS})
        m = re.match(r"^/gmail/v1/users/([^/]+)/(.*)$", p)
        if m:
            rest = m.group(2)
            if rest == "labels":
                return self.send({"labels": GO_LABELS})
            if rest == "messages":
                ids = list(GO_MSGS)
                if "pageToken" in q:
                    return self.send({"messages": [{"id": i} for i in ids[3:]]})
                return self.send({"messages": [{"id": i} for i in ids[:3]], "nextPageToken": "p2"})
            mm = re.match(r"^messages/([^/]+)$", rest)
            if mm:
                x = GO_MSGS[mm.group(1)]
                return self.send({"id": mm.group(1), "labelIds": x["labelIds"], "internalDate": x["internalDate"],
                                  "raw": base64.urlsafe_b64encode(x["raw"]).decode().rstrip("=")})
        if p == "/calendar/v3/users/me/calendarList":
            return self.send({"items": [{"id": "primary", "primary": True, "accessRole": "owner", "timeZone": "Europe/London", "summary": "erin@gw.test"},
                                        {"id": "holidays", "accessRole": "reader", "summary": "UK holidays"}]})
        if p == "/calendar/v3/calendars/primary/events":
            return self.send({"items": GO_EVENTS})
        if p == "/v1/people/me/connections":
            return self.send({"connections": GO_PEOPLE})
        self.send({"error": {"code": 404, "message": p}}, 404)

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 9911), H).serve_forever()
