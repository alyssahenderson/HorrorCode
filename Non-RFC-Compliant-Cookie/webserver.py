#!/usr/bin/env python3
"""
Cookie-mangling reproduction app — v2 with control cookie.

Sets TWO cookies on login:
  - pawAuthCookie   : contains literal backslashes (RFC 6265 violation)
  - pawCleanCookie  : same shape but only valid cookie-octet characters

If both vanish, something else is stripping cookies entirely.
If both arrive, the proxy isn't the problem.

Usage:
  python3 webserver.py [port]      # default port 8080

  COOKIE_SECURE=1                  add the "Secure" attribute
  COOKIE_SAMESITE=None|Lax|Strict  set SameSite (default: not set)
"""

import html
import http.server
import os
import sys
import urllib.parse
from datetime import datetime


# Dirty cookie: contains TWO literal backslashes (\\B and \\8B in source
# compile to single backslashes at runtime). RFC 6265 forbids backslash
# in cookie-octet.
DIRTY_COOKIE_NAME = "pawAuthCookie"
DIRTY_COOKIE_VALUE = "abcDEF12\\BUjzw94ik/oj2Os5d\\8B8nDFtGmOtfxt16w1G+QQQzzz=="

# Clean control cookie: same length and shape, no backslashes. Should
# roundtrip cleanly through any RFC-compliant proxy.
CLEAN_COOKIE_NAME = "pawCleanCookie"
CLEAN_COOKIE_VALUE = "abcDEF12xBUjzw94ik/oj2Os5dx8B8nDFtGmOtfxt16w1G+QQQzzz=="


LOGIN_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Login</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 480px; margin: 4rem auto;">
  <h1>Cookie-mangling test app (v2)</h1>
  <p>Submitting the form sets two cookies of equal length: one with
     backslashes, one without.</p>
  <form method="POST" action="/login">
    <p><label>Username <input name="user" value="setup"></label></p>
    <p><label>Password <input name="pass" type="password" value="x"></label></p>
    <p><button type="submit">Login</button></p>
  </form>
</body></html>
"""

RESULT_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Result</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 760px; margin: 3rem auto;">
  <h1>Cookie roundtrip results</h1>

  <h2 style="color:{dirty_color}">Dirty cookie (with backslashes): {dirty_status}</h2>
  <p>Set:</p>
  <pre style="background:#f4f4f4; padding:.75rem; word-break:break-all; white-space:pre-wrap;">{dirty_set}</pre>
  <p>Received:</p>
  <pre style="background:{dirty_bg}; padding:.75rem; word-break:break-all; white-space:pre-wrap;">{dirty_got}</pre>

  <h2 style="color:{clean_color}">Clean control cookie: {clean_status}</h2>
  <p>Set:</p>
  <pre style="background:#f4f4f4; padding:.75rem; word-break:break-all; white-space:pre-wrap;">{clean_set}</pre>
  <p>Received:</p>
  <pre style="background:{clean_bg}; padding:.75rem; word-break:break-all; white-space:pre-wrap;">{clean_got}</pre>

  <h3>Diagnosis</h3>
  <p>{diagnosis}</p>

  <p><a href="/logout">Log out</a> · <a href="/login">Back to login</a></p>
</body></html>
"""


def parse_cookies(header_value):
    cookies = {}
    if not header_value:
        return cookies
    for part in header_value.split(";"):
        if "=" in part:
            name, _, value = part.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


def build_set_cookie(name, value):
    attrs = ["Path=/"]
    samesite = os.environ.get("COOKIE_SAMESITE", "").strip()
    if samesite:
        attrs.append("SameSite=%s" % samesite)
    if os.environ.get("COOKIE_SECURE", "").strip() in ("1", "true", "yes"):
        attrs.append("Secure")
    return "%s=%s; %s" % (name, value, "; ".join(attrs))


def diagnose(dirty_ok, clean_ok, dirty_present, clean_present):
    if dirty_ok and clean_ok:
        return ("Both cookies arrived intact. The proxy is not stripping or "
                "mangling cookies. Whatever is breaking Proactivanet login "
                "lives elsewhere.")
    if not dirty_present and clean_ok:
        return ("Smoking gun: the clean cookie roundtripped but the cookie "
                "containing backslashes was dropped entirely. The proxy is "
                "rejecting RFC 6265-noncompliant cookie values. This is the "
                "Proactivanet failure mode.")
    if dirty_present and not dirty_ok and clean_ok:
        return ("The clean cookie roundtripped intact, but the cookie "
                "containing backslashes came back with a modified value. "
                "The proxy is rewriting (escaping or stripping) the "
                "non-compliant characters. Same root cause.")
    if not dirty_present and not clean_present:
        return ("Neither cookie was returned. The proxy or browser is "
                "blocking cookies generally — different problem from the "
                "backslash hypothesis. Check Set-Cookie attributes "
                "(Secure on a non-HTTPS page? Path mismatch from URL "
                "rewriting?) and the browser's response-header view.")
    return "Mixed result — see values above."


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "CookieMangleTest/2.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s - %s\n" % (
            datetime.now().strftime("%H:%M:%S"),
            self.address_string(),
            fmt % args,
        ))

    def _log_and_get_cookies(self):
        raw = self.headers.get("Cookie", "")
        sys.stderr.write("    Raw Cookie header (%d bytes): %r\n" % (len(raw), raw))
        cookies = parse_cookies(raw)
        for name, expected in (
            (DIRTY_COOKIE_NAME, DIRTY_COOKIE_VALUE),
            (CLEAN_COOKIE_NAME, CLEAN_COOKIE_VALUE),
        ):
            if name in cookies:
                got = cookies[name]
                sys.stderr.write(
                    "      %s: %d chars, match=%s, value=%r\n"
                    % (name, len(got), got == expected, got)
                )
            else:
                sys.stderr.write("      %s: MISSING\n" % name)
        return cookies

    def _html(self, status, body):
        body_bytes = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body_bytes)

    def _redirect(self, location, set_cookies=()):
        self.send_response(302)
        self.send_header("Location", location)
        for sc in set_cookies:
            self.send_header("Set-Cookie", sc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        cookies = self._log_and_get_cookies()

        if path == "/login":
            self._html(200, LOGIN_PAGE)
            return

        if path == "/logout":
            cleared = [
                "%s=; Path=/; Max-Age=0" % DIRTY_COOKIE_NAME,
                "%s=; Path=/; Max-Age=0" % CLEAN_COOKIE_NAME,
            ]
            self._redirect("/login", set_cookies=cleared)
            return

        if path in ("/", "/index", "/index.html"):
            dirty_got = cookies.get(DIRTY_COOKIE_NAME)
            clean_got = cookies.get(CLEAN_COOKIE_NAME)
            dirty_ok = dirty_got == DIRTY_COOKIE_VALUE
            clean_ok = clean_got == CLEAN_COOKIE_VALUE

            if dirty_got is None and clean_got is None:
                # No auth attempt yet
                self._redirect("/login")
                return

            def fmt_status(ok, present):
                if ok:
                    return ("OK", "#0a7d18", "#e8f5e9")
                if not present:
                    return ("DROPPED", "#b00020", "#ffebee")
                return ("MANGLED", "#b35c00", "#fff3cd")

            d_label, d_color, d_bg = fmt_status(dirty_ok, dirty_got is not None)
            c_label, c_color, c_bg = fmt_status(clean_ok, clean_got is not None)

            body = RESULT_TEMPLATE.format(
                dirty_status=d_label, dirty_color=d_color, dirty_bg=d_bg,
                clean_status=c_label, clean_color=c_color, clean_bg=c_bg,
                dirty_set=html.escape(DIRTY_COOKIE_VALUE),
                dirty_got=html.escape(dirty_got) if dirty_got is not None
                          else "(not received)",
                clean_set=html.escape(CLEAN_COOKIE_VALUE),
                clean_got=html.escape(clean_got) if clean_got is not None
                          else "(not received)",
                diagnosis=html.escape(diagnose(
                    dirty_ok, clean_ok,
                    dirty_got is not None, clean_got is not None,
                )),
            )
            self._html(200, body)
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        self._log_and_get_cookies()

        if path != "/login":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)

        set_cookies = [
            build_set_cookie(DIRTY_COOKIE_NAME, DIRTY_COOKIE_VALUE),
            build_set_cookie(CLEAN_COOKIE_NAME, CLEAN_COOKIE_VALUE),
        ]
        for sc in set_cookies:
            sys.stderr.write("    Set-Cookie issued: %s\n" % sc)
        self._redirect("/", set_cookies=set_cookies)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    addr = ("0.0.0.0", port)
    sys.stderr.write("Listening on http://%s:%d\n" % addr)
    sys.stderr.write("Dirty cookie (%d chars, has backslashes): %r\n"
                     % (len(DIRTY_COOKIE_VALUE), DIRTY_COOKIE_VALUE))
    sys.stderr.write("Clean cookie (%d chars, RFC 6265 OK):     %r\n"
                     % (len(CLEAN_COOKIE_VALUE), CLEAN_COOKIE_VALUE))
    sys.stderr.write("Watch stderr for received cookie values on each request.\n\n")
    http.server.HTTPServer(addr, Handler).serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write("\nShutting down.\n")