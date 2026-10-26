"""Spin up local mock web servers that imitate different stacks, for testing
fingerprinting/liveness without touching any real host."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROFILES = {
    8101: {  # PHP / Laravel behind "nginx"
        "server": "nginx/1.24.0",
        "headers": {"X-Powered-By": "PHP/8.3.11"},
        "set_cookie": ["laravel_session=abc; path=/", "XSRF-TOKEN=xyz; path=/"],
        "body": "<html><head><title>Laravel App</title></head><body>index.php</body></html>",
    },
    8102: {  # Node / Express
        "server": "",
        "headers": {"X-Powered-By": "Express"},
        "set_cookie": ["connect.sid=s%3Aabc; path=/"],
        "body": "<html><head><title>API</title></head><body>ok</body></html>",
    },
    8103: {  # Next.js (Node + React) + Angular markers mixed is unrealistic; keep Next
        "server": "",
        "headers": {"X-Powered-By": "Next.js"},
        "set_cookie": [],
        "body": '<html><head><title>Next</title></head><body><div id="__next"></div>'
                '<script src="/_next/static/chunks/main.js"></script>'
                '<script id="__NEXT_DATA__" type="application/json">{}</script></body></html>',
    },
    8104: {  # Angular SPA served by Apache
        "server": "Apache/2.4.58 (Ubuntu)",
        "headers": {},
        "set_cookie": [],
        "body": '<html><head><title>Portal</title></head>'
                '<body><app-root ng-version="17.3.2"></app-root></body></html>',
    },
    8105: {  # WordPress
        "server": "Apache/2.4.58",
        "headers": {},
        "set_cookie": [],
        "body": '<html><head><meta name="generator" content="WordPress 6.5.2">'
                '<title>Blog</title></head><body>/wp-content/themes/x</body></html>',
    },
    8106: {  # fake WAF block
        "server": "cloudflare",
        "headers": {"CF-RAY": "abc123-AMS", "CF-Cache-Status": "DYNAMIC"},
        "set_cookie": ["__cf_bm=zzz; path=/"],
        "status": 403,
        "body": "<html><head><title>Attention Required! | Cloudflare</title></head>"
                "<body>Sorry, you have been blocked. Ray ID: abc123</body></html>",
    },
}


def make_handler(profile):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            status = profile.get("status", 200)
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if profile.get("server"):
                self.server_version = profile["server"]
                self.sys_version = ""
            for k, v in profile.get("headers", {}).items():
                self.send_header(k, v)
            for c in profile.get("set_cookie", []):
                self.send_header("Set-Cookie", c)
            body = profile["body"].encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def version_string(self):
            return profile.get("server", "TestServer")
    return H


def start_all():
    servers = []
    for port, profile in PROFILES.items():
        httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(profile))
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        servers.append(httpd)
    return servers


if __name__ == "__main__":
    start_all()
    print("mock servers on", list(PROFILES))
    import time
    while True:
        time.sleep(1)
