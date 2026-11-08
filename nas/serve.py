#!/usr/bin/env python3
# serve.py —— 订阅输出服务：/ 返回明文，/sub 返回 base64，/fast 返回快节点
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OUT = os.environ.get("OUT_DIR", "/app/out")
PORT = int(os.environ.get("SERVE_PORT", "18080"))


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, body, ctype="text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Profile-Update-Interval", "6")
        self.send_header("Profile-Title", "AutoLive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        fname = "live-sub.txt" if path == "/sub" else "live-links.txt"
        fp = os.path.join(OUT, fname)
        if not os.path.exists(fp):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        with open(fp, encoding="utf-8") as f:
            self._send(f.read())

    def log_message(self, fmt, *args):
        print("[serve] %s %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    print("[serve] listening 0.0.0.0:%d  dir=%s" % (PORT, OUT), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()