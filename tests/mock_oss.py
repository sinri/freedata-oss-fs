#!/usr/bin/env python3
"""Small anonymous, read-only OSS-compatible server used by Linux FUSE tests."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit
import json
import os
import sys


OBJECTS = {
    "root/public/hello.txt": b"hello from oss\n",
    "root/public/large.bin": bytes(range(256)) * 32,
    "root/private/secret.txt": b"must not be visible\n",
    "root/teams/red/secret/token.txt": b"red token\n",
    "root/teams/red/public/info.txt": b"red public\n",
    "root/archive": b"colliding file must also be hidden\n",
    "root/archive/old.txt": b"old\n",
    "root/cli-hidden/file.txt": b"hidden by mount parameter\n",
    "root/empty/": b"",
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def record(self):
        with Path(self.server.request_log).open("a", encoding="utf-8") as output:
            output.write(json.dumps({"method": self.command, "path": self.path}) + "\n")

    def send_bytes(self, status, body, headers=None):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.record()
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if query.get("list-type") == ["2"]:
            prefix = query.get("prefix", [""])[0]
            contents = []
            for key, value in sorted(OBJECTS.items()):
                if key.startswith(prefix):
                    contents.append(
                        "<Contents>"
                        f"<Key>{quote(key, safe='')}</Key>"
                        "<LastModified>2026-08-13T00:00:00Z</LastModified>"
                        f"<ETag>&quot;etag-{len(value)}&quot;</ETag>"
                        f"<Size>{len(value)}</Size>"
                        "</Contents>"
                    )
            body = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                "<ListBucketResult><IsTruncated>false</IsTruncated>"
                + "".join(contents)
                + "</ListBucketResult>"
            ).encode()
            self.send_bytes(200, body, {"Content-Type": "application/xml"})
            return

        marker = "/bucket/"
        if not parsed.path.startswith(marker):
            self.send_bytes(404, b"unknown bucket")
            return
        key = unquote(parsed.path[len(marker) :])
        if key not in OBJECTS:
            self.send_bytes(404, b"missing object")
            return
        value = OBJECTS[key]
        range_header = self.headers.get("Range")
        if not range_header:
            self.send_bytes(200, value)
            return
        try:
            bounds = range_header.removeprefix("bytes=").split("-", 1)
            start, end = int(bounds[0]), int(bounds[1])
            if start < 0 or end < start or end >= len(value):
                raise ValueError()
        except ValueError:
            self.send_bytes(416, b"invalid range")
            return
        body = value[start : end + 1]
        self.send_bytes(
            206,
            body,
            {"Content-Range": f"bytes {start}-{end}/{len(value)}"},
        )

    def reject_mutation(self):
        self.record()
        self.send_bytes(405, b"read only")

    do_PUT = reject_mutation
    do_POST = reject_mutation
    do_DELETE = reject_mutation
    do_PATCH = reject_mutation


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: mock_oss.py PORT REQUEST_LOG")
    server = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
    server.request_log = sys.argv[2]
    server.serve_forever()


if __name__ == "__main__":
    main()
