#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Upstream servers for tests that check what leaves a sandbox.

A test starts this file as the main command of a sandbox and exposes its
ports as gateway services. The test's client runs in another sandbox and talks
to these servers through its supervisor. The servers say what arrived, so the
client can print it and the test can read it from the exec output. Nothing has
to reach the machine that runs the tests.

The REST server (REST_PORT, default 8080):

  ANY /...            answers with JSON: the request line and headers it read
                      (`head`), the body (`body`) and the body's SHA-256
                      (`body_sha256`).
  GET /seen/<id>      answers with what the WebSocket server recorded for the
                      connection to /ws/<id>: `handshake`, `binary`, `finished`.
                      404 when there was no such connection.
  GET /healthz        answers `{"status": "ok"}`.

The WebSocket server (WEBSOCKET_PORT, default 8081):

  GET /ws/<id>        completes the handshake, reads frames until the
                      connection ends, and records whether a binary frame
                      arrived.

Standard library only, so it runs from any Python image.
"""

import base64
import hashlib
import json
import os
import socketserver
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REST_PORT = int(os.environ.get("REST_PORT", "8080"))
WEBSOCKET_PORT = int(os.environ.get("WEBSOCKET_PORT", "8081"))
MAX_BODY = 1024 * 1024
MAX_CONNECTIONS = 4096
IDLE_SECONDS = 30
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

_lock = threading.Lock()
_connections = {}


def record(connection_id, **changes):
    """Update what is known about one WebSocket connection."""
    with _lock:
        entry = _connections.setdefault(
            connection_id, {"handshake": False, "binary": False, "finished": False}
        )
        entry.update(changes)
        while len(_connections) > MAX_CONNECTIONS:
            _connections.pop(next(iter(_connections)))


class Rest(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def _echo(self, body):
        head = self.requestline + "\r\n"
        head += "".join(f"{name}: {value}\r\n" for name, value in self.headers.items())
        self._reply(
            200,
            {
                "head": head,
                "body": body.decode("utf-8", "replace"),
                "body_sha256": hashlib.sha256(body).hexdigest(),
            },
        )

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._reply(413, {"error": "body_too_large"})
            return None
        return self.rfile.read(length)

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, {"status": "ok"})
        elif self.path.startswith("/seen/"):
            with _lock:
                entry = dict(_connections.get(self.path[len("/seen/"):]) or {})
            if entry:
                self._reply(200, entry)
            else:
                self._reply(404, {"error": "unknown_connection"})
        else:
            self._echo(b"")

    def do_POST(self):
        body = self._body()
        if body is not None:
            self._echo(body)

    do_PUT = do_POST

    def log_message(self, fmt, *args):
        sys.stderr.write("rest %s %s\n" % (self.address_string(), fmt % args))


class WebSocket(socketserver.StreamRequestHandler):
    timeout = IDLE_SECONDS

    def _read(self, count):
        data = self.rfile.read(count)
        if len(data) < count:
            raise ConnectionError("connection ended")
        return data

    def handle(self):
        request_line = self.rfile.readline(65537).decode("latin-1").strip()
        headers = {}
        while True:
            line = self.rfile.readline(65537).decode("latin-1")
            if line in ("\r\n", "\n", ""):
                break
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        parts = request_line.split()
        key = headers.get("sec-websocket-key")
        if len(parts) < 2 or not key or headers.get("upgrade", "").lower() != "websocket":
            self.wfile.write(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            return
        connection_id = parts[1].rsplit("/", 1)[-1]
        accept = base64.b64encode(hashlib.sha1((key + WEBSOCKET_GUID).encode()).digest())
        self.wfile.write(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )
        self.wfile.flush()
        record(connection_id, handshake=True)
        sys.stderr.write("websocket %s handshake\n" % connection_id)
        try:
            while True:
                first, second = self._read(2)
                opcode, masked, length = first & 0x0F, second & 0x80, second & 0x7F
                if length == 126:
                    (length,) = struct.unpack("!H", self._read(2))
                elif length == 127:
                    (length,) = struct.unpack("!Q", self._read(8))
                if length > MAX_BODY:
                    break
                if masked:
                    self._read(4)
                self._read(length)
                if opcode == 0x2:
                    record(connection_id, binary=True)
                elif opcode == 0x8:
                    self.wfile.write(b"\x88\x00")
                    break
        except (OSError, ConnectionError):
            pass
        finally:
            record(connection_id, finished=True)
            sys.stderr.write("websocket %s finished %s\n" % (connection_id, _connections.get(connection_id)))


class Threaded(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    rest = ThreadingHTTPServer(("0.0.0.0", REST_PORT), Rest)
    rest.daemon_threads = True
    websocket = Threaded(("0.0.0.0", WEBSOCKET_PORT), WebSocket)
    threading.Thread(target=websocket.serve_forever, daemon=True).start()
    sys.stderr.write("upstream server: rest on %d, websocket on %d\n" % (REST_PORT, WEBSOCKET_PORT))
    rest.serve_forever()


if __name__ == "__main__":
    main()
