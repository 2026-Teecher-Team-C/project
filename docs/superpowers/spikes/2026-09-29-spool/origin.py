"""로컬 오리진. /dl/big.bin (Content-Length), /dl-chunked/big.bin (chunked), /page/big.bin (비다운로드 video/mp4)."""

import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FILE = os.path.join(os.path.dirname(__file__), "big.bin")
CHUNK = 1024 * 1024


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        size = os.path.getsize(FILE)
        chunked = self.path.startswith("/dl-chunked/")
        self.send_response(200)
        if self.path.startswith("/page/"):
            self.send_header("Content-Type", "video/mp4")
        else:
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="big.bin"')
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(FILE, "rb") as f:
            while data := f.read(CHUNK):
                try:
                    if chunked:
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
                    else:
                        self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    return
            if chunked:
                self.wfile.write(b"0\r\n\r\n")


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
