import ssl, sys, runpy
sys.argv = ["origin.py", sys.argv[1]]
import http.server
_orig = http.server.ThreadingHTTPServer.server_bind
def bind(self):
    _orig(self)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("cert.pem", "key.pem")
    self.socket = ctx.wrap_socket(self.socket, server_side=True)
http.server.ThreadingHTTPServer.server_bind = bind
runpy.run_path("origin.py", run_name="__main__")
