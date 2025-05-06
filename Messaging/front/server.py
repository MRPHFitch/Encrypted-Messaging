# https_server.py
import http.server
import ssl

PORT = 8443
Handler = http.server.SimpleHTTPRequestHandler

httpd = http.server.HTTPServer(('localhost', PORT), Handler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                               certfile="localhost.pem",
                               keyfile="localhost-key.pem",
                               server_side=True)

print(f"Serving HTTPS on https://localhost:{PORT}")
httpd.serve_forever()