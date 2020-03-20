import socket
from email.parser import Parser
from functools import lru_cache
from urllib.parse import parse_qs, urlparse

max_line = 64*1024
max_header = 100


class Response:
    def __init__(self, status, reason, headers=None, body=None):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body

class Request:
    def __init__(self, method, target, ver, headers, rfile):
        self.method = method
        self.target = target
        self.ver = ver
        self.headers = headers
        self.rfile = rfile

    @property
    def pathe(self):
        return self.url.path

    @property
    @lru_cache(maxsize=None)
    def query(self):
        return parse_qs(self.url.query)

    @property
    @lru_cache(maxsize=None)
    def url(self):
        return urlparse(self.target)


class HTTPserver:

    def __init__(self, host, port, server_name):
        self._host = host
        self._port = port
        self._server_name = server_name

    def server_run(self):
        serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=0)
        try:
            serv_sock.bind((self._host, self._port))
            serv_sock.listen()
            while True:
                conn, _ = serv_sock.accept()
                try:
                    self.server_client(conn)
                    print(conn)
                except Exception as e:
                    print('Client serving failed', e)
        finally: serv_sock.close()

    def server_client(self, conn):
        try:
            req = self.parse_request(conn)
            resp = self.handle_request(req)
            self.send_response(conn, resp)
        except ConnectionResetError:
            conn = None
        except Exception as e:
            self.send_error(conn, e)
        if conn:
            conn.close()

    def parse_request(self, conn):
        rfile = conn.makefile('rb')
        method, target, ver = self.parse_req_line(rfile)
        headers = self.parse_req_headers(rfile)
        host = headers.get('Host')
        if not host:
            raise Exception('Bad request')
        if host not in (self._server_name, f'{self._server_name}:{self._port}'):
            raise Exception('Not found')
        return Request(method, target, ver, headers, rfile)

    def parse_req_line(self, rfile):
        raw = rfile.readline(max_line + 1)
        if len(raw) > max_line:
            raise Exception('Request line is to long')
        req_line = str(raw, 'iso-8859-1')
        req_line = req_line.rstrip('\r\n')
        words = req_line.split()
        if len(words) != 3:
            raise Exception('Malformed request line')
        method, target, ver = words
        if ver != 'HTTP/1.1':
            raise Exception('Unexpected HTTP version')
        return method, target, ver

    def parse_req_headers(self, rfile):
        headers = []
        while True:
            line = rfile.readfile(max_line + 1)
            if len(line) > max_line:
                raise Exception('Headers line is to long')
            if line in (b'\r\n', b'\n', b''):
                break
            headers.append(line)
            if len(headers) > max_header:
                raise Exception('Too many headers')
            sheader = b''.join(headers).decode('iso-8859-1')
            return Parser().parsestr(sheader)

    def handle_request(self, req):
        if req.target == '/' and req.method == 'GET':
            return self.handle_get_main(req)
        if req.target == '/blog' and req.method == 'GET':
            return self.handle_get_blog(req)
        raise Exception('Not found')

    def handle_get_main(self, req):
        accept = req.headers.get('Accept')
        if 'text/html' in accept:
            ContentType = 'text/html; charset=utf-8'
            body = '<html><head></head><body>'
            body += '<h1>Главная страница</h1>'
            body += '</body></html>'
        else:
            return Response(406, 'Not Acceptable')
        body = body.encode('utf-8')
        headers = [('Content-Type', ContentType),
                    ('Content-Length', len(body))]
        return Response(200, 'OK', headers, body)

    def handle_get_blog(self, req):
        accept = req.headers.get('Accept')
        if 'text/html' in accept:
            ContentType = 'text/html; charset=utf-8'
            body = '<html><head></head><body>'
            body += '<h1>Блог</h1>'
            body += '</body></html>'
        else:
            return Response(406, 'Not Acceptable')
        body = body.encode('utf-8')
        headers = [('Content-Type', ContentType),
                    ('Content-Length', len(body))]
        return Response(200, 'OK', headers, body)

    def send_response(self, conn, resp):
        wfile = conn.makefile('wb')
        status_line = f'HTTP/1.1 {resp.status} {resp.reason}\r\n'
        wfile.write(status_line.encode('iso-8859-1'))
        if resp.headers:
            for (key, volue) in resp.headers:
                header_line = f'{key}: {volue}\r\n'
                wfile.write(header_line.encode('iso-8859-1'))
        wfile.write(b'\r\n')
        if resp.body:
            wfile.write(resp.body)
        wfile.flush()
        wfile.close()

    def send_error(self, conn, err):
        try:
            status = err.status
            reason = err.reason
            body = (err.body or err.reason).encode('utf-8')
        except:
            status = 500
            reason = b'Internal Server Error'
            body = b'Internal Server Error'
        resp = Response(status, reason,
                        [('Content-Length', len(body))],
                        body)
        self.send_response(conn, resp)

class HTTPError(Exception):
  def __init__(self, status, reason, body=None):
    super()
    self.status = status
    self.reason = reason
    self.body = body

if __name__ == '__main__':
    host = 'localhost'
    port = 3000
    server_name = 'TestHTTP'
    serv = HTTPserver(host, port, server_name)
    try:
        serv.server_run()
    except KeyboardInterrupt:
        pass
