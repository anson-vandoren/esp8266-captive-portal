import gc
import usocket as socket
import uselect as select
import network  # needed for socket instantiation
import uerrno
import uio

from collections import namedtuple

ReqInfo = namedtuple("ReqInfo", ["type", "path", "params", "host"])

from server import Server


class HTTPServer(Server):
    def __init__(self, poller, local_ip):
        super().__init__(poller, 80, socket.SOCK_STREAM, "HTTP Server")
        if type(local_ip) is bytes:
            self.local_ip = local_ip
        else:
            self.local_ip = local_ip.encode()
        self.routes = dict()
        self.request = dict()
        self.conns = dict()

        self.sock.listen(1)
        self.sock.setblocking(False)
        self.is_connected = False
        self.ssid = None

    def set_ip(self, new_ip, new_ssid):
        """update settings after connected to local WiFi"""

        self.local_ip = new_ip.encode()
        self.ssid = new_ssid
        self.is_connected = True

    def accept(self, s):
        """accept a new client request socket and register it for polling"""

        try:
            sock, addr = s.accept()
        except OSError as e:
            if e.args[0] == uerrno.EAGAIN:
                print("failed to accept a new socket:", s)
                return

        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.poller.register(sock, select.POLLIN)

    def routefile(self, path, file):
        """set the file to serve for a given HTTP path"""

        self.routes[path.encode()] = file.encode()

    def conn_page(self):
        """send a connection status page if connected to local WiFi"""

        return open("./connected.html", "rb").read() % (self.ssid, self.local_ip)

    def send_response(self, s, route, headers):
        """send HTTP response to the client based on route given"""

        if type(route) is bytes:
            # expecting a known route
            body = open(route, "rb")
        elif callable(route):
            body = uio.BytesIO(route() or b"")
        else:
            # unknown route
            if not route:
                print("Empty route -> sending empty body")
            else:
                print(
                    "Unknown route type {:s} for route {:s}".format(type(route), route)
                )
            body = uio.BytesIO(b"")

        # write the response to the socket
        self.write(s, body, headers)

    def read(self, s):
        """read in client request from socket"""

        data = s.read()
        if not data:
            # no data in the TCP stream, so close the socket
            self.close(s)
            return None

        # add new data to the full request
        self.request[id(s)] = self.request.get(id(s), b"") + data

        # check if additional data expected
        if data[-4:] != b"\r\n\r\n":
            # HTTP request is not finished if no blank line at the end
            return None

        # get the completed request
        req = self.request.pop(id(s))

        headers, base_path, creds = self.check_route(s, req)
        if headers is None:
            return

        if not self.is_connected:
            print("not connected, sending route:", base_path)
            route = self.routes.get(base_path)
        else:
            print("is connected, sending default route:")
            route = self.conn_page
        self.send_response(s, route, headers)
        return creds

    def is_valid_host(self, host):
        # Android sends weird requests. Ignore those
        return len(host.split(b".")) > 1

    def parse_request(self, req):
        """parse a raw HTTP request to get items of interest"""

        req_lines = req.split(b"\r\n")
        req_type, full_path, http_ver = req_lines[0].split(b" ")
        path = full_path.split(b"?")
        base_path = path[0]
        query = path[1] if len(path) > 1 else None
        host = [line.split(b": ")[1] for line in req_lines if b"Host:" in line][0]
        query_params = (
            {
                key: val
                for key, val in [param.split(b"=") for param in query.split(b"&")]
            }
            if query
            else {}
        )
        return ReqInfo(req_type, base_path, query_params, host)

    def check_route(self, s, raw_req):
        req = self.parse_request(raw_req)

        if req.path in [b"/generate_204", b"/gen_204"] and self.is_connected:
            print("\tgenerating 204 response for connectivity check")
            headers = b"HTTP/1.1 204 No Content\r\n"
            return headers, req.path, None

        if not self.is_valid_host(req.host):
            # Android sends DNS/HTTP requests for malformed hosts sometimes
            headers = b"HTTP/1.1 404 Not Found\r\n"
            return headers, None, None

        if req.host != self.local_ip:
            print(
                "Wrong hostname: {:s} -> redirecting to {:s}/".format(
                    req.host, self.local_ip
                )
            )
            return self.redirect(s, self.local_ip, b"/")

        if req.type != b"GET" and req.path not in self.routes:
            print("Not a GET request to a known resource:", req_type, req.path)
            headers = b"HTTP/1.1 404 Not Found"
            return headers, b"/", None

        if req.path in [b"/", b"/authenticating"]:
            headers = b"HTTP/1.1 200 OK\r\n"
            return headers, req.path, None

        if req.path == b"/login":
            ssid = req.params.get(b"ssid", None)
            password = req.params.get(b"password", None)
            if not all([ssid, password]):
                # missing login parameters
                return self.redirect(s)
            headers = b"HTTP/1.1 302 OK\r\nLocation: http://{:s}/authenticating\r\n".format(
                self.local_ip
            )
            return (headers, b"/authenticating", (ssid, password))
        else:
            # unrecognized path
            headers = b"HTTP/1.1 404 Not Found\r\n"
            return headers, req.path, None

    def redirect(self, s, host=None, path=b"/"):
        if host is None:
            host = self.local_ip
        print("redirecting {:s}{:s}".format(host, path))
        path = path.lstrip(b"/")
        headers = b"HTTP/1.1 307 Temporary Redirect\r\n"
        headers += b"Location: http://{:s}/{:s}\r\n".format(host, path)
        print("headers:", headers)
        body = uio.BytesIO(b"Redirecting")
        self.write(s, body, headers)
        return None, None, None

    def write(self, s, body, headers):
        headers += "\r\n"
        buf = bytearray(headers + "\x00" * (536 - len(headers)))
        bufmv = memoryview(buf)
        bw = body.readinto(bufmv[len(headers) :], 536 - len(headers))
        c = (body, buf, bufmv, [0, len(headers) + bw])
        self.conns[id(s)] = c
        self.poller.modify(s, select.POLLOUT)

    def bufferfile(self, c, w):
        if w == c[3][1] - c[3][0]:
            c[3][0] = 0
            c[3][1] = c[0].readinto(c[1], 536)
        else:
            c[3][0] += w

    def close(self, s):
        s.close()
        self.poller.unregister(s)
        sid = id(s)
        if sid in self.request:
            del self.request[id(s)]
        if sid in self.conns:
            del self.conns[id(s)]
        gc.collect()

    @micropython.native
    def handle(self, sock, event, others):
        res = None
        print("{:s} -- ".format(self.name))
        if sock is self.sock:
            # client connecting on port 80, so spawn off a new socket to handle this connection
            print("- accepting new incoming HTTP connection")
            self.accept(sock)
        elif event & select.POLLOUT:
            # an existing spawned socket has space to send more data
            print("- HTTP sending outgoing")
            c = self.conns[id(sock)]
            if c:
                w = sock.write(c[2][c[3][0] : c[3][1]])
                if not w or c[3][1] < 536:
                    self.close(sock)
                else:
                    self.bufferfile(c, w)
            else:
                print("- failed to find outgoing socket")
        elif event & select.POLLIN:
            print("- HTTP reading incoming")
            res = self.read(sock)
            if res is not None:
                print("Got credentials")

        print("{:s} -- done".format(self.name))
        return res
