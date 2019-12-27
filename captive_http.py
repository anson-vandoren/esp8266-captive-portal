import gc
import usocket as socket
import uselect as select
import network  # needed for socket instantiation
import uio

from server import Server


class HTTPServer(Server):
    def __init__(self, poller, local_ip):
        super().__init__(poller, 80, socket.SOCK_STREAM, "HTTP Server")
        self.local_ip = local_ip.encode()
        self.routes = dict()
        self.request = dict()
        self.conns = dict()

        self.sock.listen(1)
        self.sock.setblocking(False)
        self.is_connected = False

    def set_ip(self, new_ip):
        self.local_ip = new_ip.encode()
        self.is_connected = True

    def accept(self, s):
        # accept a new socket connection for a particular request
        sock, addr = s.accept()
        # register new socket with the poller so it can be made non-blocking
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.poller.register(sock, select.POLLIN)

    def routefile(self, path, file):
        self.routes[path.encode()] = file.encode()

    def conn_page(self):
        return b"<html><head><title>Connected!</title></head><body>Device is connected to local WiFi with IP address: {:s}</body></html>".format(
            self.local_ip
        )

    def send_response(self, s, route, headers):
        if type(route) is bytes:
            print("route is bytes")
            body = open(route, "rb")
        elif callable(route):
            print("route is callable")
            body = uio.BytesIO(route() or b"")
        else:
            print("route is other:", route)
            body = uio.BytesIO(b"")
        self.write(s, body, headers)

    def read(self, s):
        res = None
        data = s.read()
        if data:
            # add new data to the full request
            self.request[id(s)] = self.request.get(id(s), b"") + data
            # HTTP requests end with a blank line
            if data[-4:] == b"\r\n\r\n":
                # get the completed request
                req = self.request.pop(id(s))

                headers, base_path, creds = self.check_route(s, req)
                print("headers, base_path", headers, base_path)
                if headers is None:
                    return

                if base_path == b"/authenticating":
                    res = creds

                if not self.is_connected:
                    print("not connected, sending route:", base_path)
                    route = self.routes.get(base_path)
                else:
                    print("is connected, sending default route:")
                    route = self.conn_page
                self.send_response(s, route, headers)
        else:
            # no data in the TCP stream, so close the socket that was opened for this transmission
            print("closing:", s)
            self.close(s)

        return res

    def is_valid_host(self, host):
        # Android sends weird requests
        return len(host.split(b".")) > 1

    def check_route(self, s, req):
        creds = None
        req_lines = req.split(b"\r\n")
        req_type, full_path, http_ver = req_lines[0].split(b" ")
        base_path = full_path.split(b"?")[0]

        host = [line.split(b": ")[1].strip() for line in req_lines if b"Host:" in line][
            0
        ]

        print("**Checking Route -- Host: {:s}, Base Path: {:s}".format(host, base_path))

        if base_path in [b"/generate_204", b"/gen_204"]:
            print("\tgenerating 204 response for connectivity check")
            headers = b"HTTP/1.1 204 No Content\r\n"
            return headers, base_path, creds

        if not self.is_valid_host(host):
            print("invalid host:", host)
            headers = b"HTTP/1.1 404 Not Found\r\n"
            base_path = None
            return headers, base_path, creds

        if host != self.local_ip:
            print(
                "Wrong hostname: {:s} -> redirecting to {:s}".format(
                    host, self.local_ip
                )
            )
            print("Full Request:")
            for line in req_lines:
                print(line)
            print()
            return self.redirect(s, self.local_ip, b"/")

        if len(full_path.split(b"?")) > 1:
            params = full_path.split(b"?")[1].split(b"&")
        else:
            params = []

        if req_type != b"GET":
            print("Not a GET request:", req_type, base_path)
            headers = b"HTTP/1.1 404 Not Found"
            base_path = b"/"
            return headers, base_path, creds
        if base_path in [b"/", b"/authenticating"]:
            headers = b"HTTP/1.1 200 OK\r\n"
            return headers, base_path, creds
        elif base_path == b"/login":
            wifi_params = {}
            for param in params:
                print("Param --", param)
                key, val = param.split(b"=")
                wifi_params[key] = val

            if b"ssid" in wifi_params and b"password" in wifi_params:
                global ssid, password
                ssid = wifi_params[b"ssid"]
                password = wifi_params[b"password"]
                headers = b"HTTP/1.1 302 OK\r\nLocation: http://{:s}/authenticating\r\n".format(
                    self.local_ip
                )
                base_path = b"/authenticating"
                return headers, base_path, (ssid, password)
            else:
                # wrong params
                return self.redirect(s)
        else:
            # unrecognized path
            headers = b"HTTP/1.1 404 Not Found\r\n"
            return headers, base_path, creds

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
