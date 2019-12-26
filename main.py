import network
import usocket as socket
import uselect as select
import ubinascii as binascii
import utime as time
import uio
import gc

gc.collect()

local_ip = "192.168.4.1"
AP_IF = network.WLAN(network.AP_IF)
STA_IF = network.WLAN(network.STA_IF)

ssid = None
password = None


class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = ""
        # header is bytes 0-11, so question starts on byte 12
        head = 12
        # length of this label defined in first byte
        length = data[head]
        while length != 0:
            label = head + 1
            # add the label to the requested domain and insert a dot after
            self.domain += data[label : label + length].decode("utf-8") + "."
            # check if there is another label after this one
            head += length + 1
            length = data[head]

    def answer(self, ip_addr):
        # ** create the answer header **
        # copy the ID from incoming request
        packet = self.data[:2]
        # set response flags (assume RD=1 from request)
        packet += b"\x81\x80"
        # copy over QDCOUNT and set ANCOUNT equal
        packet += self.data[4:6] + self.data[4:6]
        # set NSCOUNT and ARCOUNT to 0
        packet += b"\x00\x00\x00\x00"

        # ** create the answer body **
        # respond with original domain name question
        packet += self.data[12:]
        # pointer back to domain name (at byte 12)
        packet += b"\xC0\x0C"
        # set TYPE and CLASS (A record and IN class)
        packet += b"\x00\x01\x00\x01"
        # set TTL to 60sec
        packet += b"\x00\x00\x00\x3C"
        # set response length to 4 bytes (to hold one IPv4 address)
        packet += b"\x00\x04"
        # now actually send the IP address as 4 bytes (without the "."s)
        packet += bytes(map(int, ip_addr.split(".")))

        gc.collect()

        return packet


class Server:
    def __init__(self, poller, port, sock_type, name):
        self.name = name
        # create socket with correct type (stream (TCP) or datagram (UDP)
        self.sock = socket.socket(socket.AF_INET, sock_type)

        # register to get event updates for this socket
        self.poller = poller
        self.poller.register(self.sock, select.POLLIN)

        addr = socket.getaddrinfo("0.0.0.0", port)[0][-1]
        # allow new requests while still sending last response
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(addr)

        print(self.name, "listening on", addr)

    def stop(self, poller):
        poller.unregister(self.sock)
        self.sock.close()
        print(self.name, "stopped")


class DNSServer(Server):
    def __init__(self, poller, ip_addr):
        super().__init__(poller, 53, socket.SOCK_DGRAM, "DNS Server")
        self.ip_addr = ip_addr

    def handle(self, sock, event, others):
        # server doesn't spawn other sockets, so only respond to its own socket
        if sock is not self.sock:
            return

        # check the DNS question, and respond with an answer
        try:
            data, sender = sock.recvfrom(1024)
            request = DNSQuery(data)

            print("Sending {:s} -> {:s}".format(request.domain, self.ip_addr))
            sock.sendto(request.answer(self.ip_addr), sender)
            del request
            gc.collect()
        except Exception as e:
            print("DNS server exception:", e)


class HTTPServer(Server):
    def __init__(self, poller):
        super().__init__(poller, 80, socket.SOCK_STREAM, "HTTP Server")
        self.routes = dict()
        self.request = dict()
        self.conns = dict()

        self.sock.listen(1)
        self.sock.setblocking(False)

    def accept(self, s):
        # accept a new socket connection for a particular request
        sock, addr = s.accept()
        # register new socket with the poller so it can be made non-blocking
        sock.setblocking(False)
        self.poller.register(sock, select.POLLIN)

    def routefile(self, path, file):
        self.routes[path.encode()] = file.encode()

    def read(self, s):
        data = s.read()
        if data:
            # add new data to the full request
            self.request[id(s)] = self.request.get(id(s), b"") + data
            # HTTP requests end with a blank line
            if data[-4:] == b"\r\n\r\n":
                # get the completed request
                req = self.request.pop(id(s))

                headers, base_path = self.check_route(s, req)
                if headers is None or base_path is None:
                    base_path = b"/"
                    headers = b"HTTP/1.1 404 Not Found"

                serve = self.routes.get(base_path)
                if type(serve) is bytes:
                    if serve[-3:] == b".gz":
                        headers += b"Content-Encoding: gzip\r\n"
                    body = open(serve, "rb")
                elif callable(serve):
                    body = uio.BytesIO(serve(*get[1:]) or b"")
                else:
                    body = uio.BytesIO(b"")
                self.write(s, body, headers)
        else:
            # no data in the TCP stream, so close the socket that was opened for this transmission
            self.close(s)

    def check_route(self, s, req):
        req_lines = req.split(b"\r\n")
        req_type, full_path, http_ver = req_lines[0].split(b" ")

        base_path = full_path.split(b"?")[0]
        if len(full_path.split(b"?")) > 1:
            params = full_path.split(b"?")[1].split(b"&")
        else:
            params = []
        print(req_type, base_path)
        if req_type != b"GET":
            headers = b"HTTP/1.1 404 Not Found"
            base_path = b"/"
            return headers, base_path
        if base_path in [b"/generate_204", b"/gen_204"]:
            print("\tgenerating 204 response for connectivity check")
            headers = b"HTTP/1.1 204 No Content\r\n"
            return headers, base_path
        if base_path in [b"/", b"/authenticating"]:
            headers = b"HTTP/1.1 200 OK\r\n"
            return headers, base_path
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
                headers = b"HTTP/1.1 302 OK\r\nLocation: /authenticating"
                base_path = b"/authenticating"
                return headers, base_path
            else:
                # wrong params
                self.redirect(s)
                return None, None
        else:
            # unrecognized path
            self.redirect(s)
            return None, None

    def redirect(self, s):
        headers = b"HTTP/1.1 307 Temporary Redirect\r\n"
        headers += b"Location: http://{:s}/".format(local_ip)
        body = uio.BytesIO(b"Please login first")
        self.write(s, body, headers)
        return None

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
            self.read(sock)

        print("{:s} -- done".format(self.name))
        return True


def configure_wan(mode="AP"):
    ap_mode = mode == "AP"

    STA_IF.active(not ap_mode)

    if ap_mode:
        AP_IF.active(False)
        while not AP_IF.active():
            print("waiting for AP mode to turn on")
            AP_IF.active(True)
            time.sleep(1)
        # IP address, netmask, gateway, DNS
        AP_IF.ifconfig((local_ip, "255.255.255.0", local_ip, local_ip))
        essid = b"ESP8266-%s" % binascii.hexlify(AP_IF.config("mac")[-3:])
        AP_IF.config(essid=essid, authmode=network.AUTH_OPEN)
        print("AP mode configured:", AP_IF.ifconfig())


def check_for_valid_wifi():
    global ssid, password, local_ip
    if ssid is None or password is None:
        return False
    print("Have WiFi Credentials, attempting connection...")
    STA_IF.active(True)
    STA_IF.connect(ssid, password)
    attempts = 0
    while attempts < 10:
        if not STA_IF.isconnected():
            print("Not connected yet")
            time.sleep(2)
            attempts += 1
        else:
            print("Connected to {:s}".format(ssid))
            AP_IF.active(False)
            local_ip = STA_IF.ifconfig()[0]
            gc.collect()
            return True
    configure_wan(mode="AP")
    print("Failed to connect to {:s} with {:s}".format(ssid, password))
    ssid = password = None
    gc.collect()
    return False


def captive_portal():
    global ssid, password
    ssid = password = None
    configure_wan(mode="AP")
    poller = select.poll()

    http_server = HTTPServer(poller)
    http_server.routefile("/", "./index.html")
    http_server.routefile("/authenticating", "./authenticating.html")
    dns_server = DNSServer(poller, local_ip)

    try:
        while not check_for_valid_wifi():
            if AP_IF.isconnected():
                gc.collect()
                for response in poller.ipoll(-1):
                    sock, event, *others = response
                    if sock is dns_server.sock and event == select.POLLHUP:
                        continue
                    if sock is dns_server.sock:
                        dns_server.handle(sock, event, others)
                    else:
                        # all other sockets should belong to HTTP
                        http_server.handle(sock, event, others)
            else:
                print("No clients connected to access point")
                time.sleep(1)
        else:
            print("Connected with IP:", local_ip)
    except KeyboardInterrupt:
        print("Captive portal stopped")
    print("Cleaning up")
    http_server.stop(poller)
    dns_server.stop(poller)
    gc.collect()
