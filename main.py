import network
import usocket as socket
import uselect as select
import uerrno
import ubinascii as binascii
import utime as time
import uio
import gc

LOCAL_IP = "192.168.4.1"

# https://success.tanaza.com/s/article/How-Automatic-Detection-of-Captive-Portal-works
CONN_CHECKS = [
    "akamai",
    "gstatic",
    "ncsi",
    "msftconnecttest",
    "connectivitycheck",
    "clients3",
    "google",
    "login",
    "gvt3",
    "apple",
    "gvt2",
]


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
        # ** create the response header **
        # copy the ID from incoming request
        packet = self.data[:2]
        # set response flags (assume RD=1 from request)
        packet += b"\x81\x80"
        # copy over QDCOUNT and set ANCOUNT equal
        packet += self.data[4:6] + self.data[4:6]
        # set NSCOUNT and ARCOUNT to 0
        packet += b"\x00\x00\x00\x00"

        # ** create the response body **
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

        return packet


class Server:
    def __init__(self, poller, port, sock_type, name):
        self.sock = socket.socket(socket.AF_INET, sock_type)
        poller.register(self.sock, select.POLLIN)
        self.port = port
        self.name = name
        self.listen()

    def listen(self):
        addr = socket.getaddrinfo("0.0.0.0", self.port)[0][-1]
        self.sock.bind(addr)
        print(self.name, "listening on", addr)

    def stop(self, poller):
        self.sock.close()
        poller.unregister(self.sock)
        print(self.name, "stopped")


class DNSServer(Server):
    def __init__(self, poller, ip_addr):
        super().__init__(poller, 53, socket.SOCK_DGRAM, "DNS Server")
        self.ip_addr = ip_addr
        self.sock.settimeout(1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def handle(self, sock, event, others):
        if sock is not self.sock:
            return
        print("Socket:", sock, "event", event)
        try:
            start = time.ticks_ms()
            data, sender = sock.recvfrom(1024)
            if not data:
                return
            diff = time.ticks_diff(time.ticks_ms(), start)
            print("DNS receipt took:", diff)
            request = DNSQuery(data)
            print("Sending {:s} -> {:s}".format(request.domain, self.ip_addr))
            sock.sendto(request.answer(self.ip_addr), sender)
        except Exception as e:
            if e.args[0] != uerrno.ETIMEDOUT:
                print("DNS server exception:", e)


class HTTPServer(Server):
    def __init__(self, poller):
        super().__init__(poller, 80, socket.SOCK_STREAM, "HTTP Server")
        poller.modify(self.sock, select.POLLIN)
        self.poller = poller
        self.routes = dict()
        self.request = dict()
        self.conns = dict()

    def listen(self):
        super().listen()
        self.sock.listen(5)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(False)

    def accept(self, s):
        sock, addr = s.accept()
        print("Accepted connection from:", addr)
        sock.setblocking(False)
        self.poller.register(sock, select.POLLIN)

    def routefile(self, path, file):
        self.routes[path.encode()] = file.encode()

    def read(self, s):
        r = s.read()
        if r:
            self.request[id(s)] = self.request.get(id(s), b"") + r
            if r[-4:] == b"\r\n\r\n":
                req = self.request.pop(id(s))
                get = req.split(b" ", 2)[1].split(b"?", 1)
                path = get[0]
                print("requested path:", path)
                serve = self.routes.get(path)
                headers = b"HTTP/1.1 200 OK\r\n"
                if type(serve) is bytes:
                    if serve[-3:] == b".gz":
                        headers += b"Content-Encoding: gzip\r\n"
                    body = open(serve, "rb")
                elif callable(serve):
                    body = uio.BytesIO(serve(*get[1:]) or b"")
                else:
                    headers = b"HTTP/1.1 404 Not Found\r\n"
                    body = uio.BytesIO(b"")
                headers += "\r\n"
                buf = bytearray(headers + "\x00" * (536 - len(headers)))
                bufmv = memoryview(buf)
                bw = body.readinto(bufmv[len(headers) :], 536 - len(headers))
                c = (body, buf, bufmv, [0, len(headers) + bw])
                self.conns[id(s)] = c
                self.poller.modify(s, select.POLLOUT)
        else:
            self.close(s)

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

    def handle(self, sock, event, others):
        print("handling HTTP")
        if sock is self.sock:
            print("HTTP accepting connection")
            self.accept(sock)
        elif event & select.POLLOUT:
            print("HTTP sending outgoing")
            c = self.conns[id(sock)]
            if c is None:
                print("failed to find outgoing socket")
                return False
            if c:
                w = sock.write(c[2][c[3][0] : c[3][1]])
                if not w or c[3][1] < 536:
                    self.close(sock)
                else:
                    bufferfile(c, w)
        elif event & select.POLLIN:
            print("HTTP reading incoming")
            self.read(sock)

        print("done handling HTTP")
        return True


def configure_wan():

    # turn off Station Mode
    network.WLAN(network.STA_IF).active(False)

    # turn on and configure Access Point Mode
    ap_if = network.WLAN(network.AP_IF)

    # IP address, netmask, gateway, DNS
    ap_if.ifconfig((LOCAL_IP, "255.255.255.0", LOCAL_IP, LOCAL_IP))
    essid = b"ESP8266-%s" % binascii.hexlify(ap_if.config("mac")[-3:])
    ap_if.config(essid=essid, authmode=network.AUTH_OPEN)
    ap_if.active(True)


def captive_portal():
    # create a poller for both DNS and HTTP sockets
    poller = select.poll()

    http_server = HTTPServer(poller)
    http_server.routefile("/", "./index.html")
    http_server.routefile("/generate_204", "./index.html")
    dns_server = DNSServer(poller, LOCAL_IP)
    try:
        while True:
            responses = poller.poll(100)
            if not responses:
                continue
            for response in responses:
                sock, event, *others = response
                if event == select.POLLHUP:
                    continue
                print("Response", response)
                if sock is dns_server.sock:
                    dns_server.handle(sock, event, others)
                else:
                    print("processing with HTTP")
                    http_server.handle(sock, event, others)
            gc.collect()
    except KeyboardInterrupt:
        print("Captive portal stopped")
        http_server.stop(poller)
        dns_server.stop(poller)


configure_wan()
