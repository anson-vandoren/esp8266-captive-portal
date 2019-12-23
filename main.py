import network
import usocket as socket
import uselect as select
import ubinascii as binascii
import utime as time

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
        self.poller = poller
        self.poller.register(self.sock, select.POLLIN | select.POLLOUT)
        self.port = port
        self.name = name
        self.listen()

    def listen(self):
        addr = socket.getaddrinfo("0.0.0.0", self.port)[0][-1]
        self.sock.bind(addr)
        print(self.name, "listening on", addr)

    def poll(self):
        # check if there is an incoming connection on this socket
        response = self.poller.poll(500)
        if not response:
            print("no response for", self.name)
            return
        response = response[0]
        sock, event, *others = response
        if sock != self.sock:
            return
        self.handle(sock, event, others)

    def stop(self):
        self.poller.unregister(self.sock)
        self.sock.close()
        print(self.name, "stopped")


class DNSServer(Server):
    def __init__(self, poller, ip_addr):
        super().__init__(poller, 53, socket.SOCK_DGRAM, "DNS Server")
        self.ip_addr = ip_addr

    def handle(self, sock, event, others):
        try:
            data, sender = sock.recvfrom(1024)
            request = DNSQuery(data)
            # check if this is a connectivity check and respond with our own IP
            sock.sendto(request.answer(self.ip_addr), sender)
            if any(word in request.domain for word in CONN_CHECKS):
                sock.sendto(request.answer(self.ip_addr), sender)
                print("Replying: {:s} -> {:s}".format(request.domain, self.ip_addr))
            else:
                sock.sendto(request.answer(self.ip_addr), sender)
                print("Not replying to:", request.domain)
        except Exception as e:
            print("DNS server exception:", e)


class HTTPServer(Server):
    def __init__(self, poller):
        super().__init__(poller, 80, socket.SOCK_STREAM, "HTTP Server")

    def listen(self):
        super().listen()
        print("http listening")
        self.sock.listen(1)

    def handle(self, sock, event, others):
        print("handling HTTP")
        try:
            data, addr = sock.recvfrom(1024)
            print("HTTP Socket connected to:", addr, "and got data", data)
            self.sock.send(
                "<html><head><title>test</title></head><body>testtesttest</body></html>"
            )
            print("done sending HTTP")
        except Exception as e:
            print("HTTP server exception:", str(e))
        print("done handling HTTP")


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
    dns_server = DNSServer(poller, LOCAL_IP)
    try:
        while True:
            http_server.poll()
            dns_server.poll()
    except KeyboardInterrupt:
        print("Captive portal stopped")
        http_server.stop()
        dns_server.stop()


configure_wan()
