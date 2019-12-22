import network
import usocket as socket
import uselect as select
import ubinascii as binascii
import utime as time

LOCAL_IP = "192.168.4.1"

CONN_CHECKS = [
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
        head = 12  # header is bytes 0-11, so question starts on byte 12
        length = data[head]  # length of this label defined in first byte
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


class DNSServer:
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.poller = select.poll()
        self.poller.register(self.udp_sock, select.POLLIN)

    def listen(self):
        self.udp_sock.bind(("0.0.0.0", 53))
        self.udp_sock.setsockopt(socket.SOL_SOCKET, 20, self.handler)
        try:
            while True:
                self.poll()
                time.sleep(1)
        except KeyboardInterrupt as e:
            print("DNSServer stopped:", str(e))
            self.udp_sock.close()

    def poll(self):
        ready = self.poller.poll(100)
        try:
            data, sender = self.udp_sock.recvfrom(1024)
            p = DNSQuery(data)
            # check if this is a connectivity check and respond with our own IP
            if any(word in p.domain for word in CONN_CHECKS):
                self.udp_sock.sendto(p.answer(self.ip_addr), sender)
                print("Replying: {:s} -> {:s}".format(p.domain, self.ip_addr))
            else:
                print("Not replying to:", p.domain)
        except Exception as e:
            print("Exception:", str(e), e)

    def handler(self, sock):
        print("handler from", sock)


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
    dns_server = DNSServer(LOCAL_IP)
    dns_server.listen()


configure_wan()
