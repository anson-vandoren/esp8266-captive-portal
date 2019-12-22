import network
import usocket as socket
import uselect as select
import utime as time

LOCAL_IP = "192.168.4.1"


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
            print(data)
            print(sender)
        except Exception as e:
            print("Exception:", str(e))

    def handler(self, sock):
        print("handler from", sock)


def configure_wan():
    import ubinascii

    # turn off Station Mode
    network.WLAN(network.STA_IF).active(False)

    # turn on and configure Access Point Mode
    ap_if = network.WLAN(network.AP_IF)

    # IP address, netmask, gateway, DNS
    ap_if.ifconfig((LOCAL_IP, "255.255.255.0", LOCAL_IP, LOCAL_IP))
    essid = b"ESP8266-%s" % ubinascii.hexlify(ap_if.config("mac")[-3:])
    ap_if.config(essid=essid, authmode=network.AUTH_OPEN)
    ap_if.active(True)


def captive_portal():
    dns_server = DNSServer(LOCAL_IP)
    dns_server.listen()


configure_wan()
