import gc
import network
import ubinascii as binascii
import uerrno
import uos as os
import uselect as select
import utime as time

from captive_dns import DNSServer
from captive_http import HTTPServer


class CaptivePortal:
    AP_IP = "192.168.4.1"
    AP_OFF_DELAY = const(10 * 1000)
    CRED_FILE = "./wifi.creds"
    MAX_CONN_ATTEMPTS = 10

    def __init__(self, essid=None):
        self.local_ip = self.AP_IP
        self.sta_if = network.WLAN(network.STA_IF)
        self.ap_if = network.WLAN(network.AP_IF)

        if essid is None:
            essid = b"ESP8266-%s" % binascii.hexlify(self.ap_if.config("mac")[-3:])
        self.essid = essid

        self.dns_server = None
        self.http_server = None
        self.poller = select.poll()

        self.ssid = None
        self.password = None

        self.conn_time_start = None

    def start_access_point(self):
        # sometimes need to turn off AP before it will come up properly
        self.ap_if.active(False)
        while not self.ap_if.active():
            print("Waiting for access point to turn on")
            self.ap_if.active(True)
            time.sleep(1)
        # IP address, netmask, gateway, DNS
        self.ap_if.ifconfig(
            (self.local_ip, "255.255.255.0", self.local_ip, self.local_ip)
        )
        self.ap_if.config(essid=self.essid, authmode=network.AUTH_OPEN)
        print("AP mode configured:", self.ap_if.ifconfig())

    def connect_to_wifi(self):
        print(
            "Trying to connect to SSID '{:s}' with password {:s}".format(
                self.ssid, self.password
            )
        )
        # initiate the connection
        self.sta_if.active(True)
        self.sta_if.connect(self.ssid, self.password)

        attempts = 0
        while attempts < self.MAX_CONN_ATTEMPTS:
            if not self.sta_if.isconnected():
                print("Connection in progress")
                time.sleep(2)
                attempts += 1
            else:
                print("Connected to {:s}".format(self.ssid))
                self.local_ip = self.sta_if.ifconfig()[0]
                self.write_creds(self.ssid, self.password)
                return True

        print(
            "Failed to connect to {:s} with {:s}. WLAN status={:d}".format(
                self.ssid, self.password, self.sta_if.status()
            )
        )
        # forget the credentials since they didn't work, and turn off station mode
        self.ssid = self.password = None
        self.sta_if.active(False)
        return False

    def check_valid_wifi(self):
        if not self.sta_if.isconnected():
            if self.has_creds():
                # have credentials to connect, but not yet connected
                # return value based on whether the connection was successful
                return self.connect_to_wifi()
            # not connected, and no credentials to connect yet
            return False

        if not self.ap_if.active():
            # access point is already off; do nothing
            return False

        # already connected to WiFi, so turn off Access Point after a delay
        if self.conn_time_start is None:
            self.conn_time_start = time.ticks_ms()
            remaining = self.AP_OFF_DELAY
        else:
            remaining = self.AP_OFF_DELAY - time.ticks_diff(
                time.ticks_ms(), self.conn_time_start
            )
            if remaining <= 0:
                self.ap_if.active(False)
                print("Turned off access point")
        return False

    def has_creds(self):
        self.ssid, self.password = self.http_server.saved_credentials
        return None not in [self.ssid, self.password]

    def write_creds(self, ssid, password):
        open(self.CRED_FILE, "wb").write(b",".join([ssid, password]))
        print("Wrote credentials to {:s}".format(self.CRED_FILE))

    def captive_portal(self):
        print("Starting captive portal")
        self.start_access_point()

        if self.http_server is None:
            self.http_server = HTTPServer(self.poller, self.local_ip)
            print("Configured HTTP server")
        if self.dns_server is None:
            self.dns_server = DNSServer(self.poller, self.local_ip)
            print("Configured DNS server")

        try:
            while True:
                gc.collect()
                # check for socket events and handle them
                for response in self.poller.ipoll(1000):
                    sock, event, *others = response
                    is_handled = self.handle_dns(sock, event, others)
                    if not is_handled:
                        self.handle_http(sock, event, others)

                if self.check_valid_wifi():
                    print("Connected to WiFi!")
                    self.http_server.set_ip(self.local_ip, self.ssid)
                    self.dns_server.stop(self.poller)

                if not self.ap_if.active() and self.dns_server.is_active:
                    print("Stopping DNS server")
                    self.dns_server.stop(self.poller)

        except KeyboardInterrupt:
            print("Captive portal stopped")
        self.cleanup()

    def handle_dns(self, sock, event, others):
        if sock is self.dns_server.sock:
            # ignore UDP socket hangups
            if event == select.POLLHUP:
                return True
            self.dns_server.handle(sock, event, others)
            return True
        return False

    def handle_http(self, sock, event, others):
        self.http_server.handle(sock, event, others)

    def cleanup(self):
        print("Cleaning up")
        if self.dns_server:
            self.dns_server.stop(self.poller)
        gc.collect()

    def try_connect_from_file(self):
        print("Trying to load WiFi credentials from {:s}".format(self.CRED_FILE))
        try:
            os.stat(self.CRED_FILE)
        except OSError as e:
            if e.args[0] == uerrno.ENOENT:
                print("{:s} does not exist".format(self.CRED_FILE))
                return False

        contents = open(self.CRED_FILE, "rb").read().split(b",")
        if len(contents) == 2:
            self.ssid, self.password = contents
        else:
            print("Invalid credentials file:", contents)
            return False

        if not self.connect_to_wifi():
            print("Failed to connect with stored credentials, starting captive portal")
            os.remove(self.CRED_FILE)
            return False

        return True

    def start(self):
        # turn off station interface to force a reconnect
        self.sta_if.active(False)
        if not self.try_connect_from_file():
            self.captive_portal()
