import gc

import network
import ubinascii as binascii
import uerrno
import uos as os
import uselect as select
import utime as time

from captive_http import HTTPServer

gc.collect()

from captive_dns import DNSServer


class CaptivePortal:
    AP_IP = "192.168.4.1"
    AP_OFF_DELAY = const(10 * 1000)
    CRED_FILE = "./wifi.creds"
    MAX_CONN_ATTEMPTS = 10

    def __init__(self, essid=None):
        self.local_ip = self.AP_IP
        self.ssid = None
        self.password = None
        self.conn_time_start = None
        self.sta_if = network.WLAN(network.STA_IF)
        self.ap_if = network.WLAN(network.AP_IF)
        self.http_server = None
        self.dns_server = None
        if essid is None:
            essid = b"ESP8266-%s" % binascii.hexlify(self.ap_if.config("mac")[-3:])
        self.essid = essid
        self.poller = select.poll()

    def has_creds(self):
        return self.ssid is not None and self.password is not None

    def delete_creds(self):
        self.ssid = self.password = None

    def write_creds(self, ssid, password):
        open(self.CRED_FILE, "wb").write(b",".join([ssid, password]))
        print("Wrote credentials to {:s}".format(self.CRED_FILE))

    def connect_to_wifi(self):
        print(
            "Trying to connect to WiFi '{:s} with password {:s}".format(
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
        # forget possibly bad credentials and turn off station mode
        self.delete_creds()
        self.sta_if.active(False)
        return False

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

    def handle_dns(self, sock, event, others):
        if sock is self.dns_server.sock:
            # ignore UDP socket hangups
            if event == select.POLLHUP:
                time.sleep_ms(500)
                return True
            # handle DNS server first since HTTP may have many sockets open
            self.dns_server.handle(sock, event, others)
            return True

    def handle_http(self, sock, event, others):
        # remaining sockets should belong to HTTP
        res = self.http_server.handle(sock, event, others)
        if res:
            self.ssid, self.password = res
            print("Got WiFi credentials from captive portal:", self.ssid, self.password)

    def check_valid_wifi(self):
        if not self.sta_if.isconnected():
            if self.has_creds():
                # have credentials to connect, but not yet connected
                return self.connect_to_wifi()
            # not connected, and no credentials to connect yet
            return False

        if not self.ap_if.active():
            # access point is already off; do nothing
            print(".", end="")
            return False

        # already connected to WiFi, so turn off Access Point after a delay
        if self.conn_time_start is None:
            self.conn_time_start = time.ticks_ms()
            remaining = self.AP_OFF_DELAY
        else:
            remaining = self.AP_OFF_DELAY - time.ticks_diff(
                time.ticks_ms(), self.conn_time_start
            )
            print("Turning off access point in {:d} seconds".format(remaining // 1000))
            if remaining <= 0:
                self.ap_if.active(False)
                print("Turned off access point")

    def captive_portal(self):
        self.start_access_point()

        if self.http_server is None:
            print("Configured HTTP server")
            self.http_server = HTTPServer(self.poller, self.local_ip)
            self.http_server.routefile("/", "./index.html")
            self.http_server.routefile("/authenticating", "./authenticating.html")
        if self.dns_server is None:
            print("Configured DNS server")
            self.dns_server = DNSServer(self.poller, self.local_ip)

        try:
            while True:
                gc.collect()
                # check for socket events and handle them
                for response in self.poller.ipoll(1000):
                    sock, event, *others = response
                    # try DNS server first
                    is_handled = self.handle_dns(sock, event, others)
                    # if DNS didn't handle the event, send to HTTP
                    if not is_handled:
                        self.handle_http(sock, event, others)

                if self.check_valid_wifi():
                    print("Updating servers with new IP address and SSID")
                    self.http_server.set_ip(self.local_ip, self.ssid)
                    self.dns_server.set_ip(self.local_ip)

                # turn off DNS server once transitioned to actual WiFi
                if not self.ap_if.active() and self.dns_server.is_active:
                    print("Stopping DNS server")
                    self.dns_server.stop(self.poller)
                    self.dns_server.is_active = False
        except KeyboardInterrupt:
            print("Captive portal stopped")

        self.cleanup()

    def cleanup(self):
        print("Cleaning up")
        if self.http_server:
            self.http_server.stop(self.poller)
        if self.dns_server:
            self.dns_server.stop(self.poller)
        gc.collect()

    def try_connect_from_file(self):
        try:
            os.stat(self.CRED_FILE)
        except OSError as e:
            if e.args[0] == uerrno.ENOENT:
                # file does not exist
                return False

        contents = open(self.CRED_FILE, "rb").read().split(b",")
        if len(contents) == 2:
            self.ssid, self.password = contents
        else:
            print("Failed to connect:", contents)
            return False
        if not self.connect_to_wifi():
            print("Failed to connect with stored credentials, starting captive portal")
            os.remove(self.CRED_FILE)
            return False
        return True

    def start(self):
        self.sta_if.active(False)
        if not self.try_connect_from_file():
            self.captive_portal()
