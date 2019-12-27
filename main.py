import network
import uselect as select
import ubinascii as binascii
import utime as time
import gc

from captive_dns import DNSServer
from captive_http import HTTPServer

gc.collect()

AP_IP = "192.168.4.1"
local_ip = AP_IP
AP_IF = network.WLAN(network.AP_IF)
STA_IF = network.WLAN(network.STA_IF)

ssid = None
password = None


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
    else:
        print("turning off AP mode")


def has_creds():
    return ssid is not None and password is not None


def delete_creds():
    global ssid, password
    ssid = password = None


def check_for_valid_wifi():

    if STA_IF.isconnected():
        print("already connected as a station")
        return False
    elif not has_creds():
        # no creds, and not station-connected
        return False

    print("Have WiFi credentials, attempting connection...")
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
            global local_ip
            local_ip = STA_IF.ifconfig()[0]
            return True
    print("Failed to connect to {:s} with {:s}".format(ssid, password))
    delete_creds()
    STA_IF.active(False)
    return False


def captive_portal():
    global ssid, password
    ssid = password = None
    configure_wan(mode="AP")
    poller = select.poll()

    http_server = HTTPServer(poller, local_ip)
    http_server.routefile("/", "./index.html")
    http_server.routefile("/authenticating", "./authenticating.html")
    dns_server = DNSServer(poller, local_ip)

    try:
        while True:
            if AP_IF.isconnected():
                gc.collect()
                for response in poller.ipoll(1000):
                    sock, event, *others = response
                    if sock is dns_server.sock and event == select.POLLHUP:
                        time.sleep_ms(500)
                        continue
                    if sock is dns_server.sock:
                        dns_server.handle(sock, event, others)
                    else:
                        # all other sockets should belong to HTTP
                        res = http_server.handle(sock, event, others)
                        if res:
                            print("res:", res)
                            ssid, password = res

            else:
                print("No clients connected to access point")
                time.sleep(1)
            if check_for_valid_wifi():
                print("updating http server with new local ip:", local_ip)
                http_server.set_ip(local_ip)
        else:
            print("Connected with IP:", local_ip)
    except KeyboardInterrupt:
        print("Captive portal stopped")

    print("Cleaning up")
    http_server.stop(poller)
    dns_server.stop(poller)
    gc.collect()
