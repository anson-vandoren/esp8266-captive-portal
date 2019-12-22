import network

LOCAL_IP = "192.168.4.1"


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


configure_wan()
