import network
import uos


class Creds:

    CRED_FILE = "./wifi.creds"

    def __init__(self):
        self.__ssid = None
        self.__password = None

    @property
    def password(self):
        return self.__password

    @password.setter
    def password(self, password):
        self.__password = password

    @property
    def ssid(self):
        return self.__ssid

    @ssid.setter
    def ssid(self, ssid):
        s = network.WLAN(network.STA_IF)
        s.active(True)
        for info in s.scan():
            if info[0].lower() == ssid.lower():
                self.__ssid = info[0]

    def exists(self):
        try:
            uos.stat(self.CRED_FILE)
        except OSError:
            return False

        return True

    def write(self):
        """Write credentials to CRED_FILE if valid input found."""
        if self.is_valid():
            f = open(self.CRED_FILE, "wb")
            f.write(b",".join([self.ssid, self.password]))
            f.close()

    def load(self):
        if self.exists() is True:
            print("Loading WiFi credentials from {:s}".format(self.CRED_FILE))
            contents = open(self.CRED_FILE, "rb").read().split(b",")
            if len(contents) == 2:
                self.ssid, self.password = contents
            else:
                self.remove()
        return self

    def remove(self):
        """Remove Wifi Credentials if they reside on disk."""
        if self.exists():
            uos.remove(self.CRED_FILE)

    def is_valid(self):
        return all((self.ssid, self.password))