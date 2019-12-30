import usocket as socket
import gc

from server import Server


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

            # help MicroPython with memory management
            del request
            gc.collect()
        except Exception as e:
            print("DNS server exception:", e)
