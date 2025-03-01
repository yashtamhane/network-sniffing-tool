from dnslib.server import DNSServer, DNSHandler, BaseResolver
from dnslib import RR, QTYPE, A

class TestResolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=60))
        return reply

resolver = TestResolver()
server = DNSServer(resolver, port=5353, address="127.0.0.1")
server.start_thread()

print("DNS server running on 127.0.0.1:5353")
import time
while True:
    time.sleep(1)
