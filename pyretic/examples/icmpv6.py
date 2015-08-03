from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pox.lib.packet import *


def check_icmpv6(pkt):

    print pkt
    print "------------------------------------"
    srcipv6 = pkt.header['srcip']
    print srcipv6

    raw_bytes = [ord(c) for c in pkt['raw']]
    #print "ethernet payload is %d" % pkt['payload_len']

    eth_payload_bytes = raw_bytes[pkt['header_len']:]
    #print "ethernet payload is %d bytes" % len(eth_payload_bytes)

    #ip_next_header = eth_payload_bytes[6]
    #print "ip_next_header = %d" % ip_next_header
    if eth_payload_bytes[6] == 58:
        print "icmpv6 type = %d" % eth_payload_bytes[40]
    #return (Filter(srcip("fe80::a8b7:7fff:feaf:154")))


def pack():
    q = packets()
    q.register_callback(check_icmpv6)
    return q

def main():
    return (match(ethtype=34525) >> pack()) + flood()