from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pox.lib.packet import *
from pyretic.examples.icmpv6 import pack

h2_ip = IPAddr('fe80::200:ff:fe00:2')
multicast_h2_ip = IPAddr('ff02::1:ff00:2')

h1_ip = IPAddr('fe80::200:ff:fe00:1')
multicast_h1_ip = IPAddr('ff02::1:ff00:1')

def only_from_h2():
    return (
        (match(dstip=h2_ip) + match(dstip=multicast_h2_ip) >> match(inport=1) + match(inport=2) >> fwd(2)) +
        (match(dstip=h1_ip) + match(dstip=multicast_h1_ip) >> match(inport=2) + match(inport=3) >> fwd(1))
    )

def main():

    return only_from_h2()