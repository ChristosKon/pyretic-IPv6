from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pox.lib.packet import *
from pox.lib.packet.icmpv6 import NDNeighborAdvertisement

class l3_learning(DynamicPolicy):
    global nbdTable
    nbdTable = {}

    def __init__(self):
        super(l3_learning,self).__init__()
        self.flood = flood()           # REUSE A SINGLE FLOOD INSTANCE
        self.set_initial_state()


    def set_initial_state(self):
        self.query = packets(1,['srcip','switch'])
        self.query.register_callback(self.check_ip)
        self.forward = self.flood  # REUSE A SINGLE FLOOD INSTANCE
        self.update_policy()

    def set_network(self,network):
        self.set_initial_state()

    def update_policy(self):
        """Update the policy based on current forward and query policies"""
        self.policy = self.forward + self.query

    def check_ip(self,pkt):
        if pkt['srcip'] in ndbTable:
            if ndbTable[srcmac] != [pkt['srcmac'], pkt['inport']]:
                print "Update" + nbdTable[srcmac]
            else:
                print "Learn" + nbdTable[srcmac]
            nbdTablep[srcmac] = [pkt['srcmac'], pkt['inport']]

        self.forward = if_(match(dstip=pkt['srcip'],
                                switch=pkt['switch']),
                          fwd(pkt['inport']),
                          self.forward)
        self.update_policy()

        if pkt['dstip'] in nbdTable:
            reply(pkt)
        else:
            flood()

    def reply(pkt):
        if icmpv6_solicitation(pkt):
            r = NDNeighborAdvertisement()
            r.is_solicited = True
            r.target = pkt['srcip']

    def icmpv6_solicitation(pkt):
        yo = false
        if pkt['ethtype'] == 34525:
            raw_bytes = [ord(c) for c in pkt['raw']]
            eth_payload_bytes = raw_bytes[pkt['header_len']:]
            if eth_payload_bytes[40] == 135:
                yo = true
        return yo

def main():
    return l3_learning()

