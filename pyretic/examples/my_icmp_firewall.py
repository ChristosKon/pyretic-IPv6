from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.examples.dpi import dpi

class icmpv6_control(DynamicPolicy):
    #global times
    #times = 0

    def __init__(self):
        super(icmpv6_control ,self).__init__()
        self.flood = flood()           # REUSE A SINGLE FLOOD INSTANCE
        self.set_initial_state()

    def set_initial_state(self):
        self.query = packets(1,['srcmac', 'switch'])
        self.query.register_callback(self.learn_mac)
        self.forward = self.flood  # REUSE A SINGLE FLOOD INSTANCE
        self.update_policy()

    def set_network(self,network):
        self.set_initial_state()

    def update_policy(self):
        """Update the policy based on current forward and query policies"""
        self.policy = self.forward + self.query
        print "I am in update_policy"

    def learn_mac(self,pkt):
        #failed = {pkt['srcmac']:times}
        raw_bytes = [ord(c) for c in pkt['raw']]
        eth_payload_bytes = raw_bytes[pkt['header_len']:]
        if eth_payload_bytes[6] == 58 & eth_payload_bytes[40] == 135:
            print pkt['srcmac'] + "sends a Neighbor Solicitation to" + pkt['dstmac']
        self.forward = if_(match(dstmac=pkt['srcmac'],
                                switch=pkt['switch']),
                          fwd(pkt['inport']),
                          self.forward)
        self.update_policy()


def main():
    return match(ethtype=34525) >> icmpv6_control()