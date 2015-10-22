"""
You can test it pinging between hosts in the same network.
"""

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.core.network import IPAddr
from collections import defaultdict

active = defaultdict(list)
candidates = {}
blacklist = {}
innocent = [IPAddr("fc00:0:0:1::8"),IPAddr("fc00:0:0:2::8")]

class dynamic_check(DynamicPolicy):
    """Dynamic policy that detect network scanners according to the number of neighbor solicitation
       to non active IP addresses."""
    def __init__(self):
        super(dynamic_check,self).__init__()
        self.flood = flood()           # REUSE A SINGLE FLOOD INSTANCE
        self.set_initial_state()
        self.current = {}

    def set_initial_state(self):
        q = packets()

        self.query = (match(icmpv6_type=135)) >> q
        q.register_callback(self.check_destination)

        self.query2 = count_packets(900, ['srcip'])
        self.query2.register_callback(self.timeout)

        self.query3 = packets(1,['srcmac','switch'])
        self.query3.register_callback(self.learn_new_MAC)

        self.forward = self.flood  # REUSE A SINGLE FLOOD INSTANCE
        self.update_policy()

    def set_network(self,network):
        change = network.something
        for k, v in active.items():
            if change == v:
                active.__delitem__(k)

    def update_policy(self):
        """Update the policy based on current forward and query policies"""
        self.policy = self.forward + self.query + self.query2 + self.query3

    def learn_new_MAC(self,pkt):
        """Update forward policy based on newly seen (mac,port) + add srcip in active {srcip: [switch inport]}"""
        self.forward = if_(match(dstmac=pkt['srcmac'],
                                switch=pkt['switch']),
                          fwd(pkt['inport']),
                          self.forward)
        self.update_policy()
        if pkt['srcip'] not in active:
            active[pkt['srcip']].append(pkt['switch'])
            active[pkt['srcip']].append(pkt['inport'])

    def check_destination(self,pkt):
        """Update forward policy based on newly seen (mac,port)"""
        address = ""
        raw_bytes = [ord(c) for c in pkt['raw']]
        eth_payload_bytes = raw_bytes[pkt['header_len']:]
        for i in range(48,64):
            address += str(hex(eth_payload_bytes[i])[2:].zfill(2))
            if i%2 == 1:
                address += ":"
        address = address[:-1]
        destination= IPAddr(address)
        if (destination not in active) and (destination not in innocent):
            if blacklist.get(pkt['srcip']) is None:
                blacklist[pkt['srcip']] = 1
            else:
                blacklist[pkt['srcip']] += 1
                if blacklist[pkt['srcip']] >= 6:
                    self.block_this_ip(pkt)

    def block_this_ip(self,pkt):
        """Update forward policy based on newly blocked srcmac"""
        self.forward = if_(match(srmac=pkt['srcmac']), drop, self.forward)
        print "blacklist:" + str(blacklist)
        self.update_policy()

    def timeout(self,counts):
        """Represent host's timeout. Remove inactive IPs from 'active' dictionary"""
        old = self.current.copy()
        for key, value in counts.iteritems():
            self.current[key] = value

        for key in old:
            if key in self.current:
                new_packs = self.current[key] - old[key]
                if str(new_packs) == "0":
                    k = str(str(key).split('\'')[-2]).split('/')[-2]
                    if active[IPAddr(k)]:
                        active.__delitem__(IPAddr(k))
            else:
                pass

def main():
    return dynamic_check()