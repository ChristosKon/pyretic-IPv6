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
    """Dynamic Policy, after initialization it works with queries and callbacks"""
    def __init__(self):
        super(dynamic_check,self).__init__()
        self.flood = flood()           # REUSE A SINGLE FLOOD INSTANCE
        self.set_initial_state()
        self.current = {}

    def set_initial_state(self):
        """Initialize query policies for monitoring and forwarding"""
        paket_multi = packets(1,['dstip'])
        paket_int = packets(1,['srcip','dstip'])
        self.query3 = count_packets(900, ['srcip'])

        self.query = match(inport=1) >> match(icmpv6_type=135) >> paket_multi
        paket_multi.register_callback(self.is_it_active)

        self.query2 = (match(inport=2) | match(inport=3)) >> paket_int
        paket_int.register_callback(self.lists)

        self.query3.register_callback(self.timeout)

        self.forward = self.flood
        self.update_policy()

    def set_network(self,network):
        """A hacky way to update our system if a host left our network"""
        change = network.something
        for k, v in active.items():
            if change == v:
                active.__delitem__(k)

    def update_policy(self):
        """Update the policy based on current forward and query policies"""
        self.policy = self.forward + self.query + self.query2 + self.query3

    def is_it_active(self,pkt):
        """Find from Neighbor Solicitation the destination IP and check for blacklist"""
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
            try:
                self.intruder = candidates[destination]
                if blacklist.get(self.intruder) is None:
                    blacklist[self.intruder] = 1
                else:
                    blacklist[self.intruder] += 1
                    if blacklist[self.intruder] >= 3:
                        self.block_this_ip(pkt)
            except:
                pass

    def block_this_ip(self,pkt):
        """Update forward policy based on newly blocked srcip"""
        self.forward = if_(match(srcip=self.intruder), drop, self.forward)
        print "blacklist:" + str(blacklist)
        self.update_policy()

    def lists(self,pkt):
        """ Track {dstip: srcip} as candidate for attack + check if new srcip in active  """
        candidates[pkt['dstip']] = pkt['srcip']
        if pkt['srcip'] not in active:
            active[pkt['srcip']].append(pkt['switch'])
            active[pkt['srcip']].append(pkt['inport'])

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
                print "{}"

def main():
    return dynamic_check()
