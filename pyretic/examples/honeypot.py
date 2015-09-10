from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.core.network import IPAddr
from pyretic.modules.mac_learner import mac_learner

a1_eth0a = IPAddr('fe80::9039:d9ff:feef:1f40')
a1_eth0b = IPAddr('fc00:0:0:1::8')
a1_eth1a = IPAddr('fe80::e0ce:eff:fef4:cd0f')
a1_eth1b = IPAddr('fc00:0:0:2::8')
whitelist = [a1_eth0a,a1_eth0b,a1_eth1a,a1_eth1b]
blacklist = {}

class honeypot(DynamicPolicy):
    """Standard MAC-learning logic"""
    def __init__(self):
        super(honeypot,self).__init__()          # REUSE A SINGLE FLOOD INSTANCE
        print "here1"
        self.set_initial_state()

    def set_initial_state(self):
        print "initial state"
        self.query = packets(1,['dstip','switch'])
        self.query.register_callback(self.in_or_out)
        print "too smart"
        self.forward = flood()
        self.update_policy()

    def set_network(self,network):
        print "let's set network"
        self.set_initial_state()

    def update_policy(self):
        """Update the policy based on current forward and query policies"""
        print "let's update policy"
        self.policy = self.forward + self.query

    def block_this_ip(self,pkt):
        """Update forward policy based on newly seen (mac,port)"""
        print "let's block it"
        self.forward = if_(match(srcip=pkt['srcip']), drop, self.forward)
        self.update_policy()

    def in_or_out(self,pkt):
        if pkt['ethtype'] == 34525:
            raw_bytes = [ord(c) for c in pkt['raw']]
            eth_payload_bytes = raw_bytes[pkt['header_len']:]
            print eth_payload_bytes[40]
            if eth_payload_bytes[6] == 58 or eth_payload_bytes[6] == 89:
                if eth_payload_bytes[40] == 135:
                    if pkt['inport'] == 1:
                        if pkt['dstip'] in whitelist:
                            print "in whitelist, just sent"
                        else:
                            if blacklist.get(pkt['srcip']) is None:
                                blacklist[pkt['srcip']] = 1
                                print "added in blacklist"
                            else:
                                blacklist[pkt['srcip']] += 1
                                print "already in blacklist, updated"
                                if blacklist[pkt['srcip']] >= 2:
                                    self.block_this_ip(pkt)
                    else:
                        print "From inside, ip:" + str(pkt['srcip'])
                        if pkt['srcip'] in whitelist:
                            print whitelist
                        else:
                            whitelist.append(pkt['srcip'])
                            print "added in whitelist"
                            print whitelist
                else:
                    print "No neighbor solicitation"
def main():
    return mac_learner() >> honeypot()