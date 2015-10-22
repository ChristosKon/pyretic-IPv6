from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pox.lib.packet import *
from pox.lib.packet.icmpv6 import icmpv6
from packet_utils import *
from packet_base import packet_base

from pox.lib.addresses import IPAddr6,EthAddr
from pox.lib.util import hexdump, init_helper



def build_neighbor_advertisement(req,srcip):
    reply = NDNeighborAdvertisement()

    reply.target = oct(str_to_array(srcip))
    if len(self.options): reply.opts = req.options
    if self.is_router: reply.router = True
    if self.is_solicited: reply.solicited = True
    if self.is_override: reply.override = True
    # We have to deal with multicast (ff...)

    frame = ethernet()
    frame.dst = req.hwsrc
    frame.src = req.hwdst
    frame.set_payload(reply)
    return frame

