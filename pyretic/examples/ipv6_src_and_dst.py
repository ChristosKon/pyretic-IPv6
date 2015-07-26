from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pox.lib.packet import *


def src(pkt):
    print pkt.header['srcip']

def dst(pkt):
    print pkt.header['dstip']

def main():
