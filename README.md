#Pyretic in IPv6
A modification of the [Pyretic](https://github.com/frenetic-lang/pyretic) project that supports IPv6 . It is based on Pox controller using Nicira-extensions for the IPv6 support. Following the instructions below you will be able to start on mininet a Software Defined Network (2 hosts - switch - router - switch - 2 hosts) which detects and stops Network scanning in IPv6. You can test it pinging nonexistent network's IPs .

## Getting started
This project is developed and tested on Ubuntu 14.04, 64-bit, using Mininet 2.1.0 ([link](https://github.com/mininet/mininet/wiki/Mininet-VM-Images))

### Install Pyretic

Follow the instructions provided in [Pyretic setup](https://github.com/frenetic-lang/pyretic/wiki/Building-the-Pyretic-VM) changing step 6 to: 
`git clone https://github.com/ChristosKon/pyretic-IPv6.git`
and step 7 to the relevant path.

### Install Mininext

Install Mininext following the instructions described at https://github.com/USC-NSL/miniNExT.

### Quagga setup

Initially, you need to install quagga:
`sudo apt-get install quagga`

Then you need to configure Quagga: 
- at `/etc/quagga/daemons` change `zebra=yes`
- at `/etc/quagga` create an empty file `zebra.conf`
- run `/etc/init.d/quagga restart`

### VM configurations

At `/etc/sysctl.conf` change:
- `net.ipv6.conf.all.forwarding=1`
- `net.ipv6.conf.all.disable_ipv6 = 0`
- `net.ipv6.conf.default.disable_ipv6 = 0`
- `net.ipv6.conf.lo.disable_ipv6 = 0`

### My quagga-ixp folder:

You can get it at: 
`wget https://pithos.okeanos.grnet.gr/public/mchhXGEwvMfGXATPukEQv3`

### Proof of concept

Go at `/quagga-ixp` and run:
`sudo python start.py`

Open a second terminal and run:
`pyretic.py -m p0 pyretic.examples.anti-honeypot`
