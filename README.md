# Router Final Project
Adam Wolnikowski

16 November 2020

Final project submission for CPSC 435 at Yale University with Prof. Robert Soule

Implementation of an internet router control- and data-plane, in python and p4, respectively.

main.py instantiates the following topology:

    (h2)--(r2)-----(r3)--(h3)
            |     / |
            |    /  |
            |   /   |
            |  /    |
            | /     |
    (h1)--(r1)-----(r4)--(h4)

# Data-Plane Basic Requirements

* ~~Provide a routing table~~ that can store IP address/prefix pairs with their associated port and next-hop IP address.
* ~~Use the routing table to perform a longest prefix match~~ on destination IP addresses and return the appropriate egress port and next-hop address (or 0.0.0.0 for a directly attached destination).
    * NOTE: We will use a ternary match table for the routing table because LPM tables are not fully supported by SDNet yet.
* ~~Provide an ARP table~~ that can store at least 64 entries. This will accept an IP address as a search key and will return the associated MAC address (if found). This table is modified by the software, which runs its own ARP protocol.
* ~~Provide a “local IP address table”~~. This will accept an IP address as a search key and will return a signal that indicates whether the correspond address was found. This table is used to identify IP addresses that should be forwarded to the CPU.
* Decode incoming IP packets and perform the operations required by a router. These include (but are not limited to):
    * verify that the existing checksum and ~~TTL are valid~~
    * ~~look up the next-hop port and IP address in the route table~~
    * ~~look up the MAC address of the next-hop in the ARP table~~
    * ~~set the src MAC address based on the port the packet is departing from~~
    * ~~decrement TTL~~
    * ~~calculate a new IP checksum~~
    * ~~transmit the new packet via the appropriate egress port~~
    * ~~local IP packets (destined for the router) should be sent to the software~~
    * ~~PWOSPF packets should be sent to the software~~
    * ~~packets for which no matching entry is found in the routing table should be sent to the software~~
    * ~~any packets that the hardware cannot deal with should be forwarded to the CPU. (e.g. not Version 4 IP)~~
* Provide counters for the following:
    * ~~IP packets~~
    * ~~ARP packets~~
    * ~~Packets forwarded to the control-plane~~

# Control-Plane Basic Requirements

* ~~Sending ARP requests~~
* ~~Responding to ARP requests~~ (chose to implement in control plane so request sender's info can be cached in ARP table)
* ~~Updating entries in the hardware ARP cache~~ (not possible with current API)
* ~~Timing out entries in the hardware ARP cache~~
* ~~Queuing packets pending ARP replies~~
* ~~Responding to ICMP echo requests~~
* ~~Generating ICMP host unreachable packets~~
* ~~Handling corrupted or otherwise incorrect IP packets~~
* ~~Building the forwarding table via a dynamic routing protocol (PWOSPF)~~
* ~~Support static routing table entries in addition to the routes computed by PWOSPF~~
* ~~Handling all packets addressed directly to the router~~

# Initial tests:
* ~~Is your router forwarding correctly with statically configured table entries?~~
* ~~Can you ping each of the router's interfaces?~~
* ~~Is the router responding to ARP requests?~~

# Running

First, make sure you have p4app (which requires Docker):

    cd ~/
    git clone --branch rc-2.0.0 https://github.com/p4lang/p4app.git

Then run this p4app:

    ~/p4app/p4app run router.p4app
