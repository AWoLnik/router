from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP, Raw
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from pwospf import PWOSPF, Hello, LSU, LSUad, OSPF_PROT_NUM
import time
from collections import defaultdict

ICMP_PROT_NUM = 0x01
OSPF_PROT_NUM = 0x59

HELLO_TYPE = 0x01
LSU_TYPE   = 0x04

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
ARP_TIMEOUT = 30

ICMP_ECHO_REPLY_TYPE = 0x00
ICMP_ECHO_REPLY_CODE = 0x00

ICMP_HOST_UNREACHABLE_TYPE = 0x03
ICMP_HOST_UNREACHABLE_CODE = 0x01

PWOSPF_HELLO_DEST = '224.0.0.5'

class Interface():
    def __init__(self, addr, mask, helloint, port):
        self.addr = addr
        self.mask = mask
        self.helloint = helloint
        self.port = port
        self.neighbors = []
        self.neighbor_times = {}

    def addNeighbor(self, routerID, intfIP):
        self.neighbors.append((routerID, intfIP))

    def removeNeighbor(self, routerID, intfIP):
        self.neighbors.remove((routerID, intfIP))
        self.neighbor_times.pop((routerID, intfIP))

    def hasNeighbor(self, routerID, intfIP):
        return (routerID, intfIP) in self.neighbors

    def hasNeighborIP(self, routerID):
        for n in self.neighbors:
            if n[0] == routerID:
                return True
        return False

    def getNeighborUpdateTime(self, routerID, intfIP):
        return self.neighbor_times.setdefault((routerID, intfIP), 0)

    def setNeighborUpdateTime(self, routerID, intfIP, updateTime):
        self.neighbor_times[(routerID, intfIP)] = updateTime

class ARPManager(Thread):
    def __init__(self, cntrl):
        super(ARPManager, self).__init__()
        self.cntrl = cntrl

    def run(self):
        for i in range(15): #while True:
            time.sleep(1)

            # Remove timed-out entries in ARP cache
            now = time.time()
            for ip in self.cntrl.mac_for_ip_times:
                then = self.cntrl.mac_for_ip_times[ip]
                if (now - then) > ARP_TIMEOUT:
                    print("Removing ARP cache entry for " + ip) # API doesn't support removing table entries

class HelloManager(Thread):
    def __init__(self, cntrl, intf):
        super(HelloManager, self).__init__()
        self.cntrl = cntrl
        self.intf = intf

    def run(self):
        for i in range(300): #while True:
            # Send Hello packet
            if self.intf.port > 1:
                pkt = Ether()/CPUMetadata()/IP()/PWOSPF()/Hello()
                pkt[Ether].src = self.cntrl.MAC
                pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
                pkt[CPUMetadata].fromCpu = 1
                pkt[CPUMetadata].origEtherType = 0x0800
                pkt[CPUMetadata].srcPort = 1
                pkt[CPUMetadata].dstPort = self.intf.port
                pkt[IP].src = self.intf.addr
                pkt[IP].dst = "224.0.0.5"
                pkt[IP].proto = OSPF_PROT_NUM
                pkt[PWOSPF].version = 2
                pkt[PWOSPF].type = HELLO_TYPE
                pkt[PWOSPF].length = 0
                pkt[PWOSPF].routerID = self.cntrl.routerID
                pkt[PWOSPF].areaID = self.cntrl.areaID
                pkt[PWOSPF].checksum = 0
                pkt[Hello].netmask = self.intf.mask
                pkt[Hello].helloint = self.intf.helloint

                # pkt.show2()
                self.cntrl.send(pkt)

            # Remove timed-out neighbors
            now = time.time()
            for n in self.intf.neighbors:
                then = self.intf.getNeighborUpdateTime(n[0], n[1])
                if (now - then) > (self.intf.helloint * 3):
                    self.intf.removeNeighbor(n[0], n[1])

            time.sleep(self.intf.helloint)

class LSUManager(Thread):
    def __init__(self, cntrl, lsuint):
        super(LSUManager, self).__init__()
        self.lsuint = lsuint
        self.cntrl = cntrl

    def run(self):
        for i in range(300): #while True:
            # Create LSUads for each neighbor
            adList = []
            for i in self.cntrl.intfs:
                for n in i.neighbors:
                    pkt = LSUad()
                    pkt[LSUad].subnet = i.addr
                    pkt[LSUad].mask = i.mask
                    pkt[LSUad].routerID = n[0]
                    adList.append(pkt)

            # Send LSU packet
            pkt = Ether()/CPUMetadata()/IP()/PWOSPF()/LSU()
            pkt[Ether].src = self.cntrl.MAC
            pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
            pkt[CPUMetadata].fromCpu = 1
            pkt[CPUMetadata].origEtherType = 0x0800
            pkt[CPUMetadata].srcPort = 1
            # pkt[CPUMetadata].dstPort gets set by floodLSUPkt()
            pkt[IP].src = self.cntrl.routerID
            # pkt[IP].dst gets set by floodLSUPkt()
            pkt[IP].proto = OSPF_PROT_NUM
            pkt[PWOSPF].version = 2
            pkt[PWOSPF].type = LSU_TYPE
            pkt[PWOSPF].length = 0
            pkt[PWOSPF].routerID = self.cntrl.routerID
            pkt[PWOSPF].areaID = self.cntrl.areaID
            pkt[PWOSPF].checksum = 0
            pkt[LSU].sequence = self.cntrl.lsu_seq
            pkt[LSU].ttl = 64
            pkt[LSU].numAds = len(adList)
            pkt[LSU].adList = adList

            self.cntrl.lsu_seq = self.cntrl.lsu_seq + 1
            self.cntrl.floodLSUPkt(pkt)

            time.sleep(self.lsuint)

class RouterController(Thread):
    def __init__(self, sw, routerID, MAC, areaID, lsuint=2, start_wait=0.3):
        super(RouterController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listening
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.mac_for_ip = {}
        self.mac_for_ip_times = {}
        self.port_for_ip = {}
        self.stop_event = Event()
        self.MAC = MAC

        # PWOSPF state
        self.routerID = routerID
        self.areaID = areaID
        self.lsu_seq = 0
        self.last_pkts = {} # dictionary storing last LSU pkt received from every router
        self.adj_list = {} # dictionary of lists for each router, list entries are (routerID, subnet, mask) tuples

        # TODO: MY ROUTER INTERFACES MUST BE STATICALLY CONFIGURED HERE
        intfs_init = [('10.0.2.0','255.255.255.0',4,1),
                      ('10.0.2.1','255.255.255.0',4,2),
                      ('10.0.2.2','255.255.255.0',4,3),
                      ('10.0.2.3','255.255.255.0',4,4),
                      ('10.0.2.4','255.255.255.0',4,5)]
        assert len(intfs_init) == len(sw.intfs) - 1, "Length of intfs does not match number of switch interfaces"

        self.intfs = []
        for i in range(len(intfs_init)):
            # intfs arg should be a list of (addr, mask, helloint, port) tuples
            self.intfs.append(Interface(intfs_init[i][0], intfs_init[i][1], intfs_init[i][2], intfs_init[i][3]))

        self.intf_ips = set()
        for i in self.intfs:
            self.intf_ips.add(i.addr)

        # PWOSPF hack due to not being able to remove or modify routing table entries in current API
        # Allows waiting for LSUs to be received from every router
        self.lsu_wait = lsuint * 3
        self.lsu_init_time = time.time()
        self.dijkstra_flag = 0

        # timing threads
        self.arp_mngr = ARPManager(cntrl=self)
        self.lsu_mngr = LSUManager(cntrl=self, lsuint=lsuint)

        self.hello_mngrs = []
        for i in self.intfs:
            self.hello_mngrs.append(HelloManager(cntrl=self, intf=i))

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': mac},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port

    def addIPAddr(self, ip, mac):
        # Don't re-add the ip-mac mapping if we already have it:
        if ip in self.mac_for_ip: return

        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'next_hop_ip_addr': ip},
                action_name='MyIngress.arp_match',
                action_params={'dstAddr': mac})
        self.mac_for_ip[ip] = mac
        self.mac_for_ip_times[ip] = time.time()

    def handleArpReply(self, pkt):
        # add replies from hosts to cache
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIPAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.send(pkt)

    def handleArpRequest(self, pkt):
        # add requests from hosts to cache
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIPAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)

        # respond to requests addressed to any router interface
        if pkt[ARP].pdst in self.intf_ips:
            dstIP = pkt[ARP].pdst
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = self.MAC
            pkt[ARP].op = 2 # reply
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].hwsrc = self.MAC
            pkt[ARP].psrc = dstIP

        self.send(pkt)

    def handleICMPEchoRequest(self, pkt):
        respPkt = Ether()/CPUMetadata()/IP()/ICMP()
        respPkt[CPUMetadata].fromCpu = 1
        respPkt[CPUMetadata].origEtherType = 0x0800
        respPkt[CPUMetadata].srcPort = 1
        respPkt[CPUMetadata].dstPort = 0
        respPkt[IP].src = pkt[IP].dst
        respPkt[IP].dst = pkt[IP].src
        respPkt[IP].proto = ICMP_PROT_NUM
        respPkt[ICMP].type = ICMP_ECHO_REPLY_TYPE
        respPkt[ICMP].code = ICMP_ECHO_REPLY_CODE
        respPkt[ICMP].id = pkt[ICMP].id
        respPkt[ICMP].seq = pkt[ICMP].seq
        self.send(respPkt)

    def respondICMPHostUnreachable(self, pkt):
        respPkt = Ether()/CPUMetadata()/IP()/ICMP()
        respPkt[CPUMetadata].fromCpu = 1
        respPkt[CPUMetadata].origEtherType = 0x0800
        respPkt[CPUMetadata].srcPort = 1
        respPkt[CPUMetadata].dstPort = 0
        respPkt[IP].src = pkt[IP].dst
        respPkt[IP].dst = pkt[IP].src
        respPkt[IP].proto = ICMP_PROT_NUM
        respPkt[ICMP].type = ICMP_HOST_UNREACHABLE_TYPE
        respPkt[ICMP].code = ICMP_HOST_UNREACHABLE_CODE
        self.send(respPkt)

    # Returns dictionary of shortest path parents
    def dijkstra(self, adj_list, source):
        visited = {source: 0}
        path = defaultdict(lambda: "Not Present")

        nodes = set()
        for r in adj_list:
            nodes.add(r)

        while nodes:
            min_node = None
            for n in nodes:
                if n in visited:
                    if (min_node is None) or (visited[n] < visited[min_node]):
                        min_node = n

            if min_node is None:
                break

            nodes.remove(min_node)
            current_dist = visited[min_node]

            for n in adj_list[min_node]:
                dist = current_dist + 1
                if (n[0] not in visited) or (dist < visited[n[0]]):
                    visited[n[0]] = dist
                    path[n[0]] = min_node

        return path

    # Recursively trace through parents from every host to build routing table
    def traceParent(self, parents, child, source, dest):
        if child == source:
            if dest in self.port_for_ip: return
            self.sw.insertTableEntry(table_name='MyIngress.routing_table',
                    match_fields={'hdr.ipv4.dstAddr': [dest, 32]},
                    action_name='MyIngress.send_to_cpu')
            self.port_for_ip[dest] = 1
        elif parents[child] == source:
            if dest in self.port_for_ip: return

            # Find port corresponding to neighbor
            port = 0
            for i in self.intfs:
                if i.hasNeighborIP(child):
                    port = i.port

            if port == 0: return

            destBytes = dest.split('.')
            destPrefix = destBytes[0] + '.' + destBytes[1] + '.' + destBytes[2] + '.0'

            self.sw.insertTableEntry(table_name='MyIngress.routing_table',
                    match_fields={'hdr.ipv4.dstAddr': [destPrefix, 24]},
                    action_name='MyIngress.routing_match',
                    action_params={'port': port, 'next_hop': child})
            self.port_for_ip[dest] = port
        else:
            self.traceParent(parents, parents[child], source, dest)

    def floodLSUPkt(self, pkt):
        newTTL = pkt[LSU].ttl - 1
        if newTTL > 0:
            for i in self.intfs:
                for n in i.neighbors:
                    newPkt = pkt
                    newPkt[CPUMetadata].dstPort = i.port
                    newPkt[IP].dst = n[0]
                    newPkt[LSU].ttl = newTTL
                    if newPkt[IP].dst != newPkt[IP].src:
                        self.send(newPkt)

    def linkExists(self, source, dest):
        adj_list = self.adj_list[source]
        for r in adj_list:
            if r[0] == dest:
                return True
        return False

    def handlePWOSPFpacket(self, pkt):
        if pkt[PWOSPF].version != 2: return
        # TODO: verify checksum
        if pkt[PWOSPF].areaID != self.areaID: return
        if pkt[PWOSPF].auType != 0: return
        if pkt[PWOSPF].auth != 0: return
        routerID = pkt[PWOSPF].routerID

        if Hello in pkt:
            intf = None
            for i in self.intfs:
                if i.port == pkt[CPUMetadata].srcPort:
                    intf = i
            if pkt[Hello].netmask != intf.mask: return
            if pkt[Hello].helloint != intf.helloint: return


            intfIP = pkt[IP].src
            if intf.hasNeighbor(routerID, intfIP):
                intf.setNeighborUpdateTime(routerID, intfIP, time.time())
            else:
                intf.addNeighbor(routerID, intfIP)

        if LSU in pkt:
            if routerID == self.routerID: return

            # ignore/drop duplicate packets or packets with no new info
            # TODO: record time of last_pkts update and implement LSU timeout
            if routerID in self.last_pkts:
                last_pkt = self.last_pkts[routerID]
                if pkt[LSU].sequence == last_pkt[LSU].sequence: return
                if pkt[LSU].adList == last_pkt[LSU].adList and self.dijkstra_flag == 1:
                    self.last_pkts[routerID] = pkt
                    self.floodLSUPkt(pkt)
                    return

            self.last_pkts[routerID] = pkt

            # Update adjacency list
            # TODO: check for discrepancies before adding
            if routerID not in self.adj_list:
                self.adj_list[routerID] = []

            # pkt.show2()

            for LSUad in pkt[LSU].adList:
                linkedID = LSUad.routerID
                if linkedID not in self.adj_list:
                    self.adj_list[linkedID] = []

                if not self.linkExists(routerID, linkedID):
                    self.adj_list[routerID].append((linkedID, LSUad.subnet, LSUad.mask))
                if not self.linkExists(linkedID, routerID):
                    self.adj_list[linkedID].append((routerID, LSUad.subnet, LSUad.mask))

            if (time.time() - self.lsu_init_time) > self.lsu_wait: # wait for LSUs to propagate
                self.dijkstra_flag = 1
                parents = self.dijkstra(self.adj_list, self.routerID)

                # Build routing table from Dijkstra's algorithm output
                for r in self.adj_list:
                    self.traceParent(parents, r, self.routerID, r)

            self.floodLSUPkt(pkt)

    def handlePkt(self, pkt):
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header, from " + self.routerID

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)

        if ICMP in pkt:
            self.handleICMPEchoRequest(pkt)

        if IP in pkt:
            # CPU getting packet not addressed to router implies destination unreachable
            if (pkt[IP].dst not in self.intf_ips) and (pkt[IP].dst != PWOSPF_HELLO_DEST):
                self.respondICMPHostUnreachable(pkt)
            if pkt[IP].proto == OSPF_PROT_NUM:
                try:
                    pwospf_pkt = PWOSPF(pkt[Raw])
                except Exception:
                    print("Adam's router cannot parse this PWOSPF correctly")
                    return
                self.handlePWOSPFpacket(pkt[Ether]/pkt[CPUMetadata]/pkt[IP]/pwospf_pkt)

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        # pkt.show2()
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(RouterController, self).start(*args, **kwargs)
        self.arp_mngr.start()
        self.lsu_mngr.start()
        for i in self.hello_mngrs:
            i.start()
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        # print("Printing Adam's adjacency list:")
        # for r in self.adj_list:
        #     print(r)
        #     print(self.adj_list[r])
        # print('')
        super(RouterController, self).join(*args, **kwargs)
