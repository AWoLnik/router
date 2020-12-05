from p4app import P4Mininet
from my_topo import SingleSwitchTopo, TriangleSwitchesTopo, SquareSwitchesTopo
from controller import RouterController
import time

topo = SquareSwitchesTopo()
net = P4Mininet(program='router.p4', topo=topo, auto_arp=False)
net.start()

sw1, r1, h1 = net.get('s1'), net.get('cpu1'), net.get('h1')
sw2, r2, h2 = net.get('s2'), net.get('cpu2'), net.get('h2')
sw3, r3, h3 = net.get('s3'), net.get('cpu3'), net.get('h3')
sw4, r4, h4 = net.get('s4'), net.get('cpu4'), net.get('h4')

# Define interfaces
s1_intfs = [('100.0.1.1','255.255.255.0',3,1),
            ('100.0.1.2','255.255.255.0',3,2),
            ('100.0.1.3','255.255.255.0',3,3),
            ('100.0.1.4','255.255.255.0',3,4),
            ('100.0.1.5','255.255.255.0',3,5)]
s2_intfs = [('100.0.2.1','255.255.255.0',3,1),
            ('100.0.2.2','255.255.255.0',3,2),
            ('100.0.2.3','255.255.255.0',3,3),
            ('100.0.2.4','255.255.255.0',3,4)]
s3_intfs = [('100.0.3.1','255.255.255.0',3,1),
            ('100.0.3.2','255.255.255.0',3,2),
            ('100.0.3.3','255.255.255.0',3,3),
            ('100.0.3.4','255.255.255.0',3,4),
            ('100.0.3.5','255.255.255.0',3,5)]
s4_intfs = [('100.0.4.1','255.255.255.0',3,1),
            ('100.0.4.2','255.255.255.0',3,2),
            ('100.0.4.3','255.255.255.0',3,3),
            ('100.0.4.4','255.255.255.0',3,4)]

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
sw1.addMulticastGroup(mgid=bcast_mgid, ports=range(2, 6))
sw2.addMulticastGroup(mgid=bcast_mgid, ports=range(2, 5))
sw3.addMulticastGroup(mgid=bcast_mgid, ports=range(2, 6))
sw4.addMulticastGroup(mgid=bcast_mgid, ports=range(2, 5))

# Send MAC bcast packets to the bcast multicast group
sw1.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})
sw2.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})
sw3.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})
sw4.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})

# Set interface IPs in local IP tables
sw1.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.1.1'},
        action_name='MyIngress.send_to_cpu')
sw1.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.1.2'},
        action_name='MyIngress.send_to_cpu')
sw1.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.1.3'},
        action_name='MyIngress.send_to_cpu')
sw1.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.1.4'},
        action_name='MyIngress.send_to_cpu')
sw1.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.1.5'},
        action_name='MyIngress.send_to_cpu')
sw2.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.2.1'},
        action_name='MyIngress.send_to_cpu')
sw2.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.2.2'},
        action_name='MyIngress.send_to_cpu')
sw2.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.2.3'},
        action_name='MyIngress.send_to_cpu')
sw2.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.2.4'},
        action_name='MyIngress.send_to_cpu')
sw3.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.3.1'},
        action_name='MyIngress.send_to_cpu')
sw3.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.3.2'},
        action_name='MyIngress.send_to_cpu')
sw3.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.3.3'},
        action_name='MyIngress.send_to_cpu')
sw3.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.3.4'},
        action_name='MyIngress.send_to_cpu')
sw3.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.3.5'},
        action_name='MyIngress.send_to_cpu')
sw4.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.4.1'},
        action_name='MyIngress.send_to_cpu')
sw4.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.4.2'},
        action_name='MyIngress.send_to_cpu')
sw4.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.4.3'},
        action_name='MyIngress.send_to_cpu')
sw4.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.4.4'},
        action_name='MyIngress.send_to_cpu')

# Set attached host IPs in local IP tables
sw1.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.1.10'},
        action_name='MyIngress.routing_match',
        action_params={'port': 4, 'next_hop': '100.0.1.10'})
sw2.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.2.10'},
        action_name='MyIngress.routing_match',
        action_params={'port': 4, 'next_hop': '100.0.2.10'})
sw3.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.3.10'},
        action_name='MyIngress.routing_match',
        action_params={'port': 4, 'next_hop': '100.0.3.10'})
sw4.insertTableEntry(table_name='MyIngress.local_ip_table',
        match_fields={'hdr.ipv4.dstAddr': '100.0.4.10'},
        action_name='MyIngress.routing_match',
        action_params={'port': 4, 'next_hop': '100.0.4.10'})

print('Booting routers...\n')

# Start the controllers
cpu1 = RouterController(sw1, r1.IP(), r1.MAC(), 1, s1_intfs)
cpu2 = RouterController(sw2, r2.IP(), r2.MAC(), 1, s2_intfs)
cpu3 = RouterController(sw3, r3.IP(), r3.MAC(), 1, s3_intfs)
cpu4 = RouterController(sw4, r4.IP(), r4.MAC(), 1, s4_intfs)
cpu1.start()
cpu2.start()
cpu3.start()
cpu4.start()

print('Waiting for PWOSPF setup...\n')

time.sleep(10) # allow time for PWOSPF to settle

print('Pinging all interfaces of router 100.0.2.1 from host 100.0.2.10:\n')
print(h2.cmd('ping -c1 100.0.2.1'))
print(h2.cmd('ping -c1 100.0.2.2'))
print(h2.cmd('ping -c1 100.0.2.3'))
print(h2.cmd('ping -c1 100.0.2.4'))

print('Pinging host 100.0.3.10 from host 100.0.1.10:\n')
print(h1.cmd('ping -c1 100.0.3.10'))

print('Reading counters from router 100.0.1.1:\n')
print('IP packets: ' + str(sw1.readCounter('switch_ip_packets', 1)[0]))
print('ARP packets: ' + str(sw1.readCounter('switch_arp_packets', 1)[0]))
print('CPU packets: ' + str(sw1.readCounter('switch_cpu_packets', 1)[0]))
print('')

# These table entries were added by the CPU:
sw1.printTableEntries()
sw2.printTableEntries()
sw3.printTableEntries()
sw4.printTableEntries()

# print('Printing adjacency list from ' + cpu1.routerID)
# for r in cpu1.adj_list:
#         print(r)
#         print(cpu1.adj_list[r])