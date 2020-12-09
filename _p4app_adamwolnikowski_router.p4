/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const macAddr_t BROADCAST_ADDR  = 0xffffffffffff;
const mcastGrp_t BROADCAST_MGID = 0x0001;

const ip4Addr_t ALLSPFROUTERS_ADDR = 0xe0000005;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x081d;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8>  fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
    bit<16> dstPort;
}

header arp_t {
    bit<16>   hwType;
    bit<16>   protoType;
    bit<8>    hwAddrLen;
    bit<8>    protoAddrLen;
    bit<16>   opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
}

struct metadata { }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // TODO: verify checksum
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /***** COUNTERS *****/

    counter(5, CounterType.packets) switch_ip_packets;
    counter(5, CounterType.packets) switch_arp_packets;
    counter(5, CounterType.packets) switch_cpu_packets;

    /***** STATE *****/

    ip4Addr_t next_hop_ip_addr = 0;
    macAddr_t next_hop_mac_addr = 0;
    port_t dstPort = 0;

    /***** UTILS *****/

    action drop() {
        mark_to_drop();
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        dstPort = (bit<9>)hdr.cpu_metadata.dstPort;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    /***** LAYER 3 *****/

    action routing_match(port_t port, ip4Addr_t next_hop) {
        standard_metadata.egress_spec = port;
        next_hop_ip_addr = next_hop;
    }

    table routing_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            routing_match;
            send_to_cpu;
        }
        size = 64;
        default_action = send_to_cpu();
    }

    table local_ip_table {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            routing_match;
            send_to_cpu;
        }
        size = 64;
    }

    /***** LAYER 2 *****/

    action set_eth_addrs() {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = next_hop_mac_addr;
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action arp_match(macAddr_t dstAddr) {
        next_hop_mac_addr = dstAddr;
    }

    table arp_table {
        key = {
            next_hop_ip_addr: exact;
        }
        actions = {
            arp_match;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 64;
        default_action = drop();
    }

    apply {
        if (standard_metadata.ingress_port == CPU_PORT)
            cpu_meta_decap();

        if (hdr.arp.isValid())
            switch_arp_packets.count((bit<32>) 1);

        if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu();
        } else if (dstPort != 0 && standard_metadata.ingress_port == CPU_PORT) { // For packets routed in control plane (e.g. PWOSPF)
            standard_metadata.egress_spec = dstPort;
        } else if (hdr.ipv4.isValid()) {
            switch_ip_packets.count((bit<32>) 1);

            if (hdr.ipv4.ttl <= 1) {
                drop();
                // TODO: send ICMP time exceeded response
            } else {
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            }

            if(!local_ip_table.apply().hit) { // avoid calling send_to_cpu() twice
                routing_table.apply();
            }

            if(standard_metadata.egress_spec != CPU_PORT) {
                arp_table.apply();
                set_eth_addrs();
            }
        } else if (hdr.ethernet.isValid()) {
            fwd_l2.apply();
        } else {
            send_to_cpu();
        }

        if(standard_metadata.egress_spec == CPU_PORT)
            switch_cpu_packets.count((bit<32>) 1);
    }
}




/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
