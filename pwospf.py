from scapy.fields import ByteField, ShortField, IntField, LongField, IPField, FieldLenField, PacketListField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP

OSPF_PROT_NUM = 0x59

HELLO_TYPE = 0x01
LSU_TYPE   = 0x04

class PWOSPF(Packet):
    name = "PWOSPF"
    fields_desc = [ ByteField("version", None),
                    ByteField("type", None),
                    ShortField("length", None),
                    IPField("routerID", None),
                    IntField("areaID", None),
                    ShortField("checksum", None),
                    ShortField("auType", 0),
                    LongField("auth", 0)]

class Hello(Packet):
    name = "Hello"
    fields_desc = [ IPField("netmask", None),
                    ShortField("helloint", None),
                    ShortField("padding", 0)]

class LSUad(Packet):
    name = "LSUad"
    fields_desc = [ IPField("subnet", None),
                    IPField("mask", None),
                    IPField("routerID", None)]

    def extract_padding(self, s):
        return '', s

class LSU(Packet):
    name = "LSU"
    fields_desc = [ ShortField("sequence", None),
                    ShortField("ttl", None),
                    FieldLenField("numAds", None, fmt="I", count_of="adList"),
                    PacketListField("adList", None, LSUad, count_from= lambda pkt: pkt.numAds)]

bind_layers(IP, PWOSPF, proto=OSPF_PROT_NUM)
bind_layers(PWOSPF, Hello, type=HELLO_TYPE)
bind_layers(PWOSPF, LSU, type=LSU_TYPE)