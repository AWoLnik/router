from mininet.link import Intf
from p4_mininet import P4RuntimeSwitch
from p4_program import P4Program

from controller import RouterController

MAX_PORT = 10

class PWOSPFRouter(P4RuntimeSwitch):
    def __init__(self, *opts, **kwargs):
        self.controller = None

        prog = kwargs.get('prog')
        if prog is None:
            raise Exception('Must specify p4 program')
        prog = P4Program(prog)

        if prog.version == 14:
            sw_path = 'simple_switch'
            enable_grpc = False
        elif prog.version == 16:
            sw_path = 'simple_switch_grpc'
            enable_grpc = True
        else:
            raise Exception(
                'Switch does not support P4 version %s' % prog.version)

        self.ctrl_args = dict()
        if 'ctrl_args' in kwargs:
            self.ctrl_args = kwargs['ctrl_args']
            del kwargs['ctrl_args']

        kwargs.update({
            'enable_grpc': enable_grpc,
            'cli_path': 'simple_switch_CLI',
            'sw_path': sw_path,
            'program': prog,
            'start_controller': True,
        })

        P4RuntimeSwitch.__init__(self, *opts, **kwargs)

    def initTable(self):
        bcast_mgid = 1

        self.addMulticastGroup(mgid=bcast_mgid, ports=range(2,MAX_PORT))
        self.insertTableEntry(table_name='MyIngress.fwd_l2',
                              match_fields={'hdr.ethernet.dstAddr': [
                                  "ff:ff:ff:ff:ff:ff"]},
                              action_name='MyIngress.set_mgid',
                              action_params={'mgid': bcast_mgid})

        # TODO: MY ROUTER INTERFACES AND ATTACHED HOSTS MUST BE STATICALLY CONFIGURED HERE

        # Set interface IPs in local IP tables
        self.insertTableEntry(table_name='MyIngress.local_ip_table',
                match_fields={'hdr.ipv4.dstAddr': '10.0.2.0'},
                action_name='MyIngress.send_to_cpu')
        self.insertTableEntry(table_name='MyIngress.local_ip_table',
                match_fields={'hdr.ipv4.dstAddr': '10.0.2.1'},
                action_name='MyIngress.send_to_cpu')
        self.insertTableEntry(table_name='MyIngress.local_ip_table',
                match_fields={'hdr.ipv4.dstAddr': '10.0.2.2'},
                action_name='MyIngress.send_to_cpu')
        self.insertTableEntry(table_name='MyIngress.local_ip_table',
                match_fields={'hdr.ipv4.dstAddr': '10.0.2.3'},
                action_name='MyIngress.send_to_cpu')
        self.insertTableEntry(table_name='MyIngress.local_ip_table',
                match_fields={'hdr.ipv4.dstAddr': '10.0.2.4'},
                action_name='MyIngress.send_to_cpu')

        # Set attached host IPs in local IP tables
        self.insertTableEntry(table_name='MyIngress.local_ip_table',
                match_fields={'hdr.ipv4.dstAddr': '10.0.2.10'},
                action_name='MyIngress.routing_match',
                action_params={'port': 2, 'next_hop': '10.0.2.10'})
        self.insertTableEntry(table_name='MyIngress.local_ip_table',
            match_fields={'hdr.ipv4.dstAddr': '10.0.2.11'},
            action_name='MyIngress.routing_match',
            action_params={'port': 3, 'next_hop': '10.0.2.11'})

    def start(self, controllers):
        super(PWOSPFRouter, self).start(controllers)
        self.initTable()
        self.controller = RouterController(self, **self.ctrl_args)
        self.controller.start()

    def stop(self):
        if self.controller is not None:
            self.controller.join()
        super(PWOSPFRouter, self).stop()