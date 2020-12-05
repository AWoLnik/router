from mininet.topo import Topo

class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1')

        for i in xrange(1, n+1):
            host = self.addHost('h%d' % i,
                                ip = "100.0.0.%d" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            self.addLink(host, switch, port2=i)

class TriangleSwitchesTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        # Set up 3 routers
        s1 = self.addSwitch('s1')
        cpu1 = self.addHost('cpu1', ip='100.0.0.1', mac='00:00:00:00:00:01')
        self.addLink(cpu1, s1, port2=1)

        s2 = self.addSwitch('s2')
        cpu2 = self.addHost('cpu2', ip='100.0.0.4', mac='00:00:00:00:00:04')
        self.addLink(cpu2, s2, port2=1)

        s3 = self.addSwitch('s3')
        cpu3 = self.addHost('cpu3', ip='100.0.0.7', mac='00:00:00:00:00:07')
        self.addLink(cpu3, s3, port2=1)

        # Connect routers in triangle
        self.addLink(s1, s2, port1=2, port2=2)
        self.addLink(s2, s3, port1=3, port2=2)
        self.addLink(s3, s1, port1=3, port2=3)

        # hosts
        h1 = self.addHost('h1', ip='100.0.0.100', mac='00:00:00:00:00:64')
        self.addLink(h1, s1, port2=4)

# SquareSwitchesTopo visualization:
#
# (h2)--(r2)-----(r3)--(h3)
#         |     / |
#         |    /  |
#         |   /   |
#         |  /    |
#         | /     |
# (h1)--(r1)-----(r4)--(h4)

class SquareSwitchesTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        # Set up 4 routers
        s1 = self.addSwitch('s1')
        cpu1 = self.addHost('cpu1', ip='100.0.1.1')
        self.addLink(cpu1, s1, port2=1)

        s2 = self.addSwitch('s2')
        cpu2 = self.addHost('cpu2', ip='100.0.2.1')
        self.addLink(cpu2, s2, port2=1)

        s3 = self.addSwitch('s3')
        cpu3 = self.addHost('cpu3', ip='100.0.3.1')
        self.addLink(cpu3, s3, port2=1)

        s4 = self.addSwitch('s4')
        cpu4 = self.addHost('cpu4', ip='100.0.4.1')
        self.addLink(cpu4, s4, port2=1)

        # Connect routers in square with 1-3 diagonal connection
        self.addLink(s1, s2, port1=2, port2=2)
        self.addLink(s2, s3, port1=3, port2=2)
        self.addLink(s3, s4, port1=3, port2=2)
        self.addLink(s4, s1, port1=3, port2=3)
        self.addLink(s1, s3, port1=5, port2=5)

        # Add host at each router
        h1 = self.addHost('h1', ip='100.0.1.10')
        self.addLink(h1, s1, port2=4)

        h2 = self.addHost('h2', ip='100.0.2.10')
        self.addLink(h2, s2, port2=4)

        h3 = self.addHost('h3', ip='100.0.3.10')
        self.addLink(h3, s3, port2=4)

        h4 = self.addHost('h4', ip='100.0.4.10')
        self.addLink(h4, s4, port2=4)
