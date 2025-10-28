import time
from mininet.net import Mininet
from mininet.node import Controller, Node
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info

def create_topology():
    net = Mininet(link=TCLink)
    
    info('Adding controller\n')
    net.addController('c0')
    
    info('Adding switches\n')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')

    info('Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')
    dns_host = net.addHost('dns', ip='10.0.0.5/24')

    info('Adding links\n')
    net.addLink(h1, s1, bw=100, delay='2ms')
    net.addLink(h2, s2, bw=100, delay='2ms')
    net.addLink(h3, s3, bw=100, delay='2ms')
    net.addLink(h4, s4, bw=100, delay='2ms')
    net.addLink(s1, s2, bw=100, delay='5ms')
    net.addLink(s2, s3, bw=100, delay='8ms')
    net.addLink(s3, s4, bw=100, delay='10ms')
    net.addLink(s2, dns_host, bw=100, delay='1ms')

    nat = net.addNAT()
    net.addLink(nat, s2)

    info('Starting network\n')
    net.start()
    nat.configDefault()

    nat.cmd('ifconfig nat-eth0 10.0.0.6/24')

    # Forwards DNS packets through NAT
    nat.cmd('iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE')
    nat.cmd('iptables -A FORWARD -i nat-eth0 -o eth0 -j ACCEPT')
    nat.cmd('iptables -A FORWARD -i eth0 -o nat-eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT')

    for h in [h1, h2, h3, h4, dns_host]:
        h.cmd("echo 'nameserver 10.0.0.5' > /etc/resolv.conf")

    for h in [h1, h2, h3, h4, dns_host]:
        h.cmd("ip route add default via 10.0.0.6")

    net.pingAll()

    return net

if __name__ == '__main__':
    setLogLevel('info')
    net = create_topology()
    CLI(net)
    net.stop()
