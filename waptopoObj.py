from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import Controller, RemoteController, OVSKernelSwitch, UserSwitch, Controller
from mininet.link import Link, TCLink






class LinuxRouter(Node):
    "A node which connects to the Linux router"
    def config(self,**params):
        super(LinuxRouter,self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')
        
    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter,self).terminate()
        
    
class NetworkTopo(Topo):
    def build(self,**_opts):
        #add the two routers here
        r1 = self.addHost('r1',cls=LinuxRouter, ip='10.0.0.1/24')
        r2 = self.addHost('r2',cls=LinuxRouter, ip='10.1.0.1/24')
        
        
        #add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        
        
        
        
        
        #add the router-switch links in the same subnet
        self.addLink(s1, r1,intfName2='r1-eth1',params2={'ip':'10.0.0.1/24'})
        self.addLink(s2, r2,intfName2='r2-eth1',params2={'ip':'10.1.0.1/24'})
        
     
        #add router-router link in a new subnet
        self.addLink(r1,r2,intfName1='r1-eth2',intfName2='r2-eth2',params1={'ip':'10.100.0.1/24'},params2={'ip':'10.100.0.2/24'})
        
        #add hosts specifying the default route
        h1 = self.addHost(name='h1',ip='10.0.0.251/24',defaultRoute='via 10.0.0.1')        
        h2 = self.addHost(name='h2',ip='10.1.0.252/24',defaultRoute='via 10.1.0.1')
        
        
        #add host switch links
        self.addLink(h1,s1)
        self.addLink(h2,s2)

        
       

def run():
    topo = NetworkTopo()
   
    
    net = Mininet(topo=topo,controller=RemoteController, link=TCLink, switch=OVSKernelSwitch )
    # c0 = net( 'c0', controller=RemoteController, ip='127.0.0.1', port=6633 ) 
    # c0.start()
    
    #add routing form reaching networks that arent directly connected
    info(net['r1'].cmd("ip route add 10.1.0.0/24 via 10.100.0.2 dev r1-eth2"))
    info(net['r2'].cmd("ip route add 10.0.0.0/24 via 10.100.0.1 dev r2-eth2"))
    
    net.start()
    CLI(net)
    net.stop()
        
        
if __name__ == '__main__':
    setLogLevel('info')
    run()