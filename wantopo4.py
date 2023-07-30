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
        self.cmd('sysctl net.ipv4.ip_forward=1')
        super(LinuxRouter,self).config(**params)
        self.ENABLE_LEFT_TO_RIGHT_ROUTING = 1
        
        
        
    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter,self).terminate()
        
    
class NetworkTopo(Topo):
    def build(self,**_opts):
        #add the two routers here
        r1 = self.addHost('r1',cls=LinuxRouter, ip='192.168.0.1/29')
        r2 = self.addHost('r2',cls=LinuxRouter, ip='172.16.0.1/29')
        r3 = self.addHost('r3',cls=LinuxRouter, ip='10.0.0.1/29')
        # r1.cmd('sysctl net.ipv4.ip_forward=1')
        # r2.cmd('sysctl net.ipv4.ip_forward=1')
        # r3.cmd('sysctl net.ipv4.ip_forward=1')
        
        
        #add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')       
        

        
        #add the router-switch links in the same subnet
        self.addLink(s1, r1,intfName2='r1-eth1', params2={'ip':'192.168.0.1/29'})
        self.addLink(s2, r2,intfName2='r2-eth1', params2={'ip':'172.16.0.1/29'})
        self.addLink(s3, r3,intfName2='r3-eth1', params2={'ip':'10.0.0.1/29'})
        
        
        
        
     
        #add router-router link in a new subnet
        self.addLink(r1,r2,intfName1='r1-eth2',intfName2='r2-eth2',params1={'ip':'10.100.0.1/24'},params2={'ip':'10.100.0.2/24'})
        self.addLink(r2,r3,intfName1='r2-eth3',intfName2='r3-eth2',params1={'ip':'10.100.0.3/24'},params2={'ip':'10.100.0.4/24'})
        self.addLink(r3,r1,intfName1='r3-eth3',intfName2='r1-eth3',params1={'ip':'10.100.0.5/24'},params2={'ip':'10.100.0.6/24'})
        

        
        #add hosts specifying the default route
        h1 = self.addHost(name='h1',ip='192.168.0.2/29',defaultRoute='via 192.168.0.1')  
        h2 = self.addHost(name='h2',ip='192.168.0.3/29',defaultRoute='via 192.168.0.1')
        h3 = self.addHost(name='h3',ip='192.168.0.4/29',defaultRoute='via 192.168.0.1')  
        h4 = self.addHost(name='h4',ip='192.168.0.5/29',defaultRoute='via 192.168.0.1')  
        
        
        
        h5 = self.addHost(name='h5',ip='172.16.0.2/29',defaultRoute='via 172.16.0.1')
        h6 = self.addHost(name='h6',ip='172.16.0.3/29',defaultRoute='via 172.16.0.1')
        h7 = self.addHost(name='h7',ip='172.16.0.4/29',defaultRoute='via 172.16.0.1')
        h8 = self.addHost(name='h8',ip='172.16.0.5/29',defaultRoute='via 172.16.0.1')
        
        
        h9 =  self.addHost(name='h9', ip='10.0.0.2/29', defaultRoute='via 10.0.0.1')
        h10 = self.addHost(name='h10',ip='10.0.0.3/29',defaultRoute='via 10.0.0.1')
        h11 = self.addHost(name='h11',ip='10.0.0.4/29',defaultRoute='via 10.0.0.1')
        h12 = self.addHost(name='h12',ip='10.0.0.5/29',defaultRoute='via 10.0.0.1')
        

        
        
        #add host switch links
        self.addLink(h1,s1)
        self.addLink(h2,s1)
        self.addLink(h3,s1)
        self.addLink(h4,s1)
        
        self.addLink(h5,s2)
        self.addLink(h6,s2)
        self.addLink(h7,s2)
        self.addLink(h8,s2)
        
        self.addLink(h9,s3)
        self.addLink(h10,s3)
        self.addLink(h11,s3)
        self.addLink(h12,s3)
       



def run():
    topo = NetworkTopo()  
    
    net = Mininet(topo=topo,controller=RemoteController, link=TCLink, switch=OVSKernelSwitch ) 
    
    #static routing
    info(net['r1'].cmd("ip route add 172.16.0.0/29 via 10.100.0.2 dev r1-eth2")) #r1 to r2
    info(net['r2'].cmd("ip route add 192.168.0.0/29 via 10.100.0.1 dev r2-eth2")) #r2 to r1

    info(net['r2'].cmd("ip route add 10.0.0.0/29 via 10.100.0.4 dev r2-eth3"))  #r2 to r3
    info(net['r3'].cmd("ip route add 172.16.0.0/29 via 10.100.0.3 dev r3-eth2"))  #r3 to r2
    
    info(net['r1'].cmd("ip route add 10.0.0.0/29 via 10.100.0.5 dev r1-eth3"))  #r1 to r3    
    info(net['r3'].cmd("ip route add 192.168.0.0/29  via 10.100.0.6 dev r3-eth3"))  #r3 to r1        
    
    info(net['r1'].cmd("ip route add 172.16.0.1 via 10.100.0.2 dev r1-eth2"))
    info(net['r3'].cmd("ip route add 192.168.0.1  via 10.100.0.6 dev r3-eth3"))
    
    
    
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()