from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, UserSwitch, Controller
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, TCLink

 

def topology():
        net = Mininet( controller=RemoteController, link=TCLink, switch=OVSKernelSwitch )

        # Add hosts and switches

        h1 = net.addHost( 'h1', ip="192.168.10.2/24", mac="00:00:00:00:00:01")
        h2 = net.addHost( 'h2', ip="192.168.10.3/24", mac="00:00:00:00:00:02")
        h3 = net.addHost( 'h3', ip="192.168.10.4/24", mac="00:00:00:00:00:03")
        h4 = net.addHost( 'h4', ip="192.168.10.5/24", mac="00:00:00:00:00:04")

        h5 = net.addHost( 'h5', ip="172.16.10.2/24", mac="00:00:00:00:00:05")
        h6 = net.addHost( 'h6', ip="172.16.10.3/24", mac="00:00:00:00:00:06")
        h7 = net.addHost( 'h7', ip="172.16.10.4/24", mac="00:00:00:00:00:07")
        h8 = net.addHost( 'h8', ip="172.16.10.5/24", mac="00:00:00:00:00:08")

        h9 =  net.addHost(  'h9',  ip="10.0.3.2/24",  mac="00:00:00:00:00:10")        
        h10 = net.addHost( 'h10', ip="10.0.3.3/24",  mac="00:00:00:00:00:11")
        h11 = net.addHost( 'h11', ip="10.0.3.4/24",  mac="00:00:00:00:00:12")
        h12 = net.addHost( 'h12', ip="10.0.3.5/24",  mac="00:00:00:00:00:13")
       

        r1 = net.addHost( 'r1')
        s1 = net.addSwitch( 's1')
        s2 = net.addSwitch( 's2')
        s3 = net.addSwitch( 's3')  
        c0 = net.addController( 'c0', controller=RemoteController, ip='127.0.0.1', port=6633 ) 

        net.addLink( r1, s1, bw =0.5)
        net.addLink( r1, s2, bw =0.5)
        net.addLink( r1, s3, bw =0.5)

        net.addLink( h1, s1)
        net.addLink( h2, s1)
        net.addLink( h3, s1)
        net.addLink( h4, s1)

        net.addLink( h5, s2 )
        net.addLink( h6, s2 )
        net.addLink( h7, s2 )
        net.addLink( h8, s2 )

        net.addLink( h9,  s3 )
        net.addLink( h10, s3 )
        net.addLink( h11, s3 )
        net.addLink( h12, s3 )



        net.build()
        c0.start()

        s1.start( [c0] )
        s2.start( [c0] )
        s3.start( [c0] )


        


        

        r1.cmd("ifconfig r1-eth0 0")
        r1.cmd("ifconfig r1-eth1 0")
        r1.cmd("ifconfig r1-eth2 0")
        

        r1.cmd("ifconfig r1-eth0 hw ether 00:00:00:00:01:01")
        r1.cmd("ifconfig r1-eth1 hw ether 00:00:00:00:01:02")
        r1.cmd("ifconfig r1-eth2 hw ether 00:00:00:00:01:03")

        r1.cmd("ip addr add 192.168.10.1/24 brd + dev r1-eth0")
        r1.cmd("ip addr add 172.16.10.1/24 brd + dev r1-eth1")
        r1.cmd("ip addr add 10.0.3.1/24 brd + dev r1-eth2")

        r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        h1.cmd("ip route add default via 192.168.10.1")
        h2.cmd("ip route add default via 192.168.10.1")
        h3.cmd("ip route add default via 192.168.10.1")
        h4.cmd("ip route add default via 192.168.10.1")

        h5.cmd("ip route add default via 172.16.10.1")
        h6.cmd("ip route add default via 172.16.10.1")
        h7.cmd("ip route add default via 172.16.10.1")
        h8.cmd("ip route add default via 172.16.10.1")

        h9.cmd("ip route add default via 10.0.3.1")
        h10.cmd("ip route add default via 10.0.3.1")
        h11.cmd("ip route add default via 10.0.3.1")
        h12.cmd("ip route add default via 10.0.3.1")


        s1.cmd("ovs-ofctl add-flow s1 priority=1,arp,actions=flood")
        s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_dst=00:00:00:00:01:01,actions=output:1")
        s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,dl_dst=00:00:00:00:00:01,actions=output:2")
        s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,dl_dst=00:00:00:00:00:02,actions=output:3")
        s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,dl_dst=00:00:00:00:00:03,actions=output:4")
        s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,dl_dst=00:00:00:00:00:04,actions=output:5")
     

        s2.cmd("ovs-ofctl add-flow s2 priority=1,arp,actions=flood")
        s2.cmd("ovs-ofctl add-flow s2 priority=65535,ip,dl_dst=00:00:00:00:01:02,actions=output:1")
        s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,dl_dst=00:00:00:00:00:05,actions=output:2")
        s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,dl_dst=00:00:00:00:00:06,actions=output:3")
        s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,dl_dst=00:00:00:00:00:07,actions=output:4")
        s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,dl_dst=00:00:00:00:00:08,actions=output:5")


        s3.cmd("ovs-ofctl add-flow s3 priority=1,arp,actions=flood")
        s3.cmd("ovs-ofctl add-flow s3 priority=65535,ip,dl_dst=00:00:00:00:01:03,actions=output:1")
        s3.cmd("ovs-ofctl add-flow s3 priority=10,ip,dl_dst=00:00:00:00:01:09,actions=output:2")
        s3.cmd("ovs-ofctl add-flow s3 priority=10,ip,dl_dst=00:00:00:00:01:10,actions=output:3")
        s3.cmd("ovs-ofctl add-flow s3 priority=10,ip,dl_dst=00:00:00:00:01:11,actions=output:4")
        s3.cmd("ovs-ofctl add-flow s3 priority=10,ip,dl_dst=00:00:00:00:01:12,actions=output:5")
 

      

        CLI(net)

 

        print ("*** Stopping network")

        net.stop()

     

if __name__ == '__main__':

    setLogLevel( 'info' )

    topology()