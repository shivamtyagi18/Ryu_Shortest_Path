from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI

class MyTopo( Topo ):
        "Simple topology"

        def __init__( self ):
                "Creat topo"
                # Initialize topology
                Topo.__init__( self )

                #adding switches
                s1 = self.addSwitch('s1')
                s2 = self.addSwitch('s2')
                s3 = self.addSwitch('s3')
                s4 = self.addSwitch('s4')
                # s5 = self.addSwitch('s5')
                # s6 = self.addSwitch('s6')
                # s7 = self.addSwitch('s7')
                # s8 = self.addSwitch('s8')
              
        
                # #adding hosts
                h1 = self.addHost('h1')
                h2 = self.addHost('h2')
                h3 = self.addHost('h3')
                h4 = self.addHost('h4')
              

                # #host connections with switches
                self.addLink(h1, s1)
                self.addLink(h2, s2)
                self.addLink(h3, s3)
                self.addLink(h4, s4)
                # self.addLink(h5, s5)
                # self.addLink(h8, s8)

                self.addLink(s1, s2)
                self.addLink(s2, s3)
                self.addLink(s3, s4)
                # self.addLink(s4, s1)
                # self.addLink(s5, s6)
                # self.addLink(s6, s7)
                # self.addLink(s7, s8)
                
                #loop links
                # self.addLink(s3, s1)
                # self.addLink(s3, s6)
                # self.addLink(s2, s7)
                
               
                
topos = { 'mytopo': ( lambda: MyTopo() ) }