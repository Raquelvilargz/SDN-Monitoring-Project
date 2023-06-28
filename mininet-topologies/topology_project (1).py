#Topologia del proyecto de Network Automation
#Representa una topologia formado por 3 switches y dos hosts

"""Custom topology example

Goal: create a ring network with 3 switches and 2 hosts per switch

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    def build( self ):
        "Create custom topo."

        # Add hosts------------------------------------------
        # self.addHost(name, cpu=f): specify a fraction of overall
        # system CPU resources which will be allocated to the virtual host

        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )


        # Add switches---------------------------------------
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )


        # Add links-----------------------------------------
        #
        # Optional parameters -> bw=10, delay='5ms', loss=2, max_queue_size=1000, use_htb=True
        #
        # adds a bidirectional link with bandwidth, delay and loss characteristics,
        # with a maximum queue size of 1000 packets using the Hierarchical Token Bucket rate limiter
        # and netem delay/loss emulator. The parameter bw is expressed as a number in Mbit;
        # delay is expressed as a string with units in place (e.g. '5ms', '100us', '1s');
        # loss is expressed as a percentage (between 0 and 100); and max_queue_size is expressed in packets.

        self.addLink( h1, s1, 1, 1 )

        self.addLink( h2, s2, 1, 1 )


        self.addLink( s1, s2, 2, 2 )
        self.addLink( s2, s3, 3, 2 )
        self.addLink( s1, s3, 3, 3 )

topos = { 'mytopo': ( lambda: MyTopo() ) }
