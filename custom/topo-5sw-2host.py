"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        rightHost = self.addHost( 'h2' )
        SwitchA = self.addSwitch( 's1' )
        SwitchB = self.addSwitch( 's2' )
        SwitchC = self.addSwitch( 's3' )
        SwitchD = self.addSwitch( 's4' )
        SwitchE = self.addSwitch( 's5' )

        # Add links
        self.addLink( leftHost, SwitchA, 1, 1)
        self.addLink( SwitchA, SwitchB, 2, 1 )
        self.addLink( SwitchB, SwitchD, 2, 1)
        self.addLink( SwitchB, SwitchE, 3, 1)
        self.addLink( SwitchE, SwitchD, 3, 2)
        self.addLink( SwitchE, SwitchC, 2, 3)
        self.addLink( SwitchA, SwitchC, 3, 1)
        self.addLink( SwitchC, SwitchD, 2, 3)
        self.addLink( SwitchD, rightHost, 4, 1)


topos = { 'mytopo': ( lambda: MyTopo() ) }
