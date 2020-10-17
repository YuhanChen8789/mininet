#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLoglevel, info
from mininet.util import dumpNodeConnections
from mininet.link import Link, Intf, TCLink
import os
from time import sleep
import sys

class FatTreeTopo(Topo):

    def __init__(self, N):

        Topo.__init__(self)
        
    hosts = [[0 for h_idx in range(N/2)] for sL_idx in range(N)]
    leave_switch = [0 for sL_idx in range(N)]
    spine_switch = [0 for sS_idx in range(N/2)]
    
    #add hosts
    for sL_idx in range(N):
        for h_idx in range(N/2):
            host_name = 'h' + str(sL_idx) + '_' + str(h_idx)
            host_ip_idx = h_idx + sL_idx*N/2+1
            hosts[sL_idx][h_idx] = self.addHost(host_name, ip='10.0.0.'+str(host_ip_idx)+'/24')

    #add leaves switch
    for sL_idx in range(N):
        l_switch_name = 'sL' + str(sL_idx)
        leave_switch[sL_idx] = self.addSwitch(l_switch_name)

    #Add Spine switch
    for sS_idx in range(N/2):
        s_switch_name = 'sS' + str(sS_idx)
        spine_switch[sS_idx] = self.addSwitch(s_switch_name)

    #Add links in pod
    #Add host + leaves switch links
    for sL_idx in range(N):
        for h_idx in range(N/2):
            self.addLink(hosts[sL_idx], leave_switch[sL_idx])
    
    #Add leaves switch + spine switch links
    for sS_idx in range(N/2):
        for sL_idx in range(N):
            self.addLink(leave_switch[sL_idx], spine_switch[sS_idx])
            
# This is for "mn --custom"
topos = { 'mytopo': ( lambda N: FatTreeTopo(N) ) }

# This is for "python *.py"
if __name__ == '__main__':
    setLogLevel( 'info' )
            
    topo = Topology()
    net = Mininet(topo=topo, link=TCLink)       # The TCLink is a special setting for setting the bandwidth in the future.
    
    # 1. Start mininet
    net.start()
    
    
    # Wait for links setup (sometimes, it takes some time to setup, so wait for a while before mininet starts)
    print "\nWaiting for links to setup . . . .",
    sys.stdout.flush()
    for time_idx in range(3):
        print ".",
        sys.stdout.flush()
        sleep(1)
    
        
    # 2. Start the CLI commands
    info( '\n*** Running CLI\n' )
    CLI( net )
    
    
    # 3. Stop mininet properly
    net.stop()


    ### If you did not close the mininet, please run "mn -c" to clean up and re-run the mininet
