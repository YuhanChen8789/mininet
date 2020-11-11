#conding:utf-8

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
#        if ev.msg.msg_len < ev.msg.total_len:
#            self.logger.debug("packet truncated: only %s of %s bytes",
#                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_arp = pkt.get_protocols(arp.arp)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_icmp = pkt.get_protocols(icmp.icmp)
        pkt_ipv4 = pkt.get_protocols(ipv4.ipv4)
        pkt_tcp = pkt.get_protocols(tcp.tcp)
        pkt_udp = pkt.get_protocols(udp.udp)

        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
#        if pkt_udp:
#            self.logger.info("mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm pkt %s", pkt)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        #Handle the arp protocol
        if pkt_arp:
            mac_add = "10:00:00:00:00:0" + pkt_arp[0].dst_ip[-1]
#            self.logger.info("mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm pkt %s %s", src_mac, pkt_arp[0].dst_ip[-1])
	  
            arp_reply_pkt = packet.Packet()
            arp_reply_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=mac_add))
            arp_reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=mac_add, src_ip=pkt_arp[0].dst_ip, dst_mac=pkt_arp[0].src_mac, dst_ip=pkt_arp[0].src_ip, proto=pkt_arp[0].proto))
            arp_reply_pkt.serialize()
            arp_actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER, actions=arp_actions, data=arp_reply_pkt.data)
            datapath.send_msg(out)
        else:
            if abs(int(dst[-1]) - int(src[-1])) % 4 != 2:
                self.logger.info("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk pkt %s %s %s", pkt, dst[-1], src[-1])
                if int(datapath.id) == int(eth.dst[-1]):
                    out_port = 1
                elif (int(dst[-1]) - int(src[-1]) == 1) or (int(dst[-1]) - int(src[-1]) == -3):
                    out_port = 2
                else:
                    out_port = 3
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match, actions)
                data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
	    else:
                if pkt_icmp:
                #out_port = self.dump_out_port(src_host_num, dst_host_num, 1)
                    if int(datapath.id) == int(eth.dst[-1]):
                        out_port = 1
                    else:
                        out_port = 2
                    icmp_pkt = packet.Packet()
                    icmp_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=dst, src=src))
                    icmp_pkt.add_protocol(ipv4.ipv4(src=pkt_ipv4[0].src, dst=pkt_ipv4[0].dst, proto=1, ttl=255, version=4))
                    icmp_pkt.add_protocol(icmp.icmp(type_=pkt_icmp[0].type, code=0, csum=0, data=pkt_icmp[0].data))
                    icmp_actions = [parser.OFPActionOutput(out_port)]
                    icmp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=1, eth_dst=dst)
                    self.add_flow(datapath, 1, icmp_match, icmp_actions)
                    icmp_pkt.serialize()
                    out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER, actions=icmp_actions, data=icmp_pkt.data)
                    datapath.send_msg(out)

                elif pkt_tcp:
                    if((int(datapath.id) == int(2)) or (int(datapath.id) == int(4))) and (int(pkt_tcp[0].dst_port) == int(80)):
                        self.logger.info("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee http %s", pkt)
                        tcp_rst_pkt = packet.Packet()
                        tcp_rst_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, src=dst, dst=src))
                        tcp_rst_pkt.add_protocol(ipv4.ipv4(src=pkt_ipv4[0].dst, dst=pkt_ipv4[0].src, proto=6))
                        tcp_rst_pkt.add_protocol(tcp.tcp(src_port=pkt_tcp[0].dst_port, dst_port=pkt_tcp[0].src_port, ack=pkt_tcp[0].seq+1, bits=0b010100))
                        tcp_rst_pkt.serialize()
                        actions = [parser.OFPActionOutput(in_port)]
                        out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER, actions=actions, data=tcp_rst_pkt.data)
                        datapath.send_msg(out)
                    else:
                  #self.logger.info("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee tcp %s %s", pkt_ipv4, pkt_tcp)
                    #out_port = self.dump_out_port(src_host_num, dst_host_num, 1)
                        if int(datapath.id) == int(eth.dst[-1]):
                            out_port = 1
                        else:
                            out_port = 2
                            self.logger.info("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee tcp %s %s", pkt_ipv4, out_port)
                        tcp_pkt = packet.Packet()
                        tcp_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, src=src, dst=dst))
                        tcp_pkt.add_protocol(ipv4.ipv4(src=pkt_ipv4[0].src, dst=pkt_ipv4[0].dst, proto=pkt_ipv4[0].proto, identification=pkt_ipv4[0].identification))
                        tcp_pkt.add_protocol(tcp.tcp(dst_port=pkt_tcp[0].dst_port, src_port=pkt_tcp[0].src_port, ack=pkt_tcp[0].ack, seq=pkt_tcp[0].seq, bits=pkt_tcp[0].bits, window_size=pkt_tcp[0].window_size))
                        tcp_pkt.serialize()

                        tcp_actions = [parser.OFPActionOutput(out_port)]
                        tcp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=pkt_ipv4[0].proto, ipv4_src = pkt_ipv4[0].src, ipv4_dst = pkt_ipv4[0].dst, tcp_src = pkt_tcp[0].src_port, tcp_dst = pkt_tcp[0].dst_port)
                        self.add_flow(datapath, 1, tcp_match, tcp_actions)
                        out=parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER, actions=tcp_actions, data=tcp_pkt.data)
                        datapath.send_msg(out)
                elif pkt_udp and pkt_ipv4:
                    if ((int(datapath.id) == int(1)) or (int(datapath.id) == int(4))):
                        self.logger.info("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee udp %s %s", pkt_ipv4, pkt_udp)
                        actions = []
                        match = parser.OFPMatch(eth_type=0x0800, ip_proto=pkt_ipv4[0].proto, eth_dst=dst)
                        self.add_flow(datapath, 1, match, actions)
                        #parser.OFPInstructionActions(OFPIT_CLEAR_ACTIONS, actions = actions)
                
                    else:
                        #out_port = self.dump_out_port(src_host_num, dst_host_num, 1)
                        if int(datapath.id) == int(eth.dst[-1]):
                            out_port = 1
                        else:
                            out_port = 3
                        #self.logger.info("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee udp %s %s %s", pkt_ipv4, pkt_udp, out_port)
                        udp_pkt = packet.Packet()
                        udp_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, src=src, dst=dst))
                        udp_pkt.add_protocol(ipv4.ipv4(src=pkt_ipv4[0].src, dst=pkt_ipv4[0].dst, proto=pkt_ipv4[0].proto))
                        udp_pkt.add_protocol(udp.udp(src_port=pkt_udp[0].src_port, dst_port=pkt_udp[0].dst_port))
                        udp_pkt.serialize()
                        udp_actions = [parser.OFPActionOutput(out_port)]
                        udp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=pkt_ipv4[0].proto, eth_src=src, eth_dst=dst, in_port=in_port)
                        self.add_flow(datapath, 1, udp_match, udp_actions)
                        out=parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER, actions = udp_actions, data=udp_pkt.data)
                        datapath.send_msg(out)
                
        
