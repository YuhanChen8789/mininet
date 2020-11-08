from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


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
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
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

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        #Handle the arp protocol
        if pkt_arp:
            src_mac = "10:00:00:00:00:0" + pkt_arp.dst_ip[-1]
            dst_mac = "10:00:00:00:00:0" + pkt_arp.src_ip[-1]

            arp_reply_pkt = packet.Packet()
            arp_reply_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=mac_add))
            arp_reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY， src_mac=src_mac, src_ip=pkt_arp.dst_ip, dst_mac=dst_mac, dst_ip=pkt_arp.src_ip))
            arp_reply_pkt.serialize()
            arp_actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER, actions=arp_actions, data=arp_reply_pkt.data))
            datapath.send_msg(out)
            
        elif pkt_icmp:
            #out_port = self.dump_out_port(src_host_num, dst_host_num, 1)
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = 2
            icmp_actions = [parser.OFPActionOutput(out_port)]
            icmp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=pkt_icmp.proto, eth_dst=dst)
            self.add_flow(datapath, 1, icmp_match, icmp_actions)
            out=parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER，actions=icmp_actions,)
            datapath.send_msg(out)
-       elif pkt_tcp:
            src_host_list = [n for n in self.net.neighbors(src)]
            src_sw_id = src_host_list[0]

            if(src_sw_id == 2 or src_sw_id == 4) and (pkt_tcp.dst_port == 80):
                tcp_rst_pkt = packet.Packet()
                tcp_rst_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, src=dst, dst=src))
                tcp_rst_pkt.add_protocol(ipv4.ipv4(src=pkt_ipv4.dst, dst=pky.ipv4.src, proto=6))
                tcp_rst_pkt.add_protocol(tcp.tcp(src_port=pkt_tcp.dst_port, dst_port=pkt_tcp.src_port, ack=pkt_tcp.seq+1, bits=0b010100))
                tcp_rst_pkt.serialize()
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER, actions=actions, data=tcp_rst_pkt.data))
                datapath.send_msg(out)
            else:
                #out_port = self.dump_out_port(src_host_num, dst_host_num, 1)
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = 2
                tcp_actions = [parser.OFPActionOutput(out_port)]
                tcp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=pkt_tcp.proto, ipv4_src = pkt_ipv4.src_ip, ipv4_dst = pkt_ipv4.dst_ip, tcp_src = pkt_tcp.src_port, tcp_dst = pkt_tcp.dst_port)
                self.add_flow(datapath, 1, tcp_match, tcp_actions)
                out=parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER)
                datapath.send_msg(out)
        elif pkt_udp:
            src_host_list = [n for n in self.net.neighbors(src)]
            src_sw_id = src_host_list[0]
            
            if (src_sw_id == 1 or src_sw_id == 4):
                actions = []
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=pkt_udp.proto, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)
                #parser.OFPInstructionActions(OFPIT_CLEAR_ACTIONS, actions = actions)
                
            else:
                #out_port = self.dump_out_port(src_host_num, dst_host_num, 1)
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = 3
                udp_actions = [parser.OFPActionOutput(out_port)]
                udp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=pkt_udp.proto, ipv4_src = pkt_ipv4.src_ip, ipv4_dst = pkt_ipv4.dst_ip, udp_src = pkt_udp.src_port,udp_dst = pkt_udp.dst_port)
                self.add_flow(datapath, 1, udp_match, udp_actions)
                out=parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER)
                datapath.send_msg(out)
                
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
