from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.controller import ofp_event
from ryu.ofproto import ether
import logging
from operator import attrgetter
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp
from ryu.ofproto import ether
from ryu.ofproto import inet

LOG = logging.getLogger('LoadBalancingSwitch')
LOG.setLevel(logging.DEBUG)
logging.basicConfig()

class LoadBalancingSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(LoadBalancingSwitch, self).__init__(*args, **kwargs)
        self.hw_addr = ''

    #helper method adds a flow with specified match and action
    def add_flow(self, datapath, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        


    #This function is triggered when a packet is sent from the switch to the controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #LOG.debug("received packet!!")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = Packet(msg.data)
        
        eth_frame = pkt.get_protocol(ethernet)

        if eth_frame.ethertype == ether.ETH_TYPE_ARP:
            self.handle_arp(datapath, in_port, eth_frame, pkt)

    #handles arp requests sent to controller
    def handle_arp(self, datapath, port, eth_frame, pkt):
        #LOG.debug("called handle_arp!!")
        arp_pkt = pkt.get_protocol(arp)
        dst_ip = arp_pkt.dst_ip
        self.generate_arp_reply(datapath, eth_frame, arp_pkt, dst_ip, port)

    def generate_arp_reply(self, datapath, eth_frame, arp_pkt, dest_ip, in_port):
        dstIp = arp_pkt.src_ip
        srcIp = arp_pkt.dst_ip
        dstMac = eth_frame.src

        #For testing purposes, source mac is always 00:00:00:00:00:05
        srcMac = "00:00:00:00:00:05"
        outPort = in_port
        LOG.debug("Got to sending the ARP response!!!!")
        e = ethernet(dstMac,srcMac,ether.ETH_TYPE_ARP)
        a = arp(1,0x0800,6,4,2,srcMac,srcIp,dstMac,dstIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        self.send_arp_reply(datapath,in_port,p)

    #sends packet from switch out specified port
    def send_arp_reply(self, datapath, port, pkt):
        #LOG.debug("Sending Reply!!")
        ofproto=datapath.ofproto
        parser = datapath.ofproto_parser
        #pkt.serialize()
        #self.logger.info("packet-out %s" % (pkt,))
        #data = pkt.data
        actions = [parser.OFPActionOutput(port,0)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=pkt.data)
        datapath.send_msg(out)


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