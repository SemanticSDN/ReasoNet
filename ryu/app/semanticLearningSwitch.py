# Copyright (C) 2016 TOUCAN EPSRC project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.controller import dpset
from ryu.topology import switches

from ryu.app.stardogBackend import StardogBackend
from ryu.app.pathManager import PathManager
from ryu.app.flowManager import FlowManager
from ryu.app.semanticController import SemanticController
from ryu.app.topologyManager import TopologyManager
from ryu.lib.packet import ethernet, arp, packet
from ryu.lib.packet.ether_types import ETH_TYPE_ARP, ETH_TYPE_IP


LOG = logging.getLogger("SemanticLearningSwitch")

class SemanticLearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'backend': StardogBackend,
        'flowManager': FlowManager,
        'pathManager': PathManager,
        'switches': switches.Switches,
        'topologyManager': TopologyManager,
#        'controller': SemanticController,
    }

    def __init__(self, *args, **kwargs):
        super(SemanticLearningSwitch, self).__init__(*args, **kwargs)
        self.backend = kwargs["backend"]
        self.path = kwargs["pathManager"]
        self.dps = {}

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            self.dps[ev.dp.id] = ev.dp
        else:
            del  self.dps[ev.dp.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

#        # install the table-miss flow entry.
#        match = parser.OFPMatch()
#        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
#                                          ofproto.OFPCML_NO_BUFFER)]
#        self.flowManager.add_flow(datapath, 0, match, actions, datapath.ofproto.OFPCML_NO_BUFFER)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Step 1: Figure out source and destination mac and IP address
        msg = ev.msg

        datapath = msg.datapath
        port_no = msg.match['in_port']

        # check if packet is ARP in order to respond with a packet out message
        eth, pkt_type, pkt_data = ethernet.ethernet.parser(msg.data)
        if eth.ethertype == ETH_TYPE_ARP:
            # this is an ethertype and need to run an ARP proxy
            arp_pkt, _, _ = arp.arp.parser(pkt_data)
            if arp_pkt.opcode == arp.ARP_REQUEST:
                self._handle_arp(arp_pkt, datapath, port_no)
            return

        # TODO Step 2: Is the destination known to the controller If not, drop for now
        # Step 3: compute the path
        if eth.ethertype == ETH_TYPE_IP and eth.dst != "ff:ff:ff:ff:ff:ff":
            self.path.add_path(eth.src, eth.dst, msg.buffer_id,bw=1000000000)
        return

    def _handle_arp (self, arp_pkt, datapath, port_no) :
        LOG.info("looking MAC for IP addr %s"%(str(arp_pkt.dst_ip)))
        res = self.backend.get_mac_of_host(arp_pkt.dst_ip)

        if res is None:
            return

        dst_host, dst_mac = res

        LOG.error("Found host %s with IP addr %s and MAC %s" %
                  (str(dst_host), str(arp_pkt.dst_ip), str(dst_mac)))
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(src=dst_mac, dst=arp_pkt.src_mac,
                              ethertype=ETH_TYPE_ARP))
        p.add_protocol(arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4,
                               opcode=arp.ARP_REPLY, src_mac=dst_mac,
                               src_ip=arp_pkt.dst_ip,
                               dst_mac=arp_pkt.src_mac,
                               dst_ip=arp_pkt.src_ip))
        p.serialize()
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=port_no)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=p.data)
        datapath.send_msg(out)
