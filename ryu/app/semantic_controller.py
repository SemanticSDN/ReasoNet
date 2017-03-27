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
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.controller import dpset

from ryu.app.stardogBackend import StardogBackend, EventInsertTuples
# from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet.ether_types import *
from ryu.lib import hub
from ryu.topology import event, switches
from rdflib import Graph, Namespace, Literal# , plugin
# import json, rdflib_jsonld
# from rdflib.plugin import register# , Serializer
from rdflib.namespace import RDF
from rdflib.plugins.stores import sparqlstore
from ryu.controller import dpset

# import sys
# import json


LOG = logging.getLogger("SemanticWeb")

class SemanticWeb(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'switches': switches.Switches,
        'dpset': dpset.DPSet,
        'backend': StardogBackend
    }

    def __init__(self, *args, **kwargs):
        super(SemanticWeb, self).__init__(*args, **kwargs)
        self.ns = Namespace('http://home.eps.hw.ac.uk/~qz1/')
        self.db_output = 'my_buff_switchStatus.rdf'
        self.export_event = hub.Event()
        self.threads.append(hub.spawn(self.export_loop))
        self.is_active = True
        self.TIMEOUT_CHECK_PERIOD = 5
        self.g = Graph()
        self.topo = kwargs["switches"]
        self.backend = kwargs["backend"]
        self.dps = set()
        self.waiters = {}
        self.ofctl = ofctl_v1_3

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            self.dps.add(ev.dp)
        else:
            self.dps.remove(ev.dp)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Step 1: Figure out source and destination mac and IP address
        msg = ev.msg
        eth, pkt_type, pkt_data = ethernet.ethernet.parser(msg.data)
        host_mac = eth.src

        # ignore lldp and cfm packets
        if eth.ethertype in (ETH_TYPE_LLDP, ETH_TYPE_CFM):
#            LOG.error("got an LLDP packet")
            return

        datapath = msg.datapath
        dpid = datapath.id
        port_no = msg.match['in_port']
        # LOG.error("discovered %s -> %s:%s", host_mac, port.dpid, port.port_no)
        src_mac = eth.src
        dst_mac = eth.dst

# SELECT distinct ?host ?port ?mac ?sw ?type {
#   { ?host a of:Host .
#     ?host a ?type.
#     ?host of:connectToPort ?port.
#    ?host of:hasMAC ?mac.
#    ?sw of:hasPort ?port
#   }
# }

        # Step 2: Is the destination known to the controller
        LOG.error("trying to connect %s -> %s" % (src_mac, dst_mac))


        # If not, drop for now
        # TODO: minimum spanning tree to figure out controlled broadcast, or
        # run an ARP proxy (the only important broadcast thing) and self reply

        # If we know it, compute the path

        # Step 3: Install flows

        return

    def close(self):
        self.is_active = False
        self.export_event.set()
        hub.joinall(self.threads)

    def export_loop(self):
        while self.is_active:

            self.get_flows()
            self.export_event.clear()
            LOG.info("periodic event fired!")
            self.g = Graph()
#            try:
            sws = self.get_switches()
            for sw in sws:
                s = 's' + str(sw.dp.id)
                self.g.add( (self.ns[s], RDF.type, self.ns['Switch']) )
                self.g.add( (self.ns[s], self.ns.hasName, Literal(s)) )
                self.g.add( (self.ns[s], self.ns.hasID, Literal(sw.dp.id))  )

                for p in sw.ports:
                    pid = s + "_port" + str(p.port_no)
                    self.g.add( (self.ns[s], self.ns.hasPort, self.ns[pid])  )
                    self.g.add( (self.ns[pid], RDF.type, self.ns['Port'])  )
                    self.g.add( (self.ns[pid], self.ns.isIn, self.ns[s]) )
                    self.g.add( (self.ns[pid], self.ns.hasName,    Literal(p.name))  )
                    self.g.add( (self.ns[pid], self.ns.hasMAC,  Literal(p.hw_addr))  )
                    self.g.add( (self.ns[pid], self.ns.port_no,    Literal(p.port_no))  )

            hosts = self.get_hosts()
            hid_gen = 0
            for h in hosts:
                hid_gen += 1
                swid = 's' + str(h.port.dpid)
                hid = swid + "_host" + str(hid_gen)
                pid = swid + "_port" + str(h.port.port_no)
                LOG.info("sw %s host %s %s", h.port.dpid, hid, h.mac)
                self.g.add( (self.ns[hid], RDF.type, self.ns['Host'])  )
                self.g.add( (self.ns[swid], self.ns.hasHost, self.ns[hid]) )

                self.g.add( (self.ns[hid], self.ns.connectToPort, self.ns[pid]) )
                self.g.add( (self.ns[hid], self.ns.hasIPv4, Literal(h.ipv4)) )
                self.g.add( (self.ns[hid], self.ns.hasMAC,  Literal(h.mac)) )

            links = self.get_links()
            for link in links:
                sid = 's' + str(link.src.dpid)
                spid = sid + "_port" + str(link.src.port_no)
                did = 's' + str(link.dst.dpid)
                dpid = did + "_port" + str(link.dst.port_no)
                self.g.add( (self.ns[spid], self.ns.connectToPort,
                             self.ns[dpid])  )
                self.g.add( (self.ns[dpid], self.ns.connectToPort,
                             self.ns[spid])  )

            flows = self.get_flows()

            flow_count = 0
            for dpid in flows.keys():
                for flow in flows[dpid]:
                    sid = 's' + str(dpid)
                    flid = 's' + str(dpid) + '_flow' + str(flow_count)
                    self.g.add( (self.ns[sid], self.ns.hasFlow, self.ns[flid]) )
                    self.g.add( (self.ns[flid], RDF.type, self.ns['Flow']) )
                    self.g.add( (self.ns[flid], self.ns.priority,     Literal(flow.priority)) )
                    self.g.add( (self.ns[flid], self.ns.hard_timeout, Literal(flow.hard_timeout)) )
                    self.g.add( (self.ns[flid], self.ns.byte_count,   Literal(flow.byte_count)) )
                    self.g.add( (self.ns[flid], self.ns.duration_sec, Literal(flow.duration_sec)) )
                    self.g.add( (self.ns[flid], self.ns.length,       Literal(flow.length)) )
                    self.g.add( (self.ns[flid], self.ns.flags,        Literal(flow.flags)) )
                    self.g.add( (self.ns[flid], self.ns.table_id,     Literal(flow.table_id)) )
                    self.g.add( (self.ns[flid], self.ns.cookie,       Literal(flow.cookie)) )
                    self.g.add( (self.ns[flid], self.ns.packet_count, Literal(flow.packet_count)) )
                    self.g.add( (self.ns[flid], self.ns.idle_timeout, Literal(flow.idle_timeout)) )

                    for (field, val) in flow.match.iteritems():
                        self.g.add( (self.ns[flid], self.ns['has'+field], Literal(val) ) )

                    action_count = 0
                    for inst in flow.instructions:
                        for action in inst.actions:
                            actid = flid + '_action' + str(action_count)
                            self.g.add( (self.ns[flid], self.ns.hasAction, self.ns[actid]) )
                            if action.type == 0:
                                self.g.add( (self.ns[actid], RDF.type, self.ns['ActionOutput']) )
                                self.g.add( (self.ns[actid], self.ns.toPort, Literal(action.port)   ) )
                            action_count = action_count + 1
                    flow_count = flow_count + 1

            rep = self.send_request(EventInsertTuples(self.g))
            self.export_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)

    def get_switches(self):
        rep = self.send_request(event.EventSwitchRequest(None))
        return rep.switches

    def get_hosts(self):
        rep = self.send_request(event.EventHostRequest(None))
        return rep.hosts

    def get_links(self):
        rep = self.send_request(event.EventLinkRequest(None))
        return rep.links

    def get_flows(self):
        ret = {}
        for dp in self.dps:
            res = self.ofctl.get_flow_stats(dp, self.waiters)
            ret[dp.id] = []
            xids = self.waiters[dp.id].keys()
            for xid in xids:
                _, msgs = self.waiters[dp.id][xid]
                for msg in msgs:
                    ret[dp.id].extend(msg.body)
                del self.waiters[dp.id][xid]
        return ret


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if (dp.id not in self.waiters) or (msg.xid not in self.waiters[dp.id]):
            return
        locks, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return
        locks.set()


