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

from ryu.app.stardogBackend import StardogBackend
from ryu.lib.packet import ethernet, arp, packet
from ryu.lib.packet.ether_types import ETH_TYPE_ARP, ETH_TYPE_IP
from ryu.lib import hub
from ryu.topology import event, switches
from rdflib import Graph, Namespace, Literal
from rdflib.namespace import RDF

import json
import urllib2

LOG = logging.getLogger("SemanticWeb")

class SemanticWeb(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'switches': switches.Switches,
        'backend': StardogBackend
    }

    def __init__(self, *args, **kwargs):
        super(SemanticWeb, self).__init__(*args, **kwargs)
        self.export_event = hub.Event()
        self.threads.append(hub.spawn(self.export_loop))
        self.is_active = True
        self.TIMEOUT_CHECK_PERIOD = 5
        self.topo = kwargs["switches"]
        self.backend = kwargs["backend"]
        self.dps = {}
        self.waiters = {}
        self.ofctl = ofctl_v1_3

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            self.dps[ev.dp.id] = ev.dp
        else:
            del  self.dps[ev.dp.id]

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

        datapath = msg.datapath
        dpid = datapath.id
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
            src_mac = eth.src
            dst_mac = eth.dst
            url = "http://172.18.2.106:8182"
            values = {
                "gremlin" : 'g.V().has("http://home.eps.hw.ac.uk/~qz1/hasMAC", src_mac).'+
                'out("http://home.eps.hw.ac.uk/~qz1/connectToPort").'+
                'repeat(__.in("http://home.eps.hw.ac.uk/~qz1/hasPort").'+
                'out("http://home.eps.hw.ac.uk/~qz1/hasPort").'+
                'out("http://home.eps.hw.ac.uk/~qz1/connectToPort").simplePath()).'+
                'until(has("http://home.eps.hw.ac.uk/~qz1/hasMAC", dst_mac)).path().limit(1)',
                "bindings" : {"src_mac": src_mac, "dst_mac": dst_mac}
            }

            req = urllib2.Request(url, json.dumps(values))
            response = urllib2.urlopen(req)
            res = response.read()

            res = json.loads(res)
            if len(res["result"]["data"]) == 0:
                LOG.error("Didn't find a path \n%s\n%s" %(values, json.dumps(res)))
                return
            count = len(res["result"]["data"][0]["objects"])
            ix = 1
            while ix < count - 1:
                src_port = res["result"]["data"][0]["objects"][ix]["properties"]
                dst_port = res["result"]["data"][0]["objects"][ix+2]["properties"]
                sw = res["result"]["data"][0]["objects"][ix+1]["properties"]
                dpid = int(sw["http://home.eps.hw.ac.uk/~qz1/hasID"][0]["value"])
                src_port_no = int(src_port["http://home.eps.hw.ac.uk/~qz1/port_no"][0]["value"])
                dst_port_no = int(dst_port["http://home.eps.hw.ac.uk/~qz1/port_no"][0]["value"])

                # Step 3: Install flows
                if dpid in self.dps:
                    self._insert_host_connect_flows(self.dps[dpid], src_port_no, dst_mac,
                                                    dst_port_no, src_mac)
                    # setup inverse path
                    self._insert_host_connect_flows(self.dps[dpid],
                                                    dst_port_no, src_mac,
                                                    src_port_no, dst_mac)
                ix = ix + 3

        return

    def _insert_host_connect_flows(self, dp, src_port, src_mac, dst_port, dst_mac):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(src_port, ofproto.OFPCML_NO_BUFFER)])]
        match = parser.OFPMatch(in_port=dst_port, eth_dst=dst_mac, eth_src=src_mac)
        mod = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
        dp.send_msg(mod)

    def close(self):
        self.is_active = False
        self.export_event.set()
        hub.joinall(self.threads)

    def export_loop(self):
        while self.is_active:
            self.export_event.clear()
            LOG.debug("periodic event fired!")
            g = Graph()
            ns = Namespace('http://home.eps.hw.ac.uk/~qz1/')
#            try:
            sws = self.get_switches()
            for sw in sws:
                s = 's' + str(sw.dp.id)
                g.add( (ns[s], RDF.type, ns['Switch']) )
                g.add( (ns[s], ns.hasName, Literal(s)) )
                g.add( (ns[s], ns.hasID, Literal(sw.dp.id))  )

                for p in sw.ports:
                    pid = s + "_port" + str(p.port_no)
                    g.add( (ns[s], ns.hasPort, ns[pid])  )
                    g.add( (ns[pid], RDF.type, ns['Port'])  )
                    g.add( (ns[pid], ns.isIn, ns[s]) )
                    g.add( (ns[pid], ns.hasName,    Literal(p.name))  )
                    g.add( (ns[pid], ns.hasMAC,  Literal(p.hw_addr))  )
                    g.add( (ns[pid], ns.port_no,    Literal(p.port_no))  )

            hosts = self.get_hosts()
            hid_gen = 0
            for h in hosts:
                hid_gen += 1
                swid = 's' + str(h.port.dpid)
                hid = swid + "_host" + str(hid_gen)
                pid = swid + "_port" + str(h.port.port_no)
                LOG.debug("sw %s host %s %s", h.port.dpid, hid, h.mac)
                g.add( (ns[hid], RDF.type, ns['Host'])  )
                g.add( (ns[swid], ns.hasHost, ns[hid]) )

                g.add( (ns[hid], ns.connectToPort, ns[pid]) )
                g.add( (ns[pid], ns.connectToPort, ns[hid]) )
                for ip in h.ipv4:
                    g.add( (ns[hid], ns.hasIPv4, Literal(ip)) )
                g.add( (ns[hid], ns.hasMAC,  Literal(h.mac)) )

            links = self.get_links()
            for link in links:
                sid = 's' + str(link.src.dpid)
                spid = sid + "_port" + str(link.src.port_no)
                did = 's' + str(link.dst.dpid)
                dpid = did + "_port" + str(link.dst.port_no)
                g.add( (ns[spid], ns.connectToPort,
                             ns[dpid])  )
                g.add( (ns[dpid], ns.connectToPort,
                             ns[spid])  )

            flows = self.get_flows()

            flow_count = 0
            for dpid in flows.keys():
                for flow in flows[dpid]:
                    sid = 's' + str(dpid)
                    flid = 's' + str(dpid) + '_flow' + str(flow_count)
                    g.add( (ns[sid], ns.hasFlow, ns[flid]) )
                    g.add( (ns[flid], RDF.type, ns['Flow']) )
                    g.add( (ns[flid], ns.priority,     Literal(flow.priority)) )
                    g.add( (ns[flid], ns.hard_timeout, Literal(flow.hard_timeout)) )
                    g.add( (ns[flid], ns.byte_count,   Literal(flow.byte_count)) )
                    g.add( (ns[flid], ns.duration_sec, Literal(flow.duration_sec)) )
                    g.add( (ns[flid], ns.length,       Literal(flow.length)) )
                    g.add( (ns[flid], ns.flags,        Literal(flow.flags)) )
                    g.add( (ns[flid], ns.table_id,     Literal(flow.table_id)) )
                    g.add( (ns[flid], ns.cookie,       Literal(flow.cookie)) )
                    g.add( (ns[flid], ns.packet_count, Literal(flow.packet_count)) )
                    g.add( (ns[flid], ns.idle_timeout, Literal(flow.idle_timeout)) )

                    for (field, val) in flow.match.iteritems():
                        g.add( (ns[flid], ns['has'+field], Literal(val) ) )

                    action_count = 0
                    for inst in flow.instructions:
                        for action in inst.actions:
                            actid = flid + '_action' + str(action_count)
                            g.add( (ns[flid], ns.hasAction, ns[actid]) )
                            if action.type == 0:
                                g.add( (ns[actid], RDF.type, ns['ActionOutput']) )
                                g.add( (ns[actid], ns.toPort, Literal(action.port)   ) )
                            action_count = action_count + 1
                    flow_count = flow_count + 1

            # rep = self.send_request(EventInsertTuples(g))i
            self.backend.insert_tuples(g)
            self.export_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)

    def _handle_arp (self, arp_pkt, datapath, port_no) :
        LOG.error("looking MAC for IP addr %s"%(str(arp_pkt.dst_ip)))
        res = self.backend._get_mac_of_host(arp_pkt.dst_ip)

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
        for dp in self.dps.itervalues():
            self.ofctl.get_flow_stats(dp, self.waiters)
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


