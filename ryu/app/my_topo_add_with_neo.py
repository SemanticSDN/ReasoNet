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
from ryu.ofproto import ofproto_v1_3# , ofproto_v1_2
from ryu.app.stardogBackend import StardogBackend, EventInsertTuples
from ryu.lib import hub
from ryu.topology import event, switches
from rdflib import Graph, Namespace, Literal# , plugin
from rdflib.namespace import RDF
from neo4j.v1 import GraphDatabase, basic_auth

LOG = logging.getLogger("SemanticWeb")

class SemanticWeb(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'switches': switches.Switches,
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
        # init graph database
        self.driver = GraphDatabase.driver("bolt://localhost", auth=basic_auth("neo4j", "neo4j"))
        self.session = self.driver.session()

    def __del__(self):
        self.session.close()

    def dump_graphDatabase(self):
        results = self.session.run("MATCH (n)-[c]-() RETURN n, c")
        for r in results:
            print r

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
        # self.topo.host_discovery_packet_in_handler(ev)
        return

    def close(self):
        self.is_active = False
        self.export_event.set()
        hub.joinall(self.threads)

    def export_loop(self):
        while self.is_active:
            self.export_event.clear()
            LOG.error("event fired!")
            self.g = Graph()
#            try:
            sws = self.get_switches()
            for sw in sws:
                s = 's' + str(sw.dp.id)
                self.g.add( (self.ns[s], RDF.type, self.ns['Switch']) )
                LOG.error("sw %s", sw.dp.id)
                self.g.add( (self.ns[s], self.ns.hasName, Literal(s)) )
                self.g.add( (self.ns[s], self.ns.hasID, Literal(sw.dp.id))  )

                self.session.run("CREATE ("+ s +":Node {name:'"+ s +"', isSwitch:1 })")

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
                LOG.error("sw %s host %s %s", h.port.dpid, hid, h.mac)
                self.g.add( (self.ns[hid], RDF.type, self.ns['Host'])  )
                self.g.add( (self.ns[swid], self.ns.hasHost, self.ns[hid]) )

                self.g.add( (self.ns[hid], self.ns.connectToPort, self.ns[pid]) )
                self.g.add( (self.ns[hid], self.ns.hasIPv4, Literal(h.ipv4)) )
                self.g.add( (self.ns[hid], self.ns.hasMAC,  Literal(h.mac)) )

                self.session.run("CREATE ("+ hid +":Node {name:'"+ hid +"', isSwitch:0 })")

            links = self.get_links()
            for link in links:
                print(link)
                sid = 's' + str(link.src.dpid)
                spid = sid + "_port" + str(link.src.port_no)
                did = 's' + str(link.dst.dpid)
                dpid = did + "_port" + str(link.dst.port_no)
                self.g.add( (self.ns[spid], self.ns.connectToPort,
                             self.ns[dpid])  )
                self.g.add( (self.ns[dpid], self.ns.connectToPort,
                             self.ns[spid])  )

                self.session.run(" MATCH (n1:Node {name:'"+ sid +"'}), (n2:Node {name:'"+ did +"'}) CREATE (n1)-[:CONNECT]->(n2)" )

                # print(link.src.dpid + " " + link.dst.dpid)
            print(links)

#            except:
#                LOG.error("Unexpected error: %s", sys.exc_info()[0])
            with open(self.db_output, 'w') as f:
                f.write(self.g.serialize(format = 'turtle'))
                f.close()

            rep = self.send_request(EventInsertTuples(self.g))
            print("Query succeed? %s", rep.result)
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

    def findShortestPath(self, node1, node2):
        path = self.session.run("MATCH (start:Node {name:'"+ node1 +"'}), (end:Node {name:'"+ node2 +"'}), p = shortestPath((start)-[:CONNECT*]-(end)) RETURN p")
        for p in path:
            print p["p"]

    def clearLinkedDataModel(self):
        with open(self.file_abs, 'w') as f:
            f.write('')

    def clearGraphDatabase(self):
        self.session.run("MATCH (n) DETACH DELETE n")

