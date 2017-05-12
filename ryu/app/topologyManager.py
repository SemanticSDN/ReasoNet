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
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset

from ryu.app.stardogBackend import StardogBackend
from ryu.app.flowManager import FlowManager
from ryu.lib import hub
from ryu.topology import event, switches
from rdflib import Graph, Namespace, Literal
from rdflib.namespace import RDF


LOG = logging.getLogger("PathManager")

class TopologyManager(app_manager.RyuApp):
    _CONTEXTS = {
        'switches': switches.Switches,
        'backend': StardogBackend,
        'flowManager': FlowManager
    }

    def __init__(self, *args, **kwargs):
        super(TopologyManager, self).__init__(*args, **kwargs)
        self.export_event = hub.Event()
        self.threads.append(hub.spawn(self.export_loop))
        self.is_active = True
        self.TIMEOUT_CHECK_PERIOD = 5
        self.topo = kwargs["switches"]
        self.backend = kwargs["backend"]
        self.flowManager = kwargs["flowManager"]
        self.dps = {}
        self.ns = Namespace('http://home.eps.hw.ac.uk/~qz1/')

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

        # install the table-miss flow entry.
        ofproto = datapath.ofproto
        self.flowManager.add_flow(datapath, priority=0, output=ofproto.OFPP_CONTROLLER)

    @set_ev_cls(event.EventSwitchEnter)
    def topo_switch_enter(self, ev):
        g = Graph()
        s = 's' + str(ev.switch.dp.id)
        g.add( (self.ns[s], RDF.type, self.ns['Switch']) )
        g.add( (self.ns[s], self.ns.hasName, Literal(s)) )
        g.add( (self.ns[s], self.ns.hasID, Literal(ev.switch.dp.id))  )
        for p in ev.switch.ports:
            self._add_port_to_graph(g, ev.switch.dp.id, p)
        self.backend.insert_tuples(g)

    @set_ev_cls(event.EventSwitchLeave)
    def topo_switch_leave(self, ev):
        s = 's' + str(ev.switch.dp.id)
        return self.backend.remove_switch(s)

    def _add_port_to_graph(self, g, dpid, p):
        s = 's' + str(dpid)
        pid = s + "_port" + str(p.port_no)
        g.add( (self.ns[s], self.ns.hasPort, self.ns[pid])  )
        g.add( (self.ns[pid], RDF.type, self.ns['Port'])  )
        g.add( (self.ns[pid], self.ns.isIn, self.ns[s]) )
        g.add( (self.ns[pid], self.ns.hasName,    Literal(p.name))  )
        g.add( (self.ns[pid], self.ns.hasMAC,  Literal(p.hw_addr))  )
        g.add( (self.ns[pid], self.ns.port_no,    Literal(p.port_no))  )
        g.add( (self.ns[pid], self.ns.isUP,    Literal(p.is_live())  ) )
        g.add( (self.ns[pid], self.ns.hasCapacity, Literal(1000000000) ) )
        g.add( (self.ns[pid], self.ns.hasLoad, Literal(0) ) )

    @set_ev_cls(event.EventPortAdd)
    def topo_port_add(self, ev):
        g = Graph()
        self.add_port_to_graph(g, ev.port.dpid, ev.port)
        self.backend.insert_tuples(g)
        return

    @set_ev_cls(event.EventPortModify)
    def topo_port_modify(self, ev):
        s = 'of:s' + str(ev.port.dpid)
        pid = s + "_port" + str(ev.port.port_no)
        cmd = """
        PREFIX of: <http://home.eps.hw.ac.uk/~qz1/>
        delete {%s of:isUP ?p}
        insert {%s of:isUP %s}
        where  {%s of:isUP ?p}
        """ % (pid, pid, ev.port.is_live(), pid)
        self.backend.update(cmd)

        return

    @set_ev_cls(event.EventLinkAdd)
    def topo_link_add(self, ev):
        # TODO links have directionality. This state introduces a lot of redundancy
        g = Graph()
        sid = 's' + str(ev.link.src.dpid)
        spid = sid + "_port" + str(ev.link.src.port_no)
        did = 's' + str(ev.link.dst.dpid)
        dpid = did + "_port" + str(ev.link.dst.port_no)
        linkid = "link_" + spid + "_" + dpid
        LOG.debug("found new link %s %s" % (spid, dpid))
        g.add( (self.ns[spid], self.ns.connectToPort,
                self.ns[dpid])  )
#        g.add( (self.ns[dpid], self.ns.connectToPort,
#                self.ns[spid])  )
        g.add( (self.ns[linkid], RDF.type, self.ns['Link'])  )
        g.add( (self.ns[linkid], self.ns.hasSrcPort,
                self.ns[spid])  )
        g.add( (self.ns[linkid], self.ns.hasDstPort,
                self.ns[dpid])  )
        g.add( (self.ns[linkid], self.ns.isEnabled, Literal(True))  )
        g.add( (self.ns[linkid], self.ns.hasCapacity, Literal(1000000000) ) )
        g.add( (self.ns[linkid], self.ns.hasLoad, Literal(0) ) )

##        g.add( (self.ns[linkid], self.ns.connectToPort,
#                self.ns[spid])  )
        self.backend.insert_tuples(g)
        return

    @set_ev_cls(event.EventLinkDelete)
    def topo_link_remove(self, ev):
        sid = 's' + str(ev.link.src.dpid)
        spid = sid + "_port" + str(ev.link.src.port_no)
        did = 's' + str(ev.link.dst.dpid)
        dpid = did + "_port" + str(ev.link.dst.port_no)
        linkid = "of:link_" + spid + "_" + dpid
        LOG.info("link %s was removed"%(linkid))
        cmd = """
        PREFIX of: <http://home.eps.hw.ac.uk/~qz1/>
        delete {
            %s of:isEnabled True.
            ?port1 of:connectToPort ?port2.
        }
        insert {%s of:isEnabled False.}
        where {
            %s rdf:type of:Link;
                  ?v ?p;
                  of:dhasSrcPort ?port1;
                  of:hasDstPort ?port2.
          FILTER(?port1!=?port2)
        }
        """ % (linkid, linkid, linkid)
        self.backend.update(cmd)

        return

#    @set_ev_cls(event.EventHostAdd)
    def topo_host_add(self, ev):
        h = ev.host
        g = Graph()
        swid = 's' + str(h.port.dpid)
        hid = swid + "_host_" + str(h.mac)
        pid = swid + "_port" + str(h.port.port_no)
        LOG.debug("sw %s host %s %s", h.port.dpid, hid, h.mac)
        g.add( (self.ns[hid], RDF.type, self.ns['Host'])  )
        g.add( (self.ns[hid], self.ns.connectToPort, self.ns[pid]) )
        g.add( (self.ns[pid], self.ns.connectToPort, self.ns[hid]) )
        for ip in h.ipv4:
            g.add( (self.ns[hid], self.ns.hasIPv4, Literal(ip)) )
        g.add( (self.ns[hid], self.ns.hasMAC,  Literal(h.mac)) )
        self.backend.insert_tuples(g)
        return

    def export_loop(self):
        while self.is_active:
            self.export_event.clear()
#           LOG.debug("periodic event fired!")
            g = Graph()
            hosts = self.get_hosts()
            hid_gen = 0
            for h in hosts:
                hid_gen += 1
                swid = 's' + str(h.port.dpid)
                hid = swid + "_host" + str(hid_gen)
                pid = swid + "_port" + str(h.port.port_no)
                LOG.debug("sw %s host %s %s", h.port.dpid, hid, h.mac)
                g.add( (self.ns[hid], RDF.type, self.ns['Host'])  )
#                 g.add( (self.ns[swid], self.ns.hasHost, self.ns[hid]) )

                g.add( (self.ns[hid], self.ns.connectToPort, self.ns[pid]) )
                g.add( (self.ns[pid], self.ns.connectToPort, self.ns[hid]) )
                for ip in h.ipv4:
                    g.add( (self.ns[hid], self.ns.hasIPv4, Literal(ip)) )
                g.add( (self.ns[hid], self.ns.hasMAC,  Literal(h.mac)) )

            # rep = self.send_request(EventInsertTuples(g))i
            self.backend.insert_tuples(g)
            self.export_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)

    def close(self):
        self.is_active = False
        self.export_event.set()
        hub.joinall(self.threads)

    def get_hosts(self):
        rep = self.send_request(event.EventHostRequest(None))
        return rep.hosts
