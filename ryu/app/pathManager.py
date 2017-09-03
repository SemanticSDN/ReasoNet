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
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.controller import dpset

from ryu.app.stardogBackend import StardogBackend
from ryu.app.flowManager import FlowManager
from rdflib import Literal, Namespace, Graph
from rdflib.namespace import RDF

import json
import urllib2


LOG = logging.getLogger("PathComputation")


class PathManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'backend': StardogBackend,
        'flowManager': FlowManager
    }

    def __init__(self, *args, **kwargs):
        super(PathManager, self).__init__(*args, **kwargs)
        self.backend = kwargs["backend"]
        self.flowManager = kwargs["flowManager"]
        self.dps = {}
        self.ofctl = ofctl_v1_3
        self.ns = Namespace('http://home.eps.hw.ac.uk/~qz1/')
        self.backend.register_violation_callback("path", PathManager.fix_violation, self)

    def set_backend(self, backend, manager):
        self.backend = backend
        self.flowManager = manager

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        LOG.debug("Got a switch in path computation")
        if ev.enter:
            self.dps[ev.dp.id] = ev.dp
        else:
            del self.dps[ev.dp.id]

    def get_paths(self, src_mac, dst_mac, bw=None):
        ret = []
        url = "http://localhost:8182"
        values = {
            "gremlin": 'g.V().has("http://home.eps.hw.ac.uk/~qz1/hasMAC", src_mac).' +
            'out("http://home.eps.hw.ac.uk/~qz1/connectToPort").' +
            'repeat(__.in("http://home.eps.hw.ac.uk/~qz1/hasPort").' +
            'out("http://home.eps.hw.ac.uk/~qz1/hasPort").' +
            'out("http://home.eps.hw.ac.uk/~qz1/connectToPort").simplePath()).' +
            'until(has("http://home.eps.hw.ac.uk/~qz1/hasMAC", dst_mac)).path()',
            "bindings": {"src_mac": src_mac, "dst_mac": dst_mac}
        }
        values = {
            "gremlin": 'g.V().has("http://home.eps.hw.ac.uk/~qz1/hasMAC", src_mac).'+
            'out("http://home.eps.hw.ac.uk/~qz1/connectToPort").'+
            'times(5).'+
            'repeat(__.in("http://home.eps.hw.ac.uk/~qz1/hasPort").'+
            'out("http://home.eps.hw.ac.uk/~qz1/hasPort").'+
            'out("http://home.eps.hw.ac.uk/~qz1/connectToPort").'+
            'simplePath()).'+
            'emit(has("http://home.eps.hw.ac.uk/~qz1/hasMAC", dst_mac)).'+
            'has("http://home.eps.hw.ac.uk/~qz1/hasMAC", dst_mac).path()',
            "bindings": {"src_mac": src_mac, "dst_mac": dst_mac}
        }

        req = urllib2.Request(url, json.dumps(values))
        response = urllib2.urlopen(req)
        res = response.read()

        res = json.loads(res)
        ret = []
        for data in res["result"]["data"]:
            data = data["objects"]
            count = len(data)
            ix = 1
            path = []
            while ix < count - 1:
                src_port = data[ix]["properties"]
                dst_port = data[ix+2]["properties"]
                sw = data[ix+1]["properties"]
                dpid = int(sw["http://home.eps.hw.ac.uk/~qz1/hasID"][0]["value"])
                src_port_no = int(src_port["http://home.eps.hw.ac.uk/~qz1/port_no"][0]["value"])
                dst_port_no = int(dst_port["http://home.eps.hw.ac.uk/~qz1/port_no"][0]["value"])
                path.append((src_port_no, dpid, dst_port_no))
                ix = ix + 3
            ret.append(path)
        return ret

    def add_path(self, src_mac, dst_mac, buffer_id, bw=None):
        LOG.info("Looking for a path between \'%s\' and \'%s\'" % (src_mac, dst_mac))
        if self.backend.check_path_exists(src_mac, dst_mac):
            LOG.info("path between \'%s\' and \'%s\' already exists" % (src_mac, dst_mac))
            return

        self.backend.add_path_state(src_mac, dst_mac)
        self.backend.add_path_state(dst_mac, src_mac)

        paths = self.get_paths(src_mac, dst_mac, bw=bw)

        if paths is None or len(paths) == 0:
            LOG.error("No path found between \'%s\' and \'%s\'" % (src_mac, dst_mac))
            return

        path = paths[0]
        hop_count = len(path)
        for (src_port, dpid, dst_port) in reversed(path):
            if dpid in self.dps:
                pathhopid = "path_%s_%s_1_%d" % (src_mac, dst_mac, hop_count)
                print("XXXXXXXXXXXXXXX %s XXXXXXXXXXXXXXX" % (pathhopid))
                self._insert_host_connect_flows(self.dps[dpid], buffer_id,
                                                src_port, src_mac,
                                                dst_port, dst_mac, pathhopid, bw=bw)
                hop_count = hop_count - 1
        hop_count = 1
        for (src_port, dpid, dst_port) in path:
            # setup inverse path
            if dpid in self.dps:
                pathhopid = "path_%s_%s_1_%d"%(dst_mac, src_mac, hop_count)
                self._insert_host_connect_flows(self.dps[dpid],
                                                self.dps[dpid].ofproto.OFP_NO_BUFFER,
                                                dst_port, dst_mac,
                                                src_port, src_mac, pathhopid, bw=bw)
                hop_count = hop_count + 1

        path_count = 0
        active = True
        for path in paths:
            path_count = path_count + 1
            self.add_avail_path(path, src_mac, dst_mac, path_count, active)
            rev_path = self.reverse_list(path)
            self.add_avail_path(rev_path, dst_mac, src_mac, path_count, active)
            active = False

    def fix_violation(self, path):
        q = """
select ?ix1 (?hop2 as ?hasPathHop)
(?host1_mac as ?eth_src)  (?host2_mac as ?eth_dst)
(?port1_no as ?in_port) (?port2_no as ?to_port) ?swid
where
{
  BIND ( <%s> as ?path)
  ?path a of:Path;
          of:hasSrc ?host1;
          of:hasDst ?host2.
  {
    select ?availPath (COUNT(?hop) as ?hop) (GROUP_CONCAT(?status) as ?status)
         {
    ?availPath a of:AvailPath;
        of:realizes <%s>.

    ?hop a of:PathHop;
        of:belongs ?availPath;
        of:hasLink ?link.

    ?link a of:Link;
        of:isEnabled ?status.
        }
     GROUP BY ?availPath
    HAVING(! CONTAINS(UCASE(?status), "FALSE"))
    ORDER BY ?hop
    LIMIT 1
    }
{
  ?hop1 of:belongs ?availPath;
        of:hasIX ?ix1;
        of:hasLink ?link1;
        a of:PathHop.
  ?hop2 of:belongs ?availPath;
        of:hasIX ?ix2;
        of:hasLink ?link2;
        a of:PathHop.
  FILTER( ?ix1 = ?ix2 - 1)
} UNION {
  ?link1 of:hasDstPort ?port1;
        of:hasSrcPort ?host1.
  ?hop2 of:belongs ?availPath;
        of:hasIX 1;
        of:hasLink ?link2;
        a of:PathHop.
  values ?ix1 {0}.
  }
  ?link1 of:hasDstPort ?port1.
  ?link2 of:hasSrcPort ?port2.
  ?host1 of:hasMAC ?host1_mac.
  ?host2 of:hasMAC ?host2_mac.
  ?port1 of:port_no ?port1_no.
  ?port2 of:port_no ?port2_no.
  ?sw of:hasPort ?port2;
        of:hasID ?swid.
  }
        """ % (path, path)
        res = self.backend.store.query(q)
        for (_, pathhopid, src_mac, dst_mac, src_port, dst_port, dpid) in res:
            print(str(pathhopid), str(src_mac), str(dst_mac), str(src_port), str(dst_port), str(dpid))
            # self._insert_host_connect_flows(self.dps[int(dpid)], self.dps[int(dpid)].ofproto.OFP_NO_BUFFER,
            #                                    int(src_port), str(src_mac),
            #                                    int(dst_port), str(dst_mac), str(pathhopid), bw=None)
            datapath = self.dps[int(dpid)]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(in_port=int(src_port), eth_dst=str(dst_mac), eth_src=str(src_mac))
            actions = [parser.OFPActionOutput(int(dst_port),ofproto.OFPCML_NO_BUFFER )]
            self.flowManager.flow_count = self.flowManager.flow_count + 1
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.flowManager._add_flow(datapath, 1, match, inst, ofproto.OFP_NO_BUFFER)

        q = """
delete {
  ?flow ?v ?p.
  ?action ?action_v ?action_p.
  ?sw of:hasFlow ?flow.
  ?avail of:hasState "Active".
  }
insert {
  ?avail of:hasState "Inactive".
}
where
{
  ?avail a of:AvailPath;
     of:hasState "Active";
     of:realizes <%s>.
  ?hop of:belongs ?avail;
    a of:PathHop.
  ?flow a of:PathFlow
   ; of:hasPathHop ?hop
   ; of:hasAction ?action
   ; ?v ?p
          .
   ?action ?action_v ?action_p.
   ?sw of:hasFlow ?flow.
}
        """%(path)
        res = self.backend.store.update(q)
        res = self.backend.store.commit()
        q = """

delete {
  ?availPath of:hasState "Inactive".
}
insert {
   ?id a of:PathFlow;
        of:priority 0;
        of:hard_timeout 0;
        of:idle_timeout 0;
        of:flags 0;
        of:table_id 0;
        of:cookie 0;
        of:hasPathHop ?hop2;
        of:eth_src ?host1_mac;
        of:eth_dst ?host2_mac;
        of:in_port ?port1_no;
        of:hasAction ?actid.
  ?swid of:hasFlow ?id.
  ?actid a of:ActionOutput;
           of:toPort ?port2_no.
  ?availPath of:hasState "Active".
  }
where
{
  BIND ( <%s> as ?path)
  ?path a of:Path;
          of:hasSrc ?host1;
          of:hasDst ?host2.
  {
    select ?availPath (COUNT(?hop) as ?hop) (GROUP_CONCAT(?status) as ?status)
         {
    ?availPath a of:AvailPath;
        of:hasState "Inactive";
        of:realizes <%s>.

    ?hop a of:PathHop;
        of:belongs ?availPath;
        of:hasLink ?link.

    ?link a of:Link;
        of:isEnabled ?status.
        }
     GROUP BY ?availPath
    HAVING(! CONTAINS(UCASE(?status), "FALSE"))
    ORDER BY ?hop
    LIMIT 1
    }
{
  ?hop1 of:belongs ?availPath;
        of:hasIX ?ix1;
        of:hasLink ?link1;
        a of:PathHop.
  ?hop2 of:belongs ?availPath;
        of:hasIX ?ix2;
        of:hasLink ?link2;
        a of:PathHop.
  BIND (IRI(REPLACE(STR(UUID()), "urn:uuid:", "of:flow_")) as ?id).
  BIND (IRI(CONCAT(STR(?id), "_action0")) as ?actid).
  FILTER( ?ix1 = ?ix2 - 1)
} UNION {
  ?link1 of:hasDstPort ?port1;
        of:hasSrcPort ?host1.
  ?hop2 of:belongs ?availPath;
        of:hasIX 1;
        of:hasLink ?link2;
        a of:PathHop.
  values ?ix1 {0}.
  BIND (IRI(REPLACE(STR(UUID()), "urn:uuid:", "of:flow_")) as ?id).
  BIND (IRI(CONCAT(STR(?id), "_action0")) as ?actid).
  }
  ?link1 of:hasDstPort ?port1.
  ?link2 of:hasSrcPort ?port2.
  ?host1 of:hasMAC ?host1_mac.
  ?host2 of:hasMAC ?host2_mac.
  ?port1 of:port_no ?port1_no.
  ?port2 of:port_no ?port2_no.
  ?swid of:hasPort ?port2.
  }
  """%(path, path)
        res = self.backend.store.update(q)
        res = self.backend.store.commit()


    def reverse_list(self, path):
        ret = []
        for (src, sw,dst) in reversed(path):
            ret.append((dst, sw, src))
        return ret

    def add_avail_path(self, path, smac, dmac, id, active):
        g = Graph()

        avpathid = "path_%s_%s_%d"%(smac, dmac, id)
        pathid = "path_%s_%s"%(smac, dmac)
        g.add( (self.ns[avpathid], RDF.type, self.ns['AvailPath']) )
        g.add( (self.ns[avpathid], self.ns.realizes, self.ns[pathid]) )
        if active:
            g.add( (self.ns[avpathid], self.ns.hasState, Literal("Active")) )
        else:
            g.add( (self.ns[avpathid], self.ns.hasState, Literal("Inactive")) )
        print(path)

        ix = 0
        while ix < len(path)-1:
            pathhopid = "path_%s_%s_%d_%d"%(smac, dmac, id, ix+1)
            (_, src_switch, src_port) = path[ix]
            (dst_port, dst_switch, _) = path[ix + 1]
            linkid = "link_s%d_port%d_s%d_port%d" %(src_switch, src_port, dst_switch, dst_port)
            LOG.info(linkid)
            g.add( (self.ns[pathhopid], RDF.type, self.ns['PathHop']) )
            g.add( (self.ns[pathhopid], self.ns.hasLink, self.ns[linkid]) )
            g.add( (self.ns[pathhopid], self.ns.belongs, self.ns[avpathid]) )
            g.add( (self.ns[pathhopid], self.ns.hasIX, Literal(ix + 1) ) )
            ix = ix + 1
        (_, src_sw, src_port) = path[ix]
        linkid = "link_s%d_port%s_s%d_host%s" %(src_sw, src_port, src_sw, dmac)
        LOG.info(linkid)
        pathhopid = "path_%s_%s_%d_%d"%(smac, dmac, id, ix+1)
        g.add( (self.ns[pathhopid], RDF.type, self.ns['PathHop']) )
        g.add( (self.ns[pathhopid], self.ns.hasLink, self.ns[linkid]) )
        g.add( (self.ns[pathhopid], self.ns.belongs, self.ns[avpathid]) )
        g.add( (self.ns[pathhopid], self.ns.hasIX, Literal(ix + 1) ) )

        self.backend.insert_tuples(g)

    def _insert_host_connect_flows(self, dp, buffer_id, src_port, src_mac, dst_port, dst_mac,
                                   pathhopid, bw=None):
        parser = dp.ofproto_parser
        match = parser.OFPMatch(in_port=src_port, eth_dst=dst_mac, eth_src=src_mac)
        return self.flowManager.add_path_flow(pathhopid, dp, priority=1, match=match,
                                              buffer_id=buffer_id, output=dst_port,
                                              queue=bw)

#    def add_flow(self, datapath, priority, match, actions, buffer_id):
#        ofproto = datapath.ofproto
#        parser = datapath.ofproto_parser
#
#        self.backend.add_flow_state(datapath.id, priority, match, actions)
#
#        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
#        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
#                                instructions=inst, buffer_id=buffer_id)
#        return datapath.send_msg(mod)


