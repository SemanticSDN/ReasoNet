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
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch,OFPActionOutput, OFPInstructionActions
import ryu.ofproto.ofproto_v1_3 as ofproto

from rdflib import Graph, URIRef
from rdflib import Literal, Namespace
from rdflib.plugins.stores import sparqlstore
from rdflib.namespace import RDF
from rdflib.query import Result

import StringIO
from os import system

from requests_toolbelt.multipart import decoder
import requests


LOG = logging.getLogger("StardogBackend")

mappings = {
    "in_port"        : ofproto.OXM_OF_IN_PORT,
    "in_phy_port"    : ofproto.OXM_OF_IN_PHY_PORT,
    "dl_dst"         : ofproto.OXM_OF_ETH_DST,
    "dl_src"         : ofproto.OXM_OF_ETH_SRC,
    "dl_type"        : ofproto.OXM_OF_ETH_TYPE,
    "eth_dst"        : ofproto.OXM_OF_ETH_DST,
    "eth_src"        : ofproto.OXM_OF_ETH_SRC,
    "eth_type"       : ofproto.OXM_OF_ETH_TYPE,
    "vlan_vid"       : ofproto.OXM_OF_VLAN_VID,
    "vlan_pcp"       : ofproto.OXM_OF_VLAN_PCP,
    "ip_dscp"        : ofproto.OXM_OF_IP_DSCP,
    "ip_ecn"         : ofproto.OXM_OF_IP_ECN,
    "ip_proto"       : ofproto.OXM_OF_IP_PROTO,
    "ipv4_src"       : ofproto.OXM_OF_IPV4_SRC,
    "ipv4_dst"       : ofproto.OXM_OF_IPV4_DST,
    "tcp_src"        : ofproto.OXM_OF_TCP_SRC,
    "tcp_dst"        : ofproto.OXM_OF_TCP_DST,
    "udp_src"        : ofproto.OXM_OF_UDP_SRC,
    "udp_dst"        : ofproto.OXM_OF_UDP_DST,
    "sctp_src"       : ofproto.OXM_OF_SCTP_SRC,
    "sctp_dst"       : ofproto.OXM_OF_SCTP_DST,
    "icmpv4_type"    : ofproto.OXM_OF_ICMPV4_TYPE,
    "icmpv4_code"    : ofproto.OXM_OF_ICMPV4_CODE,
    "arp_opcode"     : ofproto.OXM_OF_ARP_OP,
    "arp_spa"        : ofproto.OXM_OF_ARP_SPA,
    "arp_tpa"        : ofproto.OXM_OF_ARP_TPA,
    "arp_sha"        : ofproto.OXM_OF_ARP_SHA,
    "arp_tha"        : ofproto.OXM_OF_ARP_THA,
    "ipv6_src"       : ofproto.OXM_OF_IPV6_SRC,
    "ipv6_dst"       : ofproto.OXM_OF_IPV6_DST,
    "ipv6_flabel"    : ofproto.OXM_OF_IPV6_FLABEL,
    "icmpv6_type"    : ofproto.OXM_OF_ICMPV6_TYPE,
    "icmpv6_code"    : ofproto.OXM_OF_ICMPV6_CODE,
    "ipv6_nd_target" : ofproto.OXM_OF_IPV6_ND_TARGET,
    "ipv6_nd_sll"    : ofproto.OXM_OF_IPV6_ND_SLL,
    "ipv6_nd_tll"    : ofproto.OXM_OF_IPV6_ND_TLL,
    "mpls_label"     : ofproto.OXM_OF_MPLS_LABEL,
    "mpls_tc"        : ofproto.OXM_OF_MPLS_TC,
    "mpls_bos"       : ofproto.OXM_OF_MPLS_BOS,
    "pbb_isid"       : ofproto.OXM_OF_PBB_ISID,
    "tunnel_id"      : ofproto.OXM_OF_TUNNEL_ID,
    "ipv6_exthdr"    : ofproto.OXM_OF_IPV6_EXTHDR,
    "ipv6_exthdr_masked" : ofproto.OXM_OF_IPV6_EXTHDR
}


class StardogBackend(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(StardogBackend, self).__init__(*args, **kwargs)
        self.name = 'stardogBackend'
        self.db = "test-haris"
        self.endpoint = 'http://localhost:5820/%s/query'%(self.db)
        self.updateEndpoint = 'http://localhost:5820/%s/update'%(self.db)
        self.store = sparqlstore.SPARQLUpdateStore()
        self.store.open((self.endpoint, self.updateEndpoint))
        self.store.setCredentials('admin', 'admin')
        self.default_graph = URIRef('http://home.eps.hw.ac.uk/~qz1/')
        self.ns = Namespace('http://home.eps.hw.ac.uk/~qz1/')
        self.ng = Graph(self.store, identifier=self.default_graph)

        # Dirty hack to cleat the db upon restart
        system('curl -X POST -d "query=CLEAR ALL" "http://admin:admin@localhost:5820/%s/update"'%(self.db))

        g = Graph()
        g.parse("/home/vagrant/ryu-haris/ryu/app/sardonic-v9.ttl", format="n3")
        self.insert_tuples(g)
        self.cb_violations = {}
        return

    def register_violation_callback(self, typ, cb, obj):
        self.cb_violations[typ] = {"cb": cb, "self": obj}

    def insert_tuples(self, g):
        cmd = (u'INSERT DATA { %s  }' % (
                   g.serialize(format='n3')
        ))
        self.store.update(cmd)
        self.store.commit()
        return True

    def check_violations(self):
        res = []
        headers = {
            'Content-Type': 'application/x-turtle, text/turtle, application/rdf+xml'
        }
        req = requests.post('http://admin:admin@localhost:5820/test-haris/icv/violations',
                            headers=headers)

        resp = decoder.MultipartDecoder.from_response(req)
        for p in resp.parts:
            print(p.headers)
            #if "rdf+xml" in p.headers["Content-Type"]:
            #    g = Graph()
            #    g.parse(data=p.content, format=p.headers["Content-Type"])
            if "sparql-result" in p.headers["Content-Type"]:
                g = Result('SELECT')
                g = g.parse(StringIO.StringIO(p.content)) # , format=p.headers["Content-Type"])
                for r in g:
                    res.append({"type":"path", "entity": r["path"]})
        return res

    def update(self, cmd):
        self.store.update(cmd)
        self.store.commit()
        icvs = self.check_violations()
        for icv in icvs:
            print("fixing violation " + str(icv))
            self.cb_violations[icv["type"]]["cb"](self.cb_violations[icv["type"]]["self"], icv["entity"])

        return ()

#    @set_ev_cls(EventInsertTuples)
#    def _insert_tuple_handler(self, ev):
##        print('received request to insert tuples %s ' % ev.g.serialize(format='nt'))
#        res = self.insert_tuples(ev.g)
#        rep = EventInsertTuplesReply(ev.src, res)
#        self.reply_to_request(ev, rep)
#        return

    def remove_switch(self, id):
        cmd = """
        PREFIX of: <http://home.eps.hw.ac.uk/~qz1/>

        delete {
        of:%s ?sprop ?sval.
        ?flid ?flprop ?flval
        } where {
        of:%s ?sprop ?sval.
        ?-1flid of:isIn of:%s;
        ?flprop ?flval
        }
        """ % (id, id, id)
        self.store.update(cmd)
        return self.store.commit()


    def get_mac_of_host(self, ip):
        # run a query to get MAC address
        rq = """
        PREFIX : <http://home.eps.hw.ac.uk/~qz1/>
        SELECT distinct ?host ?mac
        WHERE {
        { ?host a :Host .
        ?host :hasIPv4 '%s'.
        ?host :hasMAC ?mac
        }
        }
        """ % (ip)
        res = self.store.query(rq)
        if len(res) == 0:
            LOG.error("Failed to find host with IP addr %s"%(ip))
            return None

        dst_host, dst_mac = next(iter(res))
        return (dst_host, dst_mac)

    def get_semantic_flows(self):
        rq = """
        PREFIX : <http://home.eps.hw.ac.uk/~qz1/>
        select ?p ?param ?val
        where
        {
          {
            ?p rdf:type/rdfs:subClassOf* of:Flow;
            ?param ?val.
          }
          UNION
          {
          ?flow rdf:type/rdfs:subClassOf* of:Flow;
              of:hasAction ?p.
            ?p ?param ?val.
          }
          UNION
          {
          ?p rdf:type/rdfs:subClassOf* of:Flow.
            ?sw ?param ?p.
            ?sw :hasID ?val.
          }
        }
        """
        res = self.store.query(rq)
        flows = {}
        actions = {}
        ret = {}

        for (a, b, c) in res:
            a = a.replace("http://home.eps.hw.ac.uk/~qz1/", "").encode()
            b = b.replace("http://home.eps.hw.ac.uk/~qz1/", "").encode()
            c = c.replace("http://home.eps.hw.ac.uk/~qz1/", "").encode()
            LOG.debug("%s %s %s" % (a,b,c))
            if "hasAction" in b:
                actions[c] = a
            if "_action" in a:
                if a not in flows[actions[a]]["actions"]:
                    flows[actions[a]]["actions"][a] = {}
                flows[actions[a]]["actions"][a][b] = c
            else:
                if a not in flows:
                    # We need a datapath here
                    flows[a] = {"match": {}, "datapath": None, "actions":{}}

                if b in mappings:
                    if b in ["in_port"]:
                        flows[a]["match"][b] = int(c) # append_field(self.match_map[b], c)
                    else:
                        flows[a]["match"][b] = c # append_field(self.match_map[b], c)
                if "hasFlow" in b:
                    flows[a]["datapath"] = int(c)
        for a in flows:
            dpid = flows[a]["datapath"]
            if dpid not in ret:
                ret[dpid] = []
            flow_act = []
            for act in flows[a]["actions"]:
                action = flows[a]["actions"][act]
                if action["http://www.w3.org/1999/02/22-rdf-syntax-ns#type"] == "ActionOutput":
                    flow_act.append(OFPActionOutput(int(action["toPort"]), max_len=0xffff))
            flow_act = [OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_act)]
            # flows[a]["match"] = OFPMatch(**flows[a]["match"])
            ret[dpid].append({"actions":flow_act, "match":OFPMatch(**flows[a]["match"])})
        return ret



    def _check_inconsistent_flow(self):
        # check if the link is down but the corresponding flow is still forwarding
        qstr = """
        @PREFIX : <http://home.eps.hw.ac.uk/~qz1/> .
        @PREFIX xsd: <http://www.w3.org/2001/XMLSchema#> .

        SELECT ?port1 ?port2
        WHERE {
            ?l a :Link;
                :hasStatus "(MISSING MISSING)"^^xsd:String; # find the down links
                :linkTo ?p1;
                :linkTo ?p2.
            filter (?p1 != ?p2).

            ?p1 :hasMAC ?p1_mac;
                :hasIP ?p1_ip.

            ?p2 :hasMAC ?p2_mac;
                :hasIP ?p2_ip.

            ?f a :Flow;
                :hasInPort ?p1;
                :hasDstAddr ?p2_ip;
                :hasAction ?a.

            ?a a :hasAction;
                :hasType "output"^^xsd:String; # find the flows of the link that are still forwarding

            bind (strafter(str(?p1), "http://home.eps.hw.ac.uk/~qz1/") as ?port1).
            bind (strafter(str(?p2), "http://home.eps.hw.ac.uk/~qz1/") as ?port2).
        }
        """
        result = self.store.query(qstr)
        if len(result) == 0:
            LOG.error("Failed to check flow consistency with links")
            return None

        port1, port2 = next(iter(result))
        return (port1, port2)

    def add_path_state(self, src_mac, dst_mac):
        rq = """
        PREFIX of: <http://home.eps.hw.ac.uk/~qz1/>

        insert {
            of:path_%s_%s a of:Path;
            of:hasSrc ?host1;
            of:hasDst ?host2;
            of:hasActive of:path_%s_%s_1.
        }
        where {
            ?host1 a of:Host; of:hasMAC "%s".
            ?host2 a of:Host; of:hasMAC "%s".
        }
        """ % (src_mac, dst_mac, src_mac, dst_mac, src_mac, dst_mac)
        res = self.store.update(rq)

        return res

    def check_path_exists(self, src_mac, dst_mac):
        rq = """
        PREFIX of: <http://home.eps.hw.ac.uk/~qz1/>

        ask {
        {
            ?path a of:Path;
                of:hasSrc ?host1;
                of:hasDst ?host2.
            ?host1 a of:Host;
                of:hasMAC "%s".
            ?host2 a of:Host;
                of:hasMAC "%s".
        }
        UNION
        {
            ?path a of:Path;
                of:hasSrc ?host1;
                of:hasDst ?host2.
            ?host1 a of:Host;
                of:hasMAC "%s".
            ?host2 a of:Host;
                of:hasMAC "%s".
                }
        }
        """ % (src_mac, dst_mac, dst_mac, src_mac)
        res = self.store.query(rq)
        return bool(res)


    def add_path_flow_state(self, id, dpid, priority, match, actions, pathhopid):
        g = Graph()
        sid = 's' + str(dpid)
        flid = 's' + str(dpid) + '_flow' + str(id)
        g.add( (self.ns[sid], self.ns.hasFlow,       self.ns[flid]) )
        g.add( (self.ns[flid], RDF.type,             self.ns['PathFlow']) )
        g.add( (self.ns[flid], self.ns.priority,     Literal(priority)) )
        g.add( (self.ns[flid], self.ns.hard_timeout, Literal(0)) )
        g.add( (self.ns[flid], self.ns.idle_timeout, Literal(0)) )
        g.add( (self.ns[flid], self.ns.flags,        Literal(0)) )
        g.add( (self.ns[flid], self.ns.table_id,     Literal(0)) )
        g.add( (self.ns[flid], self.ns.cookie,       Literal(id)) )
        g.add( (self.ns[flid], self.ns.hasPathHop,   self.ns[pathhopid]))
#        g.add( (self.ns[flid], self.ns.path,       self.ns[pathhopid]) )
        # g.add( (self.ns[pathid], self.ns.hasFlow,  self.ns[flid] )   )


        for (field, val) in match.iteritems():
            g.add( (self.ns[flid], self.ns[field], Literal(val) ) )

        action_count = 0
        for action in actions:
            actid = flid + '_action' + str(action_count)
            g.add( (self.ns[flid], self.ns.hasAction, self.ns[actid]) )
            if action.type == 0:
                pid = sid + "_port" + str(action.port)
                g.add( (self.ns[actid], RDF.type, self.ns['ActionOutput']) )
                g.add( (self.ns[actid], self.ns.toPort, Literal(action.port) ))
                action_count = action_count + 1
#            elif action.type ==

        self.insert_tuples(g)

    def add_flow_state(self, id, dpid, priority, match, actions):

        g = Graph()
        sid = 's' + str(dpid)
        flid = 's' + str(dpid) + '_flow' + str(id)
        g.add( (self.ns[sid], self.ns.hasFlow,       self.ns[flid]) )
        g.add( (self.ns[flid], RDF.type,             self.ns['Flow']) )
        g.add( (self.ns[flid], self.ns.priority,     Literal(priority)) )
        g.add( (self.ns[flid], self.ns.hard_timeout, Literal(0)) )
        g.add( (self.ns[flid], self.ns.idle_timeout, Literal(0)) )
        g.add( (self.ns[flid], self.ns.flags,        Literal(0)) )
        g.add( (self.ns[flid], self.ns.table_id,     Literal(0)) )
        g.add( (self.ns[flid], self.ns.cookie,       Literal(id)) )

        for (field, val) in match.iteritems():
            g.add( (self.ns[flid], self.ns[field], Literal(val) ) )

        action_count = 0
        for action in actions:
            actid = flid + '_action' + str(action_count)
            pid = sid + "_port" + str(action.port)
            g.add( (self.ns[flid], self.ns.hasAction, self.ns[actid]) )
            if action.type == 0:
                g.add( (self.ns[actid], RDF.type, self.ns['ActionOutput']) )
                g.add( (self.ns[actid], self.ns.toPort, Literal(action.port) ) )
                action_count = action_count + 1

        self.insert_tuples(g)



