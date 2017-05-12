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

from rdflib import Graph, URIRef

from rdflib import Literal, Namespace
from rdflib.plugins.stores import sparqlstore
from rdflib.namespace import RDF
from os import system

LOG = logging.getLogger("StardogBackend")

class StardogBackend(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(StardogBackend, self).__init__(*args, **kwargs)
        self.name = 'stardogBackend'
        self.db = "test-haris"
        self.endpoint = 'http://10.30.65.148:5820/%s/query'%(self.db)
        self.store = sparqlstore.SPARQLUpdateStore()
        self.store.open((self.endpoint, self.endpoint))
        self.store.setCredentials('admin', 'admin')
        self.default_graph = URIRef('http://home.eps.hw.ac.uk/~qz1/')
        self.ns = Namespace('http://home.eps.hw.ac.uk/~qz1/')
        self.ng = Graph(self.store, identifier=self.default_graph)

        # Dirty hack to cleat the db upon restart
        system('curl -X POST -d "query=CLEAR ALL" "http://admin:admin@10.30.65.148:5820/%s/query"'%(self.db))

        g = Graph()
        g.parse("/home/ubuntu/ryu-haris/ryu/app/sardonic-v3.ttl", format="n3")
        self.insert_tuples(g)
        return

    def insert_tuples(self, g):
        cmd = (u'INSERT DATA { %s  }' % (
                   g.serialize(format='n3')
        ))
        self.store.update(cmd)
        self.store.commit()
        return True

    def update(self, cmd):
        self.store.update(cmd)
        return self.store.commit()

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
        ?flid of:isIn of:%s;
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


    def add_path_flow_state(self, id, dpid, priority, match, actions, hopCount, pathid):
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
        g.add( (self.ns[flid], self.ns.hopCount,       Literal(hopCount)) )
        g.add( (self.ns[flid], self.ns.path,       self.ns[pathid]) )
        g.add( (self.ns[pathid], self.ns.hasFlow,  self.ns[flid] )   )


        for (field, val) in match.iteritems():
            g.add( (self.ns[flid], self.ns[field], Literal(val) ) )

        action_count = 0
        for action in actions:
            actid = flid + '_action' + str(action_count)
            g.add( (self.ns[flid], self.ns.hasAction, self.ns[actid]) )
            if action.type == 0:
                pid = sid + "_port" + str(action.port)
                g.add( (self.ns[actid], RDF.type, self.ns['ActionOutput']) )
                g.add( (self.ns[actid], self.ns.toPort, self.ns[pid] ) )
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
                g.add( (self.ns[actid], self.ns.toPort, self.ns[pid] ) )
                action_count = action_count + 1

        self.insert_tuples(g)



