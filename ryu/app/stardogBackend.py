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
from ryu.topology import switches
from ryu.controller import event
from ryu.ofproto import ofproto_v1_3

from rdflib import Graph, Literal, URIRef, Namespace
from rdflib.plugins.stores import sparqlstore
from rdflib.namespace import RDF
from os import system

LOG = logging.getLogger("StardogBackend")

class EventInsertTuples(event.EventRequestBase):
    def __init__(self, g):
        super(EventInsertTuples, self).__init__()
        self.dst = 'stardogBackend'
        self.g = g

    def __str__(self):
        return 'EventInsertTuples<%s>' % (str(self.g.serialize(format='nt')))

class EventInsertTuplesReply(event.EventReplyBase):
    def __init__(self, dst, result):
        super(EventInsertTuplesReply, self).__init__(dst)
        self.result = result

    def __str__(self):
        return ("EventInsertTuplesReply<dst=%s,%s>" %
                (self.dst, self.result))

class StardogBackend(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

   # _EVENTS = [EventInsertTuples]

    _CONTEXTS = {
        'switches': switches.Switches
    }

    def __init__(self, *args, **kwargs):
        super(StardogBackend, self).__init__(*args, **kwargs)
        self.name = 'stardogBackend'
        self.endpoint = 'http://172.18.2.106:5820/test/query'
        self.store = sparqlstore.SPARQLUpdateStore()
        self.store.open((self.endpoint, self.endpoint))
        self.store.setCredentials('admin', 'admin')
        self.default_graph = URIRef('http://home.eps.hw.ac.uk/~qz1/')
        self.ns = Namespace('http://home.eps.hw.ac.uk/~qz1/')
        self.ng = Graph(self.store, identifier=self.default_graph)

        # Dirty hack to cleat the db upon restart
        system('curl -X POST -d "query=CLEAR ALL" "http://admin:admin@172.18.2.106:5820/test/query"')
        return

    def insert_tuples(self, g):
        cmd = (u'INSERT DATA { %s  }' % (
                   g.serialize(format='n3')
        ))
        self.store.update(cmd)
        self.store.commit()
        return True

#    @set_ev_cls(EventInsertTuples)
#    def _insert_tuple_handler(self, ev):
##        print('received request to insert tuples %s ' % ev.g.serialize(format='nt'))
#        res = self.insert_tuples(ev.g)
#        rep = EventInsertTuplesReply(ev.src, res)
#        self.reply_to_request(ev, rep)
#        return

    def get_mac_of_host(self, ip):
        # run a query to get MAC address
        rq = """
        PREFIX of: <http://home.eps.hw.ac.uk/~qz1/>
        SELECT distinct ?host ?mac {
        { ?host a of:Host .
        ?host of:hasIPv4 '%s'.
        ?host of:hasMAC ?mac
        }
        }
        """ % (ip)
        res = self.store.query(rq)
        if len(res) == 0:
            LOG.error("Failed to find host with IP addr %s"%(ip))
            return None

        dst_host, dst_mac = next(iter(res))
        return (dst_host, dst_mac)

    def add_path_state(self, src_mac, dst_mac):
        rq = """
        PREFIX of: <http://home.eps.hw.ac.uk/~qz1/>

        insert {
            of:path_%s_%s a of:Path;
            of:src_path ?host1;
            of:dst_path ?host2
        }
        where {
            ?host1 a of:Host; of:hasMAC "%s".
            ?host2 a of:Host; of:hasMAC "%s".
        }
        """ % (src_mac, dst_mac, src_mac, dst_mac)
        res = self.store.update(rq)

        return res

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


        for (field, val) in match.iteritems():
            g.add( (self.ns[flid], self.ns[field], Literal(val) ) )

        action_count = 0
        for action in actions:
            actid = flid + '_action' + str(action_count)
            g.add( (self.ns[flid], self.ns.hasAction, self.ns[actid]) )
            if action.type == 0:
                g.add( (self.ns[actid], RDF.type, self.ns['ActionOutput']) )
                g.add( (self.ns[actid], self.ns.toPort, Literal(action.port)   ) )
                action_count = action_count + 1

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
            g.add( (self.ns[flid], self.ns.hasAction, self.ns[actid]) )
            if action.type == 0:
                g.add( (self.ns[actid], RDF.type, self.ns['ActionOutput']) )
                g.add( (self.ns[actid], self.ns.toPort, Literal(action.port)   ) )
                action_count = action_count + 1

        self.insert_tuples(g)



