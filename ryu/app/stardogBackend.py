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
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from rdflib import Graph, URIRef
from rdflib.plugins.stores import sparqlstore
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

    _EVENTS = [EventInsertTuples]

    _CONTEXTS = {
        'switches': switches.Switches}

    def __init__(self, *args, **kwargs):
        super(StardogBackend, self).__init__(*args, **kwargs)
        self.name = 'stardogBackend'
        self.endpoint = 'http://172.18.2.106:5820/test/query'
        self.store = sparqlstore.SPARQLUpdateStore()
        self.store.open((self.endpoint, self.endpoint))
        self.store.setCredentials('admin', 'admin')
        self.default_graph = URIRef('http://home.eps.hw.ac.uk/~qz1/')
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

    @set_ev_cls(EventInsertTuples)
    def _insert_tuple_handler(self, ev):
#        print('received request to insert tuples %s ' % ev.g.serialize(format='nt'))
        res = self.insert_tuples(ev.g)
        rep = EventInsertTuplesReply(ev.src, res)
        self.reply_to_request(ev, rep)
        return

    def _get_mac_of_host(self, ip):
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



