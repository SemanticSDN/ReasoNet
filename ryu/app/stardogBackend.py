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

from ryu.base import app_manager
from ryu.topology import switches
from ryu.controller import ofp_event
from ryu.controller import event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3

from rdflib import Graph, Literal, URIRef
from rdflib.plugins.stores import sparqlstore


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
        return

    @set_ev_cls(EventInsertTuples)
    def _insert_tuple_handler(self, ev):
        print('received request to insert tuples')
        self.store.update(
                u'INSERT DATA { %s  }' % ev.g.serialize(format='nt')
        )
        self.store.commit()

        rep = EventInsertTuplesReply(ev.src, True)
        self.reply_to_request(ev, rep)
        return


