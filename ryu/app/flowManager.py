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

from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.controller import dpset
from ryu.lib.ovs.bridge import OVSBridge

from ryu.app.stardogBackend import StardogBackend
from ryu.lib import hub

from rdflib import Graph, Namespace, Literal
from rdflib.namespace import RDF



LOG = logging.getLogger("FlowManager")

class FlowManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'backend': StardogBackend,
    }

    def __init__(self, *args, **kwargs):
        super(FlowManager, self).__init__(*args, **kwargs)
        self.export_event = hub.Event()
        self.threads.append(hub.spawn(self.flow_monitor))
        self.is_active = True
        self.TIMEOUT_CHECK_PERIOD = 5
        self.dps = {}
        self.waiters = {}
        self.ofctl = ofctl_v1_3
        self.flow_count = 1
        self.backend = kwargs["backend"]
        self.ns = Namespace('http://home.eps.hw.ac.uk/~qz1/')

    def close(self):
        self.is_active = False
        self.export_event.set()
        hub.joinall(self.threads)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            self.dps[ev.dp.id] = ev.dp
        else:
            del  self.dps[ev.dp.id]

    def add_flow(self, datapath, priority=1, match=None,
                 actions=None, buffer_id=None, output=None, queue=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = actions if actions is not None else []
        bid = ofproto.OFP_NO_BUFFER if buffer_id is None else buffer_id
        out = ofproto.OFPP_ALL if output is None else output
        match= parser.OFPMatch() if match is None else match

        if queue is not None:
            qid = output * 100 + self.flow_count
            # pid = "s%d-eth%d"%(datapath.id, output)
            self._create_queue(datapath, output, qid, queue, None)
            actions.append(parser.OFPActionSetQueue(qid))
        actions.append(parser.OFPActionOutput(out,ofproto.OFPCML_NO_BUFFER ))

        self.backend.add_flow_state(self.flow_count, datapath.id, priority, match, actions)
        self.flow_count = self.flow_count + 1
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        return self._add_flow(datapath, priority, match, inst, bid)

    def add_path_flow(self, pathid, hopCount,
                      datapath, priority=1, match=None,
                      actions=None, buffer_id=None, output=None, queue=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = actions if actions is not None else []
        bid = ofproto.OFP_NO_BUFFER if buffer_id is None else buffer_id
        out = ofproto.OFPP_ALL if output is None else output
        match= parser.OFPMatch() if match is None else match

        if queue is not None:
            qid = output * 100 + self.flow_count
            # pid = "s%d-eth%d"%(datapath.id, output)
            self._create_queue(datapath, output, qid, queue, pathid)
            actions.append(parser.OFPActionSetQueue(qid))
        actions.append(parser.OFPActionOutput(out,ofproto.OFPCML_NO_BUFFER ))

        self.backend.add_path_flow_state(self.flow_count, datapath.id, priority, match, actions,
                                         hopCount, pathid)
        self.flow_count = self.flow_count + 1
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        return # self._add_flow(datapath, priority, match, inst, bid)

    def flow_monitor(self):
       while self.is_active:
            self.export_event.clear()
#            LOG.info("flow monitor fired!")
            my_flows = self.backend.get_semantic_flows()
            flows = self.get_flows()
            del_flows = {}
            for dpid in flows:
                for f in flows[dpid]:
                    a = f.instructions
                    m = f.match
                    res = [ix for (ix, f2) in enumerate(my_flows[dpid])
                           if a == f2["actions"] and m == f2["match"]]
                    for ix in res:
                        print("found flow %s" % (m))
                        del my_flows[dpid][ix]
                    if len(res) == 0:
                        if dpid not in del_flows:
                            del_flows[dpid] = []
                        del_flows[dpid].append(f)
            print("adding " + str(my_flows))
            print("removing " + str(del_flows))
            for dpid in del_flows:
                ofproto = self.dps[dpid].ofproto
                for fl in del_flows[dpid]:
                    self._del_strict_flow(self.dps[dpid], fl.priority, fl.match, fl.instructions)

            for dpid in my_flows:
                for fl in my_flows[dpid]:
                    self._add_flow(self.dps[dpid], 1, fl["match"], fl["actions"], ofproto.OFP_NO_BUFFER)

           # TODO: get all flows, update individual flows stats and remove any unwanted flows
            self.export_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)

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
    def _stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if (dp.id not in self.waiters) or (msg.xid not in self.waiters[dp.id]):
            return
        locks, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return
        locks.set()

    def _create_queue(self, datapath, pid, qid, rate, pathid):
        ovs = OVSBridge(cfg.CONF, datapath.id, "unix:/var/run/openvswitch/db.sock")
        ovs.init()
        LOG.debug("creating queue %d on port %s" %(qid, pid))
        ovs.set_qos(("s%d-eth%d"%(datapath.id, pid)), max_rate="1000000000",
                    queues=[{"max-rate": str(rate),
                             "queue-id" : ((qid))}])

        qid = "s%d_queue%s"%(datapath.id, qid)
        g = Graph()
        g.add( (self.ns[qid], RDF.type, self.ns['Queue'])  )
        pid = "s%d_port%d"%(datapath.id, pid)
        LOG.info("inserting the queue " + qid + " on queue " + pid)
        g.add( (self.ns[pid], self.ns.hasQueue, self.ns[qid]) )
        if pathid is not None:
            LOG.info("adding queue %s for path %s" % (qid, pathid))
            g.add( (self.ns[qid], self.ns.hasPath, self.ns[pathid])  )
        g.add( (self.ns[qid], self.ns.hasBW, Literal(rate)) )
        self.backend.insert_tuples(g)

        rq = """
        PREFIX of: <http://home.eps.hw.ac.uk/~qz1/>
        delete {of:%s of:hasLoad ?bw}
        insert {of:%s of:hasLoad ?newBW}
        where
        {
          of:%s of:hasLoad ?bw.
            {select ((?bw+%d) as ?newBW)
            where {
              of:%s of:hasLoad ?bw.
            }}
        }
        """%(pid, pid, pid, rate, pid)
        self.backend.update(rq)


    def _add_flow(self, datapath, priority, match, inst, bid):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                command=ofproto.OFPFC_ADD,
                                instructions=inst, buffer_id=bid, cookie=self.flow_count)
        # LOG.info("adding path %s flow %s" % (pathid, str(mod)))
        return datapath.send_msg(mod)

    def _del_strict_flow(self, datapath, priority, match, inst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                command=ofproto.OFPFC_DELETE_STRICT, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                instructions=[], cookie=self.flow_count)
        print ("deleting " + str(mod))
        return datapath.send_msg(mod)
        # LOG.info("deleting path %s flow %s" % (pathid, str(mod)))
