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
from ryu.app.pathComputation import PathComputation
from ryu.lib.packet import ethernet, arp, packet
from ryu.lib.packet.ether_types import ETH_TYPE_ARP, ETH_TYPE_IP
from ryu.lib import hub
from ryu.topology import event, switches
from rdflib import Graph, Namespace, Literal
from rdflib.namespace import RDF

import json


LOG = logging.getLogger("FlowManager")

class FlowManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'switches': switches.Switches,
        'backend': StardogBackend,
        'pathComputation': PathComputation
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
        self.backend = None

    def set_backend(self, backend):
        self.backend = backend

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

    def add_flow(self, datapath, priority, match, actions, buffer_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.backend.add_flow_state(self.flow_count, datapath.id, priority, match, actions)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst, buffer_id=buffer_id, cookie=self.flow_count)
        LOG.info("adding flow %s" % (str(mod)))
        self.flow_count = self.flow_count + 1
        return datapath.send_msg(mod)

    def add_path_flow(self, pathid, hopCount, datapath, priority, match, actions, buffer_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.backend.add_path_flow_state(self.flow_count, datapath.id, priority, match, actions,
                                         hopCount, pathid)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst, buffer_id=buffer_id, cookie=self.flow_count)
        LOG.info("adding path %s flow %s" % (pathid, str(mod)))
        self.flow_count = self.flow_count + 1
        return datapath.send_msg(mod)



    def flow_monitor(self):
       while self.is_active:
            self.export_event.clear()
#            LOG.info("flow monitor fired!")
            flows = self.get_flows()
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


