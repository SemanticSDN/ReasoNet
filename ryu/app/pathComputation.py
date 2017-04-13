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

import json
import urllib2
import json


LOG = logging.getLogger("PathComputation")

class PathComputation(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'backend': StardogBackend
    }

    def __init__(self, *args, **kwargs):
        super(PathComputation, self).__init__(*args, **kwargs)
        self.backend = None # kwargs["backend"]
        self.flowManager = None # kwargs["backend"]
        self.dps = {}
        self.ofctl = ofctl_v1_3

    def set_backend(self, backend, manager):
        self.backend = backend
        self.flowManager = manager

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        LOG.debug("Got a switch in path computation")
        if ev.enter:
            self.dps[ev.dp.id] = ev.dp
        else:
            del  self.dps[ev.dp.id]

    def get_path(self, src_mac, dst_mac):
        ret = []
        url = "http://172.18.2.106:8182"
        values = {
            "gremlin" : 'g.V().has("http://home.eps.hw.ac.uk/~qz1/hasMAC", src_mac).'+
            'out("http://home.eps.hw.ac.uk/~qz1/connectToPort").'+
            'repeat(__.in("http://home.eps.hw.ac.uk/~qz1/hasPort").'+
            'out("http://home.eps.hw.ac.uk/~qz1/hasPort").'+
            'out("http://home.eps.hw.ac.uk/~qz1/connectToPort").simplePath()).'+
            'until(has("http://home.eps.hw.ac.uk/~qz1/hasMAC", dst_mac)).path().limit(1)',
            "bindings" : {"src_mac": src_mac, "dst_mac": dst_mac}
        }

        req = urllib2.Request(url, json.dumps(values))
        response = urllib2.urlopen(req)
        res = response.read()

        res = json.loads(res)
        if len(res["result"]["data"]) == 0:
            return None
        count = len(res["result"]["data"][0]["objects"])
        ix = 1
        while ix < count - 1:
            src_port = res["result"]["data"][0]["objects"][ix]["properties"]
            dst_port = res["result"]["data"][0]["objects"][ix+2]["properties"]
            sw = res["result"]["data"][0]["objects"][ix+1]["properties"]
            dpid = int(sw["http://home.eps.hw.ac.uk/~qz1/hasID"][0]["value"])
            src_port_no = int(src_port["http://home.eps.hw.ac.uk/~qz1/port_no"][0]["value"])
            dst_port_no = int(dst_port["http://home.eps.hw.ac.uk/~qz1/port_no"][0]["value"])
            ret.append((src_port_no, dpid, dst_port_no))
            ix = ix + 3

        return ret

    def add_path(self, src_mac, dst_mac, buffer_id):
        path = self.get_path(src_mac, dst_mac)

        if path is None or len(path) == 0:
            LOG.error("No path found between \'%s\' and \'%s\'" % (src_mac, dst_mac))
            return

        for (src_port, dpid, dst_port) in reversed(path):
            if dpid in self.dps:
                self._insert_host_connect_flows(self.dps[dpid], buffer_id,
                                                src_port, src_mac,
                                                dst_port, dst_mac)
        for (src_port, dpid, dst_port) in path:
                # setup inverse path
                self._insert_host_connect_flows(self.dps[dpid],
                                                self.dps[dpid].ofproto.OFPCML_NO_BUFFER,
                                                dst_port, dst_mac,
                                                src_port, src_mac)

        self.backend.add_path_state(src_mac, dst_mac)

    def _insert_host_connect_flows(self, dp, buffer_id, src_port, src_mac, dst_port, dst_mac):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(dst_port, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(in_port=src_port, eth_dst=dst_mac, eth_src=src_mac)
        return self.flowManager.add_flow(dp, 1, match, actions, buffer_id)

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


