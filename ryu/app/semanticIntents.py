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
from ryu.controller import dpset
from ryu.topology import switches

from ryu.app.stardogBackend import StardogBackend
from ryu.app.pathManager import PathManager
from ryu.app.flowManager import FlowManager
from ryu.app.semanticController import SemanticController
from ryu.app.topologyManager import TopologyManager

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response


LOG = logging.getLogger("SemanticIntents")

BASE_URL = '/semantic'

class SemanticIntents(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'backend'        : StardogBackend,
        'flowManager'    : FlowManager,
        'pathManager'    : PathManager,
        'switches'       : switches.Switches,
        'topologyManager': TopologyManager,
        'wsgi'           : WSGIApplication,
#        'controller': SemanticController,
    }

    def __init__(self, *args, **kwargs):
        super(SemanticIntents, self).__init__(*args, **kwargs)
        self.backend = kwargs["backend"]
        self.path = kwargs["pathManager"]
        wsgi = kwargs['wsgi']
        self.dps = {}
        self.data = {}
        wsgi.registory['SemanticsIntentsRest'] = self.data
        wsgi.register(SemanticIntentsRest, self.data)


    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            self.dps[ev.dp.id] = ev.dp
        else:
            del  self.dps[ev.dp.id]

class SemanticIntentsRest(ControllerBase):
    _LOGGER = None

    def __init__(self, req, link, data, **config):
        super(SemanticIntentsRest, self).__init__(req, link, data, **config)

    @classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[QoS][%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)


    @route("state", BASE_URL + '/state', methods=['GET'])
    def get_state(self, req, **kwargs):
        try:
            rest = req.json if req.body else {}
        except ValueError:
            QoSController._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)
        return Response(content_type='application/json', body=str([{"hello":"world!!!"}]))

    @route("intent", BASE_URL + "/intent", methods=["GET"])
    def get_intents(self, req, **kwargs):
        try:
            rest = req.json if req.body else {}
        except ValueError:
            SemanticIntentsRest._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)
        return Response(content_type='application/json', body=str([{"hello":"world!!!"}]))

    @route("intent", BASE_URL + "/intent", methods=["POST"])
    def add_intent(self, req, **kwargs):
        try:
            rest = req.json if req.body else {}
        except ValueError:
            SemanticIntentRest._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)

        # Add new path intent in DB

        #

        return Response(content_type='application/json', body=str([{"hello":"world!!!"}, rest]))
