# Copyright 2015 Intel Corporation.
# All Rights Reserved.
#
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import ast
import copy
import inspect
import threading
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import timeutils

from tacker._i18n import _
from tacker.common import driver_manager
from tacker.common import exceptions
from tacker import context as t_context
from tacker.plugins.common import constants
from tacker.vnfm import utils as vnfm_utils


LOG = logging.getLogger(__name__)
CONF = cfg.CONF
OPTS = [
    cfg.IntOpt('check_intvl',
               default=10,
               help=_("check interval for monitor")),
]
CONF.register_opts(OPTS, group='monitor')


def config_opts():
    return [('monitor', OPTS),
            ('tacker', VNFMonitor.OPTS),
            ('tacker', VNFAlarmMonitor.OPTS),
            ('tacker', VNFAppMonitor.OPTS)]


class VNFMonitor(object):
    """VNF Monitor."""

    _instance = None
    _hosting_vnfs = dict()   # vnf_id => dict of parameters
    _status_check_intvl = 0
    _lock = threading.RLock()

    OPTS = [
        cfg.ListOpt(
            'monitor_driver', default=['ping', 'http_ping'],
            help=_('Monitor driver to communicate with '
                   'Hosting VNF/logical service '
                   'instance tacker plugin will use')),
    ]
    cfg.CONF.register_opts(OPTS, 'tacker')

    def __new__(cls, boot_wait, check_intvl=None):
        if not cls._instance:
            cls._instance = super(VNFMonitor, cls).__new__(cls)
        return cls._instance

    def __init__(self, boot_wait, check_intvl=None):
        self._monitor_manager = driver_manager.DriverManager(
            'tacker.tacker.monitor.drivers',
            cfg.CONF.tacker.monitor_driver)

        self.boot_wait = boot_wait
        if check_intvl is None:
            check_intvl = cfg.CONF.monitor.check_intvl
        self._status_check_intvl = check_intvl
        LOG.debug('Spawning VNF monitor thread')
        threading.Thread(target=self.__run__).start()
