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


    def __run__(self):
        while(1):
            time.sleep(self._status_check_intvl)

            with self._lock:
                for hosting_vnf in VNFMonitor._hosting_vnfs.values():
                    if hosting_vnf.get('dead', False) or (
                            hosting_vnf['vnf']['status'] ==
                            constants.PENDING_HEAL):
                        LOG.debug(
                            'monitor skips for DEAD/PENDING_HEAL vnf %s',
                            hosting_vnf)
                        continue
                    try:
                        self.run_monitor(hosting_vnf)
                    except Exception as ex:
                        LOG.exception("Unknown exception: Monitoring failed "
                                      "for VNF '%s' due to '%s' ",
                                      hosting_vnf['id'], ex)


    @staticmethod
    def to_hosting_vnf(vnf_dict, action_cb):
        return {
            'id': vnf_dict['id'],
            'mgmt_ip_addresses': jsonutils.loads(
                vnf_dict['mgmt_ip_address']),
            'action_cb': action_cb,
            'vnf': vnf_dict,
            'monitoring_policy': jsonutils.loads(
                vnf_dict['attributes']['monitoring_policy'])
        }

    def add_hosting_vnf(self, new_vnf):
        LOG.debug('Adding host %(id)s, Mgmt IP %(ips)s',
                  {'id': new_vnf['id'],
                   'ips': new_vnf['mgmt_ip_addresses']})
        new_vnf['boot_at'] = timeutils.utcnow()
        with self._lock:
            VNFMonitor._hosting_vnfs[new_vnf['id']] = new_vnf

        attrib_dict = new_vnf['vnf']['attributes']
        mon_policy_dict = attrib_dict['monitoring_policy']
        evt_details = (("VNF added for monitoring. "
                        "mon_policy_dict = %s,") % (mon_policy_dict))
        vnfm_utils.log_events(t_context.get_admin_context(),
                              new_vnf['vnf'],
                              constants.RES_EVT_MONITOR, evt_details)


    def delete_hosting_vnf(self, vnf_id):
        LOG.debug('deleting vnf_id %(vnf_id)s', {'vnf_id': vnf_id})
        with self._lock:
            hosting_vnf = VNFMonitor._hosting_vnfs.pop(vnf_id, None)
            if hosting_vnf:
                LOG.debug('deleting vnf_id %(vnf_id)s, Mgmt IP %(ips)s',
                          {'vnf_id': vnf_id,
                           'ips': hosting_vnf['mgmt_ip_addresses']})

    def update_hosting_vnf(self, updated_vnf_dict, evt_details=None):
        with self._lock:
            vnf_to_update = VNFMonitor._hosting_vnfs.get(
                updated_vnf_dict.get('id'))
            if vnf_to_update:
                updated_vnf = copy.deepcopy(updated_vnf_dict)
                vnf_to_update['vnf'] = updated_vnf
                vnf_to_update['mgmt_ip_addresses'] = jsonutils.loads(
                    updated_vnf_dict['mgmt_ip_address'])

                if evt_details is not None:
                    vnfm_utils.log_events(t_context.get_admin_context(),
                                          vnf_to_update['vnf'],
                                          constants.RES_EVT_HEAL,
                                          evt_details=evt_details)
