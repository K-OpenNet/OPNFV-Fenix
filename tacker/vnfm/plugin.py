# Copyright 2013, 2014 Intel Corporation.
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

import inspect
import six
import yaml

import eventlet
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils
from toscaparser.tosca_template import ToscaTemplate

from tacker._i18n import _
from tacker.api.v1 import attributes
from tacker.common import driver_manager
from tacker.common import exceptions
from tacker.common import utils
from tacker import context as t_context
from tacker.db.vnfm import vnfm_db
from tacker.extensions import vnfm
from tacker.plugins.common import constants
from tacker.tosca import utils as toscautils
from tacker.vnfm.mgmt_drivers import constants as mgmt_constants
from tacker.vnfm import monitor
from tacker.vnfm import vim_client


LOG = logging.getLogger(__name__)
CONF = cfg.CONF



def config_opts():
    return [('tacker', VNFMMgmtMixin.OPTS),
            ('tacker', VNFMPlugin.OPTS_INFRA_DRIVER),
            ('tacker', VNFMPlugin.OPTS_POLICY_ACTION)]


class VNFMMgmtMixin(object):
    OPTS = [
        cfg.ListOpt(
            'mgmt_driver', default=['noop', 'openwrt'],
            help=_('MGMT driver to communicate with '
                   'Hosting VNF/logical service '
                   'instance tacker plugin will use')),
        cfg.IntOpt('boot_wait', default=30,
            help=_('Time interval to wait for VM to boot'))
    ]
    cfg.CONF.register_opts(OPTS, 'tacker')

    def __init__(self):
        super(VNFMMgmtMixin, self).__init__()
        self._mgmt_manager = driver_manager.DriverManager(
            'tacker.tacker.mgmt.drivers', cfg.CONF.tacker.mgmt_driver)

    def _invoke(self, vnf_dict, **kwargs):
        method = inspect.stack()[1][3]
        return self._mgmt_manager.invoke(
            self._mgmt_driver_name(vnf_dict), method, **kwargs)

    def mgmt_create_pre(self, context, vnf_dict):
        return self._invoke(
            vnf_dict, plugin=self, context=context, vnf=vnf_dict)

    def mgmt_create_post(self, context, vnf_dict):
        return self._invoke(
            vnf_dict, plugin=self, context=context, vnf=vnf_dict)

    def mgmt_update_pre(self, context, vnf_dict):
        return self._invoke(
            vnf_dict, plugin=self, context=context, vnf=vnf_dict)

    def mgmt_update_post(self, context, vnf_dict):
        return self._invoke(
            vnf_dict, plugin=self, context=context, vnf=vnf_dict)

    def mgmt_delete_pre(self, context, vnf_dict):
        return self._invoke(
            vnf_dict, plugin=self, context=context, vnf=vnf_dict)

    def mgmt_delete_post(self, context, vnf_dict):
        return self._invoke(
            vnf_dict, plugin=self, context=context, vnf=vnf_dict)

    def mgmt_get_config(self, context, vnf_dict):
        return self._invoke(
            vnf_dict, plugin=self, context=context, vnf=vnf_dict)

    def mgmt_ip_address(self, context, vnf_dict):
        return self._invoke(
            vnf_dict, plugin=self, context=context, vnf=vnf_dict)

    def mgmt_call(self, context, vnf_dict, kwargs):
        return self._invoke(
            vnf_dict, plugin=self, context=context, vnf=vnf_dict,
            kwargs=kwargs)


class VNFMPlugin(vnfm_db.VNFMPluginDb, VNFMMgmtMixin):
    """VNFMPlugin which supports VNFM framework.

    Plugin which supports Tacker framework
    """
    OPTS_INFRA_DRIVER = [
        cfg.ListOpt(
            'infra_driver', default=['noop', 'openstack', 'kubernetes'],
            help=_('Hosting vnf drivers tacker plugin will use')),
    ]
    cfg.CONF.register_opts(OPTS_INFRA_DRIVER, 'tacker')

    OPTS_POLICY_ACTION = [
        cfg.ListOpt(
            'policy_action', default=['autoscaling', 'respawn',
                                      'vdu_autoheal', 'log', 'log_and_kill'],
            help=_('Hosting vnf drivers tacker plugin will use')),
    ]
    cfg.CONF.register_opts(OPTS_POLICY_ACTION, 'tacker')
