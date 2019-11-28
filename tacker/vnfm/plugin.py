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

    supported_extension_aliases = ['vnfm']

    def __init__(self):
        super(VNFMPlugin, self).__init__()
        self._pool = eventlet.GreenPool()
        self.boot_wait = cfg.CONF.tacker.boot_wait
        self.vim_client = vim_client.VimClient()
        self._vnf_manager = driver_manager.DriverManager(
            'tacker.tacker.vnfm.drivers',
            cfg.CONF.tacker.infra_driver)
        self._vnf_action = driver_manager.DriverManager(
            'tacker.tacker.policy.actions',
            cfg.CONF.tacker.policy_action)
        self._vnf_monitor = monitor.VNFMonitor(self.boot_wait)
        self._vnf_alarm_monitor = monitor.VNFAlarmMonitor()
        self._vnf_reservation_monitor = monitor.VNFReservationAlarmMonitor()
        self._vnf_maintenance_monitor = monitor.VNFMaintenanceAlarmMonitor()
        self._vnf_app_monitor = monitor.VNFAppMonitor()
        self._init_monitoring()
nit_monitoring(self):
        context = t_context.get_admin_context()
        vnfs = self.get_vnfs(context)
        for vnf in vnfs:
            # Add tenant_id in context object as it is required
            # to get VIM in monitoring.
            context.tenant_id = vnf['tenant_id']
            self.add_vnf_to_monitor(context, vnf)

    def spawn_n(self, function, *args, **kwargs):
        self._pool.spawn_n(function, *args, **kwargs)

    def create_vnfd(self, context, vnfd):
        vnfd_data = vnfd['vnfd']
        template = vnfd_data['attributes'].get('vnfd')
        if isinstance(template, dict):
            # TODO(sripriya) remove this yaml dump once db supports storing
            # json format of yaml files in a separate column instead of
            # key value string pairs in vnf attributes table
            vnfd_data['attributes']['vnfd'] = yaml.safe_dump(
                template)
        else:
            raise vnfm.InvalidAPIAttributeType(atype=type(template))
        if "tosca_definitions_version" not in template:
            raise exceptions.Invalid('Not a valid template: '
                                     'tosca_definitions_version is missing.')

        LOG.debug('vnfd %s', vnfd_data)

        service_types = vnfd_data.get('service_types')
        if not attributes.is_attr_set(service_types):
            LOG.debug('service type must be specified')
            raise vnfm.ServiceTypesNotSpecified()
        for service_type in service_types:
            # TODO(yamahata):
            # framework doesn't know what services are valid for now.
            # so doesn't check it here yet.
            pass
        if 'template_source' in vnfd_data:
            template_source = vnfd_data.get('template_source')
        else:
            template_source = 'onboarded'
        vnfd['vnfd']['template_source'] = template_source

        self._parse_template_input(vnfd)
        return super(VNFMPlugin, self).create_vnfd(
            context, vnfd)

    def _parse_template_input(self, vnfd):
        vnfd_dict = vnfd['vnfd']
        vnfd_yaml = vnfd_dict['attributes'].get('vnfd')
        if vnfd_yaml is None:
            return

        inner_vnfd_dict = yaml.safe_load(vnfd_yaml)
        LOG.debug('vnfd_dict: %s', inner_vnfd_dict)

        # Prepend the tacker_defs.yaml import file with the full
        # path to the file
        toscautils.updateimports(inner_vnfd_dict)

        try:
            tosca = ToscaTemplate(a_file=False,
                                  yaml_dict_tpl=inner_vnfd_dict)
        except Exception as e:
            LOG.exception("tosca-parser error: %s", str(e))
            raise vnfm.ToscaParserFailed(error_msg_details=str(e))

        if ('description' not in vnfd_dict or
                vnfd_dict['description'] == ''):
            vnfd_dict['description'] = inner_vnfd_dict.get(
                'description', '')
        if (('name' not in vnfd_dict or
                not len(vnfd_dict['name'])) and
                'metadata' in inner_vnfd_dict):
            vnfd_dict['name'] = inner_vnfd_dict['metadata'].get(
                'template_name', '')

        vnfd_dict['mgmt_driver'] = toscautils.get_mgmt_driver(
            tosca)

        if vnfd_dict['mgmt_driver'] not in cfg.CONF.tacker.mgmt_driver:
            LOG.error("Invalid mgmt_driver in TOSCA template")
            raise vnfm.InvalidMgmtDriver(
                mgmt_driver_name=vnfd_dict['mgmt_driver'])

        LOG.debug('vnfd %s', vnfd)

    def add_vnf_to_monitor(self, context, vnf_dict):
        dev_attrs = vnf_dict['attributes']
        mgmt_ip_address = vnf_dict['mgmt_ip_address']
        if 'monitoring_policy' in dev_attrs and mgmt_ip_address:
            def action_cb(action, **kwargs):
                LOG.debug('policy action: %s', action)
                self._vnf_action.invoke(
                    action, 'execute_action', plugin=self, context=context,
                    vnf_dict=hosting_vnf['vnf'], args=kwargs)

            hosting_vnf = self._vnf_monitor.to_hosting_vnf(
                vnf_dict, action_cb)
            LOG.debug('hosting_vnf: %s', hosting_vnf)
            self._vnf_monitor.add_hosting_vnf(hosting_vnf)

