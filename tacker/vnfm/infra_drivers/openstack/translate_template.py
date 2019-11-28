# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
from toscaparser import tosca_template
from toscaparser.utils import yamlparser
from translator.hot import tosca_translator
import yaml

from tacker._i18n import _
from tacker.common import exceptions
from tacker.common import log
from tacker.extensions import common_services as cs
from tacker.extensions import vnfm
from tacker.plugins.common import constants
from tacker.tosca import utils as toscautils



LOG = logging.getLogger(__name__)
CONF = cfg.CONF

OPTS = [
    cfg.DictOpt('flavor_extra_specs',
               default={},
               help=_("Flavor Extra Specs")),
]

CONF.register_opts(OPTS, group='openstack_vim')

HEAT_VERSION_INCOMPATIBILITY_MAP = {'OS::Neutron::Port': {
    'port_security_enabled': 'value_specs', }, }

HEAT_TEMPLATE_BASE = """
heat_template_version: 2013-05-23
"""

ALARMING_POLICY = 'tosca.policies.tacker.Alarming'
SCALING_POLICY = 'tosca.policies.tacker.Scaling'


class TOSCAToHOT(object):
    """Convert TOSCA template to HOT template."""

    def __init__(self, vnf, heatclient):
        self.vnf = vnf
        self.heatclient = heatclient
        self.attributes = {}
        self.vnfd_yaml = None
        self.unsupported_props = {}
        self.heat_template_yaml = None
        self.monitoring_dict = None
        self.nested_resources = dict()
        self.fields = None
        self.STACK_FLAVOR_EXTRA = cfg.CONF.openstack_vim.flavor_extra_specs
        self.appmonitoring_dict = None

    @log.log
    def generate_hot(self):

        self._get_vnfd()
        dev_attrs = self._update_fields()

        vnfd_dict = yamlparser.simple_ordered_parse(self.vnfd_yaml)
        LOG.debug('vnfd_dict %s', vnfd_dict)
        self._get_unsupported_resource_props(self.heatclient)

        self._generate_hot_from_tosca(vnfd_dict, dev_attrs)
        self.fields['template'] = self.heat_template_yaml
        if not self.vnf['attributes'].get('heat_template'):
            self.vnf['attributes']['heat_template'] = self.fields['template']
        if self.monitoring_dict:
            self.vnf['attributes'][
                'monitoring_policy'] = jsonutils.dump_as_bytes(
                self.monitoring_dict)
        if self.appmonitoring_dict:
            self.vnf['attributes']['app_monitoring_policy'] = \
                jsonutils.dump_as_bytes(self.appmonitoring_dict)

    @log.log
    def _get_vnfd(self):
        self.attributes = self.vnf['vnfd']['attributes'].copy()
        self.vnfd_yaml = self.attributes.pop('vnfd', None)
        if self.vnfd_yaml is None:
            LOG.error("VNFD is not provided, so no vnf is created !!")
            raise exceptions.InvalidInput("VNFD template is None.")
        LOG.debug('vnfd_yaml %s', self.vnfd_yaml)

    @log.log
    def _update_fields(self):
        attributes = self.attributes
        fields = dict((key, attributes.pop(key)) for key
                      in ('stack_name', 'template_url', 'template')
                      if key in attributes)
        for key in ('files', 'parameters'):
            if key in attributes:
                fields[key] = jsonutils.loads(attributes.pop(key))

        # overwrite parameters with given dev_attrs for vnf creation
        dev_attrs = self.vnf['attributes'].copy()
        fields.update(dict((key, dev_attrs.pop(key)) for key
                      in ('stack_name', 'template_url', 'template')
                      if key in dev_attrs))
        for key in ('files', 'parameters'):
            if key in dev_attrs:
                fields.setdefault(key, {}).update(
                    jsonutils.loads(dev_attrs.pop(key)))

        self.attributes = attributes
        self.fields = fields
        return dev_attrs


    @log.log
    def _update_params(self, original, paramvalues, match=False):
        for key, value in (original).items():
            if not isinstance(value, dict) or 'get_input' not in str(value):
                pass
            elif isinstance(value, dict):
                if not match:
                    if key in paramvalues and 'param' in paramvalues[key]:
                        self._update_params(value, paramvalues[key]['param'],
                                            True)
                    elif key in paramvalues:
                        self._update_params(value, paramvalues[key], False)
                    else:
                        LOG.debug('Key missing Value: %s', key)
                        raise cs.InputValuesMissing(key=key)
                elif 'get_input' in value:
                    if value['get_input'] in paramvalues:
                        original[key] = paramvalues[value['get_input']]
                    else:
                        LOG.debug('Key missing Value: %s', key)
                        raise cs.InputValuesMissing(key=key)
                else:
                    self._update_params(value, paramvalues, True)

    @log.log
    def _process_parameterized_input(self, dev_attrs, vnfd_dict):
        param_vattrs_yaml = dev_attrs.pop('param_values', None)
        if param_vattrs_yaml:
            try:
                param_vattrs_dict = yaml.safe_load(param_vattrs_yaml)
                LOG.debug('param_vattrs_yaml', param_vattrs_dict)
            except Exception as e:
                LOG.debug("Not Well Formed: %s", str(e))
                raise vnfm.ParamYAMLNotWellFormed(
                    error_msg_details=str(e))
            else:
                self._update_params(vnfd_dict, param_vattrs_dict)
        else:
            raise cs.ParamYAMLInputMissing()

    @log.log
    def _process_vdu_network_interfaces(self, vdu_id, vdu_dict, properties,
                                        template_dict):

        networks_list = []
        properties['networks'] = networks_list
        for network_param in vdu_dict['network_interfaces'].values():
            port = None
            if 'addresses' in network_param:
                ip_list = network_param.pop('addresses', [])
                if not isinstance(ip_list, list):
                    raise vnfm.IPAddrInvalidInput()
                mgmt_flag = network_param.pop('management', False)
                port, template_dict =\
                    self._handle_port_creation(vdu_id, network_param,
                                               template_dict,
                                               ip_list, mgmt_flag)
            if network_param.pop('management', False):
                port, template_dict = self._handle_port_creation(vdu_id,
                                                                 network_param,
                                                                 template_dict,
                                                                 [], True)
            if port is not None:
                network_param = {
                    'port': {'get_resource': port}
                }
            networks_list.append(dict(network_param))
        return vdu_dict, template_dict

    @log.log
    def _make_port_dict(self):
        port_dict = {'type': 'OS::Neutron::Port'}
        if self.unsupported_props:
            port_dict['properties'] = {
                'value_specs': {
                    'port_security_enabled': False
                }
            }
        else:
            port_dict['properties'] = {
                'port_security_enabled': False
            }
        port_dict['properties'].setdefault('fixed_ips', [])
        return port_dict

    @log.log
    def _make_mgmt_outputs_dict(self, vdu_id, port, template_dict):
        mgmt_ip = 'mgmt_ip-%s' % vdu_id
        outputs_dict = template_dict['outputs']
        outputs_dict[mgmt_ip] = {
            'description': 'management ip address',
            'value': {
                'get_attr': [port, 'fixed_ips', 0, 'ip_address']
            }
        }
        template_dict['outputs'] = outputs_dict
        return template_dict

    @log.log
    def _handle_port_creation(self, vdu_id, network_param,
                              template_dict, ip_list=None,
                              mgmt_flag=False):
        ip_list = ip_list or []
        port = '%s-%s-port' % (vdu_id, network_param['network'])
        port_dict = self._make_port_dict()
        if mgmt_flag:
            template_dict = self._make_mgmt_outputs_dict(vdu_id, port,
                                                         template_dict)
        for ip in ip_list:
            port_dict['properties']['fixed_ips'].append({"ip_address": ip})
        port_dict['properties'].update(network_param)
        template_dict['resources'][port] = port_dict
        return port, template_dict
