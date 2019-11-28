# Copyright 2016 - Nokia
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

import collections
import os
import re
import sys
import yaml

from collections import OrderedDict
from oslo_log import log as logging
from oslo_utils import uuidutils

from tacker._i18n import _
from tacker.common import exceptions
from tacker.common import log
from tacker.common import utils
from tacker.extensions import vnfm
from tacker.plugins.common import constants
from toscaparser import properties
from toscaparser.utils import yamlparser



FAILURE = 'tosca.policies.tacker.Failure'
LOG = logging.getLogger(__name__)
MONITORING = 'tosca.policies.Monitoring'
SCALING = 'tosca.policies.Scaling'
RESERVATION = 'tosca.policies.Reservation'
PLACEMENT = 'tosca.policies.tacker.Placement'
TACKERCP = 'tosca.nodes.nfv.CP.Tacker'
TACKERVDU = 'tosca.nodes.nfv.VDU.Tacker'
BLOCKSTORAGE = 'tosca.nodes.BlockStorage.Tacker'
BLOCKSTORAGE_ATTACHMENT = 'tosca.nodes.BlockStorageAttachment'
TOSCA_BINDS_TO = 'tosca.relationships.network.BindsTo'
VDU = 'tosca.nodes.nfv.VDU'
IMAGE = 'tosca.artifacts.Deployment.Image.VM'
HEAT_SOFTWARE_CONFIG = 'OS::Heat::SoftwareConfig'
OS_RESOURCES = {
    'flavor': 'get_flavor_dict',
        'image': 'get_image_dict'
        }

        FLAVOR_PROPS = {
            "num_cpus": ("vcpus", 1, None),
                "disk_size": ("disk", 1, "GB"),
                    "mem_size": ("ram", 512, "MB")
                    }


CPU_PROP_MAP = (('hw:cpu_policy', 'cpu_affinity'),
                ('hw:cpu_threads_policy', 'thread_allocation'),
                ('hw:cpu_sockets', 'socket_count'),
                ('hw:cpu_threads', 'thread_count'),
                ('hw:cpu_cores', 'core_count'))

CPU_PROP_VAL_MAP = {'cpu_affinity': ('shared', 'dedicated')}

CPU_PROP_KEY_SET = {'cpu_affinity', 'thread_allocation', 'socket_count',
                    'thread_count', 'core_count'}

FLAVOR_EXTRA_SPECS_LIST = ('cpu_allocation',
                           'mem_page_size',
                           'numa_node_count',
                           'numa_nodes')

delpropmap = {TACKERVDU: ('mgmt_driver', 'config', 'service_type',
                          'placement_policy', 'monitoring_policy',
                          'metadata', 'failure_policy'),
              TACKERCP: ('management',)}

convert_prop = {TACKERCP: {'anti_spoofing_protection':
                           'port_security_enabled',
                           'type':
                           'binding:vnic_type'}}

convert_prop_values = {TACKERCP: {'type': {'sriov': 'direct',
                                           'vnic': 'normal'}}}

deletenodes = (MONITORING, FAILURE, PLACEMENT)

HEAT_RESOURCE_MAP = {
    "flavor": "OS::Nova::Flavor",
    "image": "OS::Glance::WebImage",
    "maintenance": "OS::Aodh::EventAlarm"
}

SCALE_GROUP_RESOURCE = "OS::Heat::AutoScalingGroup"
SCALE_POLICY_RESOURCE = "OS::Heat::ScalingPolicy"


@log.log
def updateimports(template):
    path = os.path.dirname(os.path.abspath(__file__)) + '/lib/'
    defsfile = path + 'tacker_defs.yaml'

    if 'imports' in template:
        template['imports'].append(defsfile)
    else:
        template['imports'] = [defsfile]

    if 'nfv' in template['tosca_definitions_version']:
        nfvfile = path + 'tacker_nfv_defs.yaml'

        template['imports'].append(nfvfile)

    LOG.debug(path)


@log.log
def check_for_substitution_mappings(template, params):
    sm_dict = params.get('substitution_mappings', {})
    requirements = sm_dict.get('requirements')
    node_tpl = template['topology_template']['node_templates']
    req_dict_tpl = template['topology_template']['substitution_mappings'].get(
        'requirements')
    # Check if substitution_mappings and requirements are empty in params but
    # not in template. If True raise exception
    if (not sm_dict or not requirements) and req_dict_tpl:
        raise vnfm.InvalidParamsForSM()
    # Check if requirements are present for SM in template, if True then return
    elif (not sm_dict or not requirements) and not req_dict_tpl:
        return
    del params['substitution_mappings']
    for req_name, req_val in (req_dict_tpl).items():
        if req_name not in requirements:
            raise vnfm.SMRequirementMissing(requirement=req_name)
        if not isinstance(req_val, list):
            raise vnfm.InvalidSubstitutionMapping(requirement=req_name)
        try:
            node_name = req_val[0]
            node_req = req_val[1]

            node_tpl[node_name]['requirements'].append({
                node_req: {
                    'node': requirements[req_name]
                }
            })
            node_tpl[requirements[req_name]] = \
                sm_dict[requirements[req_name]]
        except Exception:
            raise vnfm.InvalidSubstitutionMapping(requirement=req_name)


@log.log
def get_vdu_monitoring(template):
    monitoring_dict = dict()
    policy_dict = dict()
    policy_dict['vdus'] = collections.OrderedDict()
    for nt in template.nodetemplates:
        if nt.type_definition.is_derived_from(TACKERVDU):
            mon_policy = nt.get_property_value('monitoring_policy') or 'noop'
            if mon_policy != 'noop':
                if 'parameters' in mon_policy:
                    mon_policy['monitoring_params'] = mon_policy['parameters']
                policy_dict['vdus'][nt.name] = {}
                policy_dict['vdus'][nt.name][mon_policy['name']] = mon_policy
    if policy_dict.get('vdus'):
        monitoring_dict = policy_dict
    return monitoring_dict



def get_vdu_applicationmonitoring(template):
    tpl_temp = "topology_template"
    n_temp = "node_templates"
    poly = "app_monitoring_policy"
    monitoring_dict = dict()
    policy_dict = dict()
    policy_dict['vdus'] = collections.OrderedDict()
    node_list = template[tpl_temp][n_temp].keys()
    for node in node_list:
        nt = template[tpl_temp][n_temp][node]
        if nt['type'] == TACKERVDU:
            if poly in nt['properties'].keys():
                mon_policy = nt['properties'][poly]
                if mon_policy != 'noop':
                    policy_dict['vdus'][node] = {}
                    policy_dict['vdus'][node] = mon_policy
                del template[tpl_temp][n_temp][node]['properties'][poly]
    if policy_dict.get('vdus'):
        monitoring_dict = policy_dict
    return monitoring_dict


@log.log
def get_vdu_metadata(template, unique_id=None):
    metadata = dict()
    metadata.setdefault('vdus', {})
    for nt in template.nodetemplates:
        if nt.type_definition.is_derived_from(TACKERVDU):
            metadata_dict = nt.get_property_value('metadata') or None
            if metadata_dict:
                metadata_dict['metering.server_group'] = \
                    (metadata_dict['metering.server_group'] + '-'
                     + unique_id)[:15]
                metadata['vdus'][nt.name] = {}
                metadata['vdus'][nt.name].update(metadata_dict)
    return metadata


@log.log
def get_metadata_for_reservation(template, metadata):
    """Method used to add lease_id in metadata

     So that it can be used further while creating query_metadata

    :param template: ToscaTemplate object
    :param metadata: metadata dict
    :return: dictionary contains lease_id
    """

    metadata.setdefault('reservation', {})
    input_param_list = template.parsed_params.keys()
    # if lease_id is passed in the parameter file,
    # get it from template parsed_params.
    if 'lease_id' in input_param_list:
        metadata['reservation']['lease_id'] = template.parsed_params[
            'lease_id']
    else:
        for policy in template.policies:
            if policy.entity_tpl['type'] == constants.POLICY_RESERVATION:
                metadata['reservation']['lease_id'] = policy.entity_tpl[
                    'reservation']['properties']['lease_id']
                break
    if not uuidutils.is_uuid_like(metadata['reservation']['lease_id']):
        raise exceptions.Invalid('Invalid UUID for lease_id')
    return metadata


@log.log
def pre_process_alarm_resources(vnf, template, vdu_metadata, unique_id=None):
    alarm_resources = dict()
    query_metadata = dict()
    alarm_actions = dict()
    for policy in template.policies:
        if policy.type_definition.is_derived_from(MONITORING):
            query_metadata.update(_process_query_metadata(
                vdu_metadata, policy, unique_id))
            alarm_actions.update(_process_alarm_actions(vnf, policy))
        if policy.type_definition.is_derived_from(RESERVATION):
            query_metadata.update(_process_query_metadata_reservation(
                vdu_metadata, policy))
            alarm_actions.update(_process_alarm_actions_for_reservation(
                vnf, policy))
            alarm_resources['event_types'] = {
                'start_actions': {'event_type': 'lease.event.start_lease'},
                'before_end_actions': {
                    'event_type': 'lease.event.before_end_lease'},
                'end_actions': {'event_type': 'lease.event.end_lease'}}

    maintenance_vdus = get_maintenance_vdus(template)
    if maintenance_vdus:
        alarm_actions.update(_process_alarm_actions_for_maintenance(
            vnf, maintenance_vdus))

    alarm_resources['query_metadata'] = query_metadata
    alarm_resources['alarm_actions'] = alarm_actions
    return alarm_resources
