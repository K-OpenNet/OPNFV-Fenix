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



def _process_query_metadata(metadata, policy, unique_id):
    query_mtdata = dict()
    triggers = policy.entity_tpl['triggers']
    for trigger_name, trigger_dict in triggers.items():
        resource_type = trigger_dict.get('condition').get('resource_type')
        # TODO(phuoc): currently, Tacker only supports resource_type with
        # instance value. Other types such as instance_network_interface,
        # instance_disk can be supported in the future.
        if resource_type == 'instance':
            if not (trigger_dict.get('metadata') and metadata):
                raise vnfm.MetadataNotMatched()
            is_matched = False
            for vdu_name, metadata_dict in metadata['vdus'].items():
                trigger_dict['metadata'] = \
                    (trigger_dict['metadata'] + '-' + unique_id)[:15]
                if trigger_dict['metadata'] == \
                        metadata_dict['metering.server_group']:
                    is_matched = True
            if not is_matched:
                raise vnfm.MetadataNotMatched()
            query_template = dict()
            query_template['str_replace'] = dict()
            query_template['str_replace']['template'] = \
                '{"=": {"server_group": "scaling_group_id"}}'
            scaling_group_param = \
                {'scaling_group_id': trigger_dict['metadata']}
            query_template['str_replace']['params'] = scaling_group_param
        else:
            raise vnfm.InvalidResourceType(resource_type=resource_type)
        query_mtdata[trigger_name] = query_template
    return query_mtdata


def _process_query_metadata_reservation(metadata, policy):
    query_metadata = dict()
    policy_actions = policy.entity_tpl['reservation'].keys()
    policy_actions.remove('properties')
    for action in policy_actions:
        query_template = [{
            "field": 'traits.lease_id', "op": "eq",
            "value": metadata['reservation']['lease_id']}]
        query_metadata[action] = query_template

    return query_metadata


def _process_alarm_actions(vnf, policy):
    # process  alarm url here
    triggers = policy.entity_tpl['triggers']
    alarm_actions = dict()
    for trigger_name, trigger_dict in triggers.items():
        alarm_url = vnf['attributes'].get(trigger_name)
        if alarm_url:
            alarm_url = str(alarm_url)
            LOG.debug('Alarm url in heat %s', alarm_url)
            alarm_actions[trigger_name] = dict()
            alarm_actions[trigger_name]['alarm_actions'] = [alarm_url]
    return alarm_actions


def _process_alarm_actions_for_reservation(vnf, policy):
    # process  alarm url here
    alarm_actions = dict()
    policy_actions = policy.entity_tpl['reservation'].keys()
    policy_actions.remove('properties')
    for action in policy_actions:
        alarm_url = vnf['attributes'].get(action)
        if alarm_url:
            LOG.debug('Alarm url in heat %s', alarm_url)
            alarm_actions[action] = dict()
            alarm_actions[action]['alarm_actions'] = [alarm_url]
    return alarm_actions


def _process_alarm_actions_for_maintenance(vnf, vdus):
    # process alarm url here
    alarm_actions = dict()
    maintenance_actions = [str(x) + '_maintenance' for x in vdus]
    for action in maintenance_actions:
        alarm_url = vnf['attributes'].get(action)
        if alarm_url:
            LOG.debug('Alarm url in heat %s', alarm_url)
            alarm_actions[action] = dict()
            alarm_actions[action]['alarm_actions'] = [alarm_url]
    return alarm_actions


def get_volumes(template):
    volume_dict = dict()
    node_tpl = template['topology_template']['node_templates']
    for node_name in list(node_tpl.keys()):
        node_value = node_tpl[node_name]
        if node_value['type'] != BLOCKSTORAGE:
            continue
        volume_dict[node_name] = dict()
        block_properties = node_value.get('properties', {})
        for prop_name, prop_value in block_properties.items():
            if prop_name == 'size':
                prop_value = \
                    re.compile('(\d+)\s*(\w+)').match(prop_value).groups()[0]
            volume_dict[node_name][prop_name] = prop_value
        del node_tpl[node_name]
    return volume_dict



@log.log
def get_vol_attachments(template):
    vol_attach_dict = dict()
    node_tpl = template['topology_template']['node_templates']
    valid_properties = {
        'location': 'mountpoint'
    }
    for node_name in list(node_tpl.keys()):
        node_value = node_tpl[node_name]
        if node_value['type'] != BLOCKSTORAGE_ATTACHMENT:
            continue
        vol_attach_dict[node_name] = dict()
        vol_attach_properties = node_value.get('properties', {})
        # parse properties
        for prop_name, prop_value in vol_attach_properties.items():
            if prop_name in valid_properties:
                vol_attach_dict[node_name][valid_properties[prop_name]] = \
                    prop_value
        # parse requirements to get mapping of cinder volume <-> Nova instance
        for req in node_value.get('requirements', {}):
            if 'virtualBinding' in req:
                vol_attach_dict[node_name]['instance_uuid'] = \
                    {'get_resource': req['virtualBinding']['node']}
            elif 'virtualAttachment' in req:
                vol_attach_dict[node_name]['volume_id'] = \
                    {'get_resource': req['virtualAttachment']['node']}
        del node_tpl[node_name]
    return vol_attach_dict


@log.log
def get_block_storage_details(template):
    block_storage_details = dict()
    block_storage_details['volumes'] = get_volumes(template)
    block_storage_details['volume_attachments'] = get_vol_attachments(template)
    return block_storage_details


@log.log
def get_mgmt_ports(tosca):
    mgmt_ports = {}
    for nt in tosca.nodetemplates:
        if nt.type_definition.is_derived_from(TACKERCP):
            mgmt = nt.get_property_value('management') or None
            if mgmt:
                vdu = None
                for rel, node in nt.relationships.items():
                    if rel.is_derived_from(TOSCA_BINDS_TO):
                        vdu = node.name
                        break

                if vdu is not None:
                    name = 'mgmt_ip-%s' % vdu
                    mgmt_ports[name] = nt.name
    LOG.debug('mgmt_ports: %s', mgmt_ports)
    return mgmt_ports


@log.log
def add_resources_tpl(heat_dict, hot_res_tpl):
    for res, res_dict in (hot_res_tpl).items():
        for vdu, vdu_dict in (res_dict).items():
            res_name = vdu + "_" + res
            heat_dict["resources"][res_name] = {
                "type": HEAT_RESOURCE_MAP[res],
                "properties": {}
            }

            if res == "maintenance":
                continue
            for prop, val in (vdu_dict).items():
                # change from 'get_input' to 'get_param' to meet HOT template
                if isinstance(val, dict):
                    if 'get_input' in val:
                        val['get_param'] = val.pop('get_input')
                heat_dict["resources"][res_name]["properties"][prop] = val
            if heat_dict["resources"].get(vdu):
                heat_dict["resources"][vdu]["properties"][res] = {
                    "get_resource": res_name
                }


@log.log
def convert_unsupported_res_prop(heat_dict, unsupported_res_prop):
    res_dict = heat_dict['resources']

    for res, attr in (res_dict).items():
        res_type = attr['type']
        if res_type in unsupported_res_prop:
            prop_dict = attr['properties']
            unsupported_prop_dict = unsupported_res_prop[res_type]
            unsupported_prop = set(prop_dict.keys()) & set(
                unsupported_prop_dict.keys())
            for prop in unsupported_prop:
                    # some properties are just punted to 'value_specs'
                    # property if they are incompatible
                    new_prop = unsupported_prop_dict[prop]
                    if new_prop == 'value_specs':
                        prop_dict.setdefault(new_prop, {})[
                            prop] = prop_dict.pop(prop)
                    else:
                        prop_dict[new_prop] = prop_dict.pop(prop)


@log.log
def represent_odict(dump, tag, mapping, flow_style=None):
    value = []
    node = yaml.MappingNode(tag, value, flow_style=flow_style)
    if dump.alias_key is not None:
        dump.represented_objects[dump.alias_key] = node
    best_style = True
    if hasattr(mapping, 'items'):
        mapping = mapping.items()
    for item_key, item_value in mapping:
        node_key = dump.represent_data(item_key)
        node_value = dump.represent_data(item_value)
        if not (isinstance(node_key, yaml.ScalarNode) and not node_key.style):
            best_style = False
        if not (isinstance(node_value, yaml.ScalarNode)
                and not node_value.style):
            best_style = False
        value.append((node_key, node_value))
    if flow_style is None:
        if dump.default_flow_style is not None:
            node.flow_style = dump.default_flow_style
        else:
            node.flow_style = best_style
    return node



@log.log
def post_process_heat_template(heat_tpl, mgmt_ports, metadata,
                               alarm_resources, res_tpl, vol_res={},
                               unsupported_res_prop=None, unique_id=None):
    #
    # TODO(bobh) - remove when heat-translator can support literal strings.
    #
    def fix_user_data(user_data_string):
        user_data_string = re.sub('user_data: #', 'user_data: |\n        #',
                                  user_data_string, re.MULTILINE)
        return re.sub('\n\n', '\n', user_data_string, re.MULTILINE)

    heat_tpl = fix_user_data(heat_tpl)
    #
    # End temporary workaround for heat-translator
    #
    heat_dict = yamlparser.simple_ordered_parse(heat_tpl)
    for outputname, portname in mgmt_ports.items():
        ipval = {'get_attr': [portname, 'fixed_ips', 0, 'ip_address']}
        output = {outputname: {'value': ipval}}
        if 'outputs' in heat_dict:
            heat_dict['outputs'].update(output)
        else:
            heat_dict['outputs'] = output
        LOG.debug('Added output for %s', outputname)
    if metadata.get('vdus'):
        for vdu_name, metadata_dict in metadata['vdus'].items():
            metadata_dict['metering.server_group'] = \
                (metadata_dict['metering.server_group'] + '-' + unique_id)[:15]
            if heat_dict['resources'].get(vdu_name):
                heat_dict['resources'][vdu_name]['properties']['metadata'] =\
                    metadata_dict
    add_resources_tpl(heat_dict, res_tpl)

    query_metadata = alarm_resources.get('query_metadata')
    alarm_actions = alarm_resources.get('alarm_actions')
    event_types = alarm_resources.get('event_types')
    if query_metadata:
        for trigger_name, matching_metadata_dict in query_metadata.items():
            if heat_dict['resources'].get(trigger_name):
                query_mtdata = dict()
                query_mtdata['query'] = \
                    query_metadata[trigger_name]
                heat_dict['resources'][trigger_name][
                    'properties'].update(query_mtdata)
    if alarm_actions:
        for trigger_name, alarm_actions_dict in alarm_actions.items():
            if heat_dict['resources'].get(trigger_name):
                heat_dict['resources'][trigger_name]['properties']. \
                    update(alarm_actions_dict)

    if event_types:
        for trigger_name, event_type in event_types.items():
            if heat_dict['resources'].get(trigger_name):
                heat_dict['resources'][trigger_name]['properties'].update(
                    event_type)

    for res in heat_dict["resources"].values():
        if not res['type'] == HEAT_SOFTWARE_CONFIG:
            continue
        config = res["properties"]["config"]
        if 'get_file' in config:
            res["properties"]["config"] = open(config["get_file"]).read()

    if vol_res.get('volumes'):
        add_volume_resources(heat_dict, vol_res)
    if unsupported_res_prop:
        convert_unsupported_res_prop(heat_dict, unsupported_res_prop)

    yaml.SafeDumper.add_representer(OrderedDict,
    lambda dumper, value: represent_odict(dumper,
                                          u'tag:yaml.org,2002:map', value))
    return yaml.safe_dump(heat_dict)
