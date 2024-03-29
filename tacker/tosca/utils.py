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



@log.log
def add_volume_resources(heat_dict, vol_res):
    # Add cinder volumes
    for res_name, cinder_vol in vol_res['volumes'].items():
        heat_dict['resources'][res_name] = {
            'type': 'OS::Cinder::Volume',
            'properties': {}
        }
        for prop_name, prop_val in cinder_vol.items():
            heat_dict['resources'][res_name]['properties'][prop_name] = \
                prop_val
    # Add cinder volume attachments
    for res_name, cinder_vol in vol_res['volume_attachments'].items():
        heat_dict['resources'][res_name] = {
            'type': 'OS::Cinder::VolumeAttachment',
            'properties': {}
        }
        for prop_name, prop_val in cinder_vol.items():
            heat_dict['resources'][res_name]['properties'][prop_name] = \
                prop_val


@log.log
def post_process_template(template):
    def _add_scheduler_hints_property(nt):
        hints = nt.get_property_value('scheduler_hints')
        if hints is None:
            hints = OrderedDict()
            hints_schema = {'type': 'map', 'required': False,
                            'entry_schema': {'type': 'string'}}
            hints_prop = properties.Property('scheduler_hints',
                                             hints,
                                             hints_schema)
            nt.get_properties_objects().append(hints_prop)
        return hints

    for nt in template.nodetemplates:
        if (nt.type_definition.is_derived_from(MONITORING) or
            nt.type_definition.is_derived_from(FAILURE) or
                nt.type_definition.is_derived_from(PLACEMENT)):
            template.nodetemplates.remove(nt)
            continue

        if nt.type in delpropmap.keys():
            for prop in delpropmap[nt.type]:
                for p in nt.get_properties_objects():
                    if prop == p.name:
                        nt.get_properties_objects().remove(p)

        # change the property value first before the property key
        if nt.type in convert_prop_values:
            for prop in convert_prop_values[nt.type].keys():
                for p in nt.get_properties_objects():
                    if (prop == p.name and
                            p.value in
                            convert_prop_values[nt.type][prop].keys()):
                        v = convert_prop_values[nt.type][prop][p.value]
                        p.value = v

        if nt.type in convert_prop:
            for prop in convert_prop[nt.type].keys():
                for p in nt.get_properties_objects():
                    if prop == p.name:
                        schema_dict = {'type': p.type}
                        v = nt.get_property_value(p.name)
                        newprop = properties.Property(
                            convert_prop[nt.type][prop], v, schema_dict)
                        nt.get_properties_objects().append(newprop)
                        nt.get_properties_objects().remove(p)

        if nt.type_definition.is_derived_from(TACKERVDU):
            reservation_metadata = nt.get_property_value(
                'reservation_metadata')
            if reservation_metadata is not None:
                hints = _add_scheduler_hints_property(nt)

                input_resource_type = reservation_metadata.get(
                    'resource_type')
                input_id = reservation_metadata.get('id')

                # Checking if 'resource_type' and 'id' is passed through a
                # input parameter file or not. If it's then get the value
                # from input parameter file.
                if (isinstance(input_resource_type, OrderedDict) and
                        input_resource_type.get('get_input')):
                    input_resource_type = template.parsed_params.get(
                        input_resource_type.get('get_input'))
                # TODO(niraj-singh): Remove this validation once bug
                # 1815755 is fixed.
                if input_resource_type not in (
                        'physical_host', 'virtual_instance'):
                    raise exceptions.Invalid(
                        'resoure_type must be physical_host'
                        ' or virtual_instance')

                if (isinstance(input_id, OrderedDict) and
                        input_id.get('get_input')):
                    input_id = template.parsed_params.get(
                        input_id.get('get_input'))

                if input_resource_type == 'physical_host':
                    hints['reservation'] = input_id
                elif input_resource_type == 'virtual_instance':
                    hints['group'] = input_id
                nt.get_properties_objects().remove(nt.get_properties().get(
                    'reservation_metadata'))


@log.log
def get_mgmt_driver(template):
    mgmt_driver = None
    for nt in template.nodetemplates:
        if nt.type_definition.is_derived_from(TACKERVDU):
            if (mgmt_driver and nt.get_property_value('mgmt_driver') !=
                    mgmt_driver):
                raise vnfm.MultipleMGMTDriversSpecified()
            else:
                mgmt_driver = nt.get_property_value('mgmt_driver')

    return mgmt_driver


def findvdus(template):
    vdus = []
    for nt in template.nodetemplates:
        if nt.type_definition.is_derived_from(TACKERVDU):
            vdus.append(nt)
    return vdus


def get_maintenance_vdus(template):
    maintenance_vdu_names = list()
    vdus = findvdus(template)
    for nt in vdus:
        if nt.get_properties().get('maintenance'):
            maintenance_vdu_names.append(nt.name)
    return maintenance_vdu_names


def get_flavor_dict(template, flavor_extra_input=None):
    flavor_dict = {}
    vdus = findvdus(template)
    for nt in vdus:
        flavor_tmp = nt.get_properties().get('flavor')
        if flavor_tmp:
            continue
        if nt.get_capabilities().get("nfv_compute"):
            flavor_dict[nt.name] = {}
            properties = nt.get_capabilities()["nfv_compute"].get_properties()
            for prop, (hot_prop, default, unit) in \
                    (FLAVOR_PROPS).items():
                hot_prop_val = (properties[prop].value
                                if properties.get(prop, None) else None)
                if unit and hot_prop_val:
                    hot_prop_val = \
                        utils.change_memory_unit(hot_prop_val, unit)
                flavor_dict[nt.name][hot_prop] = \
                    hot_prop_val if hot_prop_val else default
            if any(p in properties for p in FLAVOR_EXTRA_SPECS_LIST):
                flavor_dict[nt.name]['extra_specs'] = {}
                es_dict = flavor_dict[nt.name]['extra_specs']
                populate_flavor_extra_specs(es_dict, properties,
                                            flavor_extra_input)
    return flavor_dict



def populate_flavor_extra_specs(es_dict, properties, flavor_extra_input):
    if 'mem_page_size' in properties:
        mval = properties['mem_page_size'].value
        if str(mval).isdigit():
            mval = mval * 1024
        elif mval not in ('small', 'large', 'any'):
            raise vnfm.HugePageSizeInvalidInput(
                error_msg_details=(mval + ":Invalid Input"))
        es_dict['hw:mem_page_size'] = mval
    if 'numa_nodes' in properties and 'numa_node_count' in properties:
        LOG.warning('Both numa_nodes and numa_node_count have been '
                    'specified; numa_node definitions will be ignored and '
                    'numa_node_count will be applied')
    if 'numa_node_count' in properties:
        es_dict['hw:numa_nodes'] = \
            properties['numa_node_count'].value
    if 'numa_nodes' in properties and 'numa_node_count' not in properties:
        nodes_dict = dict(properties['numa_nodes'].value)
        dval = list(nodes_dict.values())
        ncount = 0
        for ndict in dval:
            invalid_input = set(ndict.keys()) - {'id', 'vcpus', 'mem_size'}
            if invalid_input:
                raise vnfm.NumaNodesInvalidKeys(
                    error_msg_details=(', '.join(invalid_input)),
                    valid_keys="id, vcpus and mem_size")
            if 'id' in ndict and 'vcpus' in ndict:
                vk = "hw:numa_cpus." + str(ndict['id'])
                vval = ",".join([str(x) for x in ndict['vcpus']])
                es_dict[vk] = vval
            if 'id' in ndict and 'mem_size' in ndict:
                mk = "hw:numa_mem." + str(ndict['id'])
                es_dict[mk] = ndict['mem_size']
            ncount += 1
        es_dict['hw:numa_nodes'] = ncount
    if 'cpu_allocation' in properties:
        cpu_dict = dict(properties['cpu_allocation'].value)
        invalid_input = set(cpu_dict.keys()) - CPU_PROP_KEY_SET
        if invalid_input:
            raise vnfm.CpuAllocationInvalidKeys(
                error_msg_details=(', '.join(invalid_input)),
                valid_keys=(', '.join(CPU_PROP_KEY_SET)))
        for(k, v) in CPU_PROP_MAP:
            if v not in cpu_dict:
                continue
            if CPU_PROP_VAL_MAP.get(v, None):
                if cpu_dict[v] not in CPU_PROP_VAL_MAP[v]:
                    raise vnfm.CpuAllocationInvalidValues(
                        error_msg_details=cpu_dict[v],
                        valid_values=CPU_PROP_VAL_MAP[v])
            es_dict[k] = cpu_dict[v]
    if flavor_extra_input:
        es_dict.update(flavor_extra_input)



def get_image_dict(template):
    image_dict = {}
    vdus = findvdus(template)
    for vdu in vdus:
        if not vdu.entity_tpl.get("artifacts"):
            continue
        artifacts = vdu.entity_tpl["artifacts"]
        for name, artifact in (artifacts).items():
            if ('type' in artifact.keys() and
               artifact["type"] == IMAGE):
                if 'file' not in artifact.keys():
                    raise vnfm.FilePathMissing()
                image_dict[vdu.name] = {
                    "location": artifact["file"],
                    "container_format": "bare",
                    "disk_format": "raw",
                    "name": name
                }
    return image_dict


def get_resources_dict(template, flavor_extra_input=None):
    res_dict = dict()
    for res, method in (OS_RESOURCES).items():
        res_method = getattr(sys.modules[__name__], method)
        if res is 'flavor':
            res_dict[res] = res_method(template, flavor_extra_input)
        else:
            res_dict[res] = res_method(template)
    return res_dict


def get_resources_for_maintenance(template, res_dict):
    res_dict['maintenance'] = dict()
    for vdu_name in get_maintenance_vdus(template):
        res_dict["maintenance"][vdu_name] = {}

    return res_dict



@log.log
def get_scaling_policy(template):
    scaling_policy_names = list()
    for policy in template.policies:
        if (policy.type_definition.is_derived_from(SCALING)):
            scaling_policy_names.append(policy.name)
    return scaling_policy_names


@log.log
def get_scaling_group_dict(ht_template, scaling_policy_names):
    scaling_group_dict = dict()
    scaling_group_names = list()
    heat_dict = yamlparser.simple_ordered_parse(ht_template)
    for resource_name, resource_dict in heat_dict['resources'].items():
        if resource_dict['type'] == SCALE_GROUP_RESOURCE:
            scaling_group_names.append(resource_name)
    if scaling_group_names:
        scaling_group_dict[scaling_policy_names[0]] = scaling_group_names[0]
    return scaling_group_dict


def get_nested_resources_name(template):
    for policy in template.policies:
        if (policy.type_definition.is_derived_from(SCALING)):
            nested_resource_name = policy.name + '_res.yaml'
            return nested_resource_name


def get_sub_heat_tmpl_name(template):
    for policy in template.policies:
        if (policy.type_definition.is_derived_from(SCALING)):
            sub_heat_tmpl_name = policy.name + '_' + \
                uuidutils.generate_uuid() + '_res.yaml'
            return sub_heat_tmpl_name



def update_nested_scaling_resources(nested_resources, mgmt_ports, metadata,
                                    res_tpl, unsupported_res_prop=None):
    nested_tpl = dict()
    if nested_resources:
        nested_resource_name, nested_resources_yaml =\
            list(nested_resources.items())[0]
        nested_resources_dict =\
            yamlparser.simple_ordered_parse(nested_resources_yaml)
        if metadata.get('vdus'):
            for vdu_name, metadata_dict in metadata['vdus'].items():
                if nested_resources_dict['resources'].get(vdu_name):
                    nested_resources_dict['resources'][vdu_name]['properties']['metadata'] = \
                        metadata_dict
        add_resources_tpl(nested_resources_dict, res_tpl)
        for res in nested_resources_dict["resources"].values():
            if not res['type'] == HEAT_SOFTWARE_CONFIG:
                continue
            config = res["properties"]["config"]
            if 'get_file' in config:
                res["properties"]["config"] = open(config["get_file"]).read()

        if unsupported_res_prop:
            convert_unsupported_res_prop(nested_resources_dict,
                                         unsupported_res_prop)

        for outputname, portname in mgmt_ports.items():
            ipval = {'get_attr': [portname, 'fixed_ips', 0, 'ip_address']}
            output = {outputname: {'value': ipval}}
            if 'outputs' in nested_resources_dict:
                nested_resources_dict['outputs'].update(output)
            else:
                nested_resources_dict['outputs'] = output
            LOG.debug(_('Added output for %s'), outputname)
            yaml.SafeDumper.add_representer(
                OrderedDict, lambda dumper, value: represent_odict(
                    dumper, u'tag:yaml.org,2002:map', value))
            nested_tpl[nested_resource_name] =\
                yaml.safe_dump(nested_resources_dict)
    return nested_tpl

