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
