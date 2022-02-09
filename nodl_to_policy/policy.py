# Copyright 2021 Open Source Robotics Foundation, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
from typing import Dict, List, Tuple, Union

from lxml import etree

import nodl  # noqa: F401
from nodl.types import (
    Node,
    PubSubRole,
    ServerClientRole,
)

from nodl_to_policy.common.profile import (
    common_publish_topics,
    common_reply_services,
    common_request_services,
    common_subscribe_topics,
)

from sros2.policy import (
    dump_policy,
    POLICY_VERSION,
)


_POLICY_FILE_EXTENSION = '.policy.xml'


def init_policy() -> etree._ElementTree:
    """
    Create a policy element in an LXML ElementTree.

    :return: LXML ElementTree structure representing a "policy" tag.
    :rtype: etree._ElementTree
    """
    enclaves = etree.Element('enclaves')
    policy = etree.Element('policy')
    policy.attrib['version'] = POLICY_VERSION
    policy.append(enclaves)
    return policy


def get_profile(policy: etree._ElementTree, node_name: str) -> etree._ElementTree:
    """
    Return a node's respective profile tag in an LXML ElementTree.

    :param policy: LXML ElementTree structure representing a "policy" tag.
    :type policy: etree._ElementTree
    :param node_name: Node name for which profile is inquired.
    :type node_name: str
    :return: LXML ElementTree structure representing a "profile" tag.
    :rtype: etree._ElementTree
    """
    # Every node is assumed to be in its own enclave
    # This assumption is needed since the NoDL description does not specify enclave paths
    # Moreover, this assumption is better than placing all nodes in the base "/" path
    enclave = policy.find(path=f'enclaves/enclave[@path="/{node_name}"]')
    if enclave is None:
        enclave = etree.Element('enclave')
        enclave.attrib['path'] = f'/{node_name}'
        profiles = etree.Element('profiles')
        enclave.append(profiles)
        enclaves = policy.find('enclaves')
        enclaves.append(enclave)

    profile = enclave.find(path=f'profiles/profile[@ns="/"][@node="{node_name}"]')
    if profile is None:
        profile = etree.Element('profile')
        # namespace information not provided in NoDL description yet
        profile.attrib['ns'] = '/'
        profile.attrib['node'] = node_name
        profiles = enclave.find('profiles')
        profiles.append(profile)

    return profile


def get_permissions(
    profile: etree._ElementTree, permission_type: str, rule_type: str,
    rule_expression: str
) -> etree._ElementTree:
    """
    Return (or create) an appropriate permission (actions/services/topics) tag.

    :param profile: LXML ElementTree structure representing a "policy" tag.
    :type policy: etree._ElementTree
    :param permission_type: One of service/action/topic.
    :type permission_type: str
    :param rule_type: The type of topic (pub/sub) or service/action (req/reply).
    :type rule_type: str
    :param rule_expression: 'ALLOW' or 'DENY'
    :type rule_expression: str
    :return: LXML ElementTree structure representing a services/actions/topics tag.
    :rtype: etree._ElementTree
    """
    permissions = profile.find(path=f'{permission_type}s[@{rule_type}="{rule_expression}"]')
    if permissions is None:
        permissions = etree.Element(permission_type + 's')
        permissions.attrib[rule_type] = rule_expression
        profile.append(permissions)
    return permissions


def add_permissions(
    profile: etree._ElementTree, node: Node, permission_type: str, rule_type: str,
    expressions: Union[Dict, List]
) -> None:
    """
    For each service/action/topic, the actual expression tag is added to the ElementTree.

    :param profile: LXML ElementTree structure representing a "policy" tag.
    :type policy: etree._ElementTree
    :param node: A Node object primarily used to extract a node's name.
    :type node: nodl.types.Node
    :param permission_type: One of service/action/topic.
    :type permission_type: str
    :param rule_type: The type of topic (pub/sub) or service/action (req/reply).
    :type rule_type: str
    :param expressions: A collection of specific service/action/topic names.
    :type expressions: Union[Dict, List]
    """
    # do not create a permissions tag if not required
    if not expressions:
        return
    # get permission
    permissions = get_permissions(profile, permission_type, rule_type, 'ALLOW')

    # add permission
    for expression_name in expressions:
        permission = etree.Element(permission_type)
        if expression_name.startswith(node.name + '/'):
            permission.text = '~' + expression_name[len(node.name):]
        elif expression_name.startswith('/'):
            permission.text = expression_name[len('/'):]
        else:
            permission.text = expression_name
        if permission.text in [expression.text for expression in permissions]:
            continue
        permissions.append(permission)


def add_common_permissions(profile: etree._ElementTree, node: Node) -> None:
    """
    `add_permissions` for each of the common services/topics/actions.

    :param profile: LXML ElementTree structure representing a "policy" tag.
    :type policy: etree._ElementTree
    :param node: A Node object primarily used to extract a node's name.
    :type node: nodl.types.Node
    """
    permission_and_rule_types = {
        'topic': {'subscribe': common_subscribe_topics(), 'publish': common_publish_topics()},
        'service': {'reply': common_reply_services(), 'request': common_request_services()}}

    # For each of the default 'topic'/'service', add that tag under the appropriate permissions tag
    for permission_type, rules_and_items in permission_and_rule_types.items():
        for rule_type, allowed_items in rules_and_items.items():
            add_permissions(
                profile,
                node,
                permission_type,
                rule_type,
                [item.text for item in allowed_items])


def convert_to_policy(nodl_description: List[Node]) -> etree._ElementTree:
    """
    Handle the main logic for conversion from NoDL description to access control policy.

    :param nodl_description: The list of `nodl.Node` objects to add to the policy.
    :type nodl_description: List[nodl.Node]
    :return: LXML ElementTree structure representing a completed "policy" tag.
    :rtype: etree._ElementTree
    """
    policy = init_policy()

    for node in nodl_description:
        # Profile: need to find enclave path and node namespace somehow
        profile = get_profile(policy, node.name)
        # First add all the common (default) permissions for a ROS node
        add_common_permissions(profile, node)

        # TODO(aprotyas): Parameters? Not specified in access control policy
        subscribe_topics, publish_topics = _get_topics_by_role(node.topics)
        reply_services, request_services = _get_services_by_role(node.services)
        reply_actions, request_actions = _get_actions_by_role(node.actions)

        permission_and_rule_types = {
            'topic': {'subscribe': subscribe_topics, 'publish': publish_topics},
            'service': {'reply': reply_services, 'request': request_services},
            'action': {'execute': reply_actions, 'call': request_actions}}

        for permission_type, rules_and_items in permission_and_rule_types.items():
            for rule_type, allowed_items in rules_and_items.items():
                add_permissions(profile, node, permission_type, rule_type, allowed_items)

    return policy


def print_policy(policy: etree._ElementTree) -> None:
    """
    Print a generated policy ElementTree to the console standard output.

    :param policy: LXML ElementTree structure representing a completed "policy" tag.
    :type policy: etree._ElementTree
    :raises RuntimeError: If the policy structure is invalid.
    """
    dump_policy(policy, stream=sys.stdout)


def _get_topics_by_role(topics: Dict) -> Tuple[Dict, Dict]:
    """
    Split the dictionary of all topics into two dictionaries for publish/subscribe topics.

    :param topics: Dictionary representing all topics in a NoDL description.
    :type topics: Dict
    :return: A tuple of dictionaries, one for published topics, and one for subscribed topics.
    :rtype: Tuple[Dict, Dict]
    """
    subscribe_topics = {}
    publish_topics = {}
    for _, topic in topics.items():
        if PubSubRole(topic.role) is PubSubRole.SUBSCRIPTION:
            subscribe_topics[topic.name] = topic
        elif PubSubRole(topic.role) is PubSubRole.PUBLISHER:
            publish_topics[topic.name] = topic
        else:  # PubSubRole(topic.role) is PubSubRole.BOTH
            subscribe_topics[topic.name] = topic
            publish_topics[topic.name] = topic
    return subscribe_topics, publish_topics


def _get_services_by_role(services: Dict) -> Tuple[Dict, Dict]:
    """
    Split the dictionary of all services into two dictionaries for reply/request services.

    :param services: Dictionary representing all services in a NoDL description.
    :type services: Dict
    :return: A tuple of dictionaries, one for reply services, and one for request services.
    :rtype: Tuple[Dict, Dict]
    """
    reply_services = {}
    request_services = {}
    for _, service in services.items():
        if ServerClientRole(service.role) is ServerClientRole.CLIENT:
            request_services[service.name] = service
        elif ServerClientRole(service.role) is ServerClientRole.SERVER:
            reply_services[service.name] = service
        else:  # ServerClientRole(service.role) is ServerClientRole.BOTH
            request_services[service.name] = service
            reply_services[service.name] = service

    return reply_services, request_services


def _get_actions_by_role(actions: Dict) -> Tuple[Dict, Dict]:
    """
    Split the dictionary of all actions into two dictionaries for client/server actions.

    :param actions: Dictionary representing all actions in a NoDL description.
    :type actions: Dict
    :return: A tuple of dictionaries, one for client actions, and one for server actions.
    :rtype: Tuple[Dict, Dict]
    """
    return _get_services_by_role(actions)  # `nodl.types.Action` also share ServerClientRole enums
