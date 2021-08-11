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

from typing import List

from lxml import etree
try:
    import importlib.resources as importlib_resources
except ModuleNotFoundError:
    import importlib_resources  # type: ignore


# TODO(aprotyas): For now, only use `node.xml`, since NoDL does not describe Lifecycle nodes
def common_profile() -> etree._ElementTree:
    return _get_profile('node.xml')


def common_subscribe_topics() -> List:
    return _get_items_by_role('topics', 'subscribe')


def common_publish_topics() -> List:
    return _get_items_by_role('topics', 'publish')


def common_reply_services() -> List:
    return _get_items_by_role('services', 'reply')


def common_request_services() -> List:
    return _get_items_by_role('services', 'request')


def _get_profile(filename: str) -> etree._ElementTree:
    with importlib_resources.path('nodl_to_policy.common', filename) as path:
        profile = etree.parse(str(path))
    profile.xinclude()
    return profile


def _get_items_by_role(item_type: str, role: str) -> List[etree._ElementTree]:
    items_list: List[etree._ElementTree] = []
    # Terminate the function for empty queries, prevents predicate errors in the find operation
    if not item_type or not role:
        return items_list
    # Find `item_type` (topic/service) tags with an allowed `role` (pub/sub/reply/req) attribute
    for items in common_profile().findall(f'{item_type}[@{role}="ALLOW"]'):
        # Child tags are: topics -> topic, services -> service
        for item in items.iter(item_type[:-1]):
            items_list.append(item)
    return items_list
