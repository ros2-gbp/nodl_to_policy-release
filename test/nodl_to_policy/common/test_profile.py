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

from lxml import etree
from lxml.builder import E
import nodl_to_policy.common.profile as common_profile
import pytest


def test_common_profile(mocker):
    """Test that the `common_profile` function makes a call to `_get_profile`, as expected."""
    common_profile_mock = mocker.patch(
        'nodl_to_policy.common.profile._get_profile',
        autospec=True)
    common_profile.common_profile()
    assert common_profile_mock.call_count == 1


def test_common_subscribe_topics(mocker):
    """Test that `common_subscribe_topics` calls `_get_items_by_role` correctly."""
    get_items_mock = mocker.patch(
        'nodl_to_policy.common.profile._get_items_by_role',
        autospec=True)
    common_profile.common_subscribe_topics()
    assert get_items_mock.call_count == 1
    assert ('topics', 'subscribe') == get_items_mock.call_args.args


def test_common_publish_topics(mocker):
    """Test that `common_publish_topics` calls `_get_items_by_role` correctly."""
    get_items_mock = mocker.patch(
        'nodl_to_policy.common.profile._get_items_by_role',
        autospec=True)
    common_profile.common_publish_topics()
    assert get_items_mock.call_count == 1
    assert ('topics', 'publish') == get_items_mock.call_args.args


def test_common_reply_services(mocker):
    """Test that `common_reply_services` calls `_get_items_by_role` correctly."""
    get_items_mock = mocker.patch(
        'nodl_to_policy.common.profile._get_items_by_role',
        autospec=True)
    common_profile.common_reply_services()
    assert get_items_mock.call_count == 1
    assert ('services', 'reply') == get_items_mock.call_args.args


def test_common_request_services(mocker):
    """Test that `common_request_services` calls `_get_items_by_role` correctly."""
    get_items_mock = mocker.patch(
        'nodl_to_policy.common.profile._get_items_by_role',
        autospec=True)
    common_profile.common_request_services()
    assert get_items_mock.call_count == 1
    assert ('services', 'request') == get_items_mock.call_args.args


def test__get_profile_invalid():
    """Test that `_get_profile` throws with an empty XML path."""
    with pytest.raises(etree.XMLSyntaxError) as _:
        common_profile._get_profile('')


def test__get_profile(common_profile_tree):
    """Test that `_get_profile` returns the correct common permissions XML tree."""
    test_profile = common_profile._get_profile('node.xml').getroot()

    print(etree.tostring(test_profile, pretty_print=True).decode())

    test_profile_pub_topics = test_profile.findall(
        f'topics[@publish="ALLOW"]')
    test_pub_topics = []
    for topics in test_profile_pub_topics:
        for topic in topics:
            test_pub_topics.append(topic.text)
    pub_topics = ['rosout', '/parameter_events']

    test_profile_sub_topics = test_profile.findall(
        f'topics[@subscribe="ALLOW"]')
    test_sub_topics = []
    for topics in test_profile_sub_topics:
        for topic in topics:
            test_sub_topics.append(topic.text)
    sub_topics = ['/clock', '/parameter_events']

    test_profile_reply_services = test_profile.find(
        f'services[@reply="ALLOW"]')
    services = ['~/describe_parameters', '~/get_parameter_types',
                '~/get_parameters', '~/list_parameters',
                '~set_parameters', '~/set_parameters_atomically']
    test_reply_services = []
    for services in test_profile_reply_services:
        for service in services:
            test_reply_services.append(service.text)

    test_profile_request_services = test_profile.find(
        f'services[@request="ALLOW"]')
    test_request_services = []
    for services in test_profile_request_services:
        for service in services:
            test_request_services.append(service.text)

    assert len(test_pub_topics) == len(pub_topics)
    print(test_pub_topics)
    assert all([pub_topic in test_pub_topics for pub_topic in pub_topics])

    assert len(test_sub_topics) == len(sub_topics)
    assert all([sub_topic in test_sub_topics for sub_topic in sub_topics])

    assert len(test_reply_services) == len(services)
    assert all([service in test_reply_services for service in services])

    assert len(test_request_services) == len(services)
    assert all([service in test_request_services for service in services])


def test__get_items_by_role_empty_request():
    """Test that `_get_items_by_role` correctly returns an empty list for empty requests."""
    assert not common_profile._get_items_by_role('', '')


def test__get_items_by_role_no_items():
    """Test that `_get_items_by_role` returns an empty list for non-existent combinations."""
    assert not common_profile._get_items_by_role('actions', 'reply')


@pytest.fixture
def simple_profile() -> etree._ElementTree:
    return E.profile(
        E.topics(
            E.topic('foo'),
            publish='ALLOW',
        )
    )


def test__get_items_by_role(mocker, simple_profile):
    """Test that `_get_items_by_role` returns the correct list of items for proper requests."""
    mocker.patch(
        'nodl_to_policy.common.profile.common_profile',
        return_value=simple_profile
    )

    assert len(common_profile._get_items_by_role('topics', 'publish')) == 1
    assert common_profile._get_items_by_role('topics', 'publish')[0].text == 'foo'
