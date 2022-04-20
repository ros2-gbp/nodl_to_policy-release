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
import nodl
import nodl._parsing
import nodl_to_policy.policy as policy
import pytest
import sros2


def test_init_policy():
    """Test that an initial empty policy is well-formed."""
    test_policy = policy.init_policy()
    assert test_policy.tag == 'policy'
    assert test_policy.attrib['version'] == sros2.policy.POLICY_VERSION
    assert len(test_policy) == 1
    assert test_policy[0].tag == 'enclaves'
    assert len(test_policy[0]) == 0


def test_get_profile_minimal():
    """Test an XML tree with no pre-existing `enclaves`/`profiles`/`profile` tags."""
    test_policy = policy.init_policy()
    test_profile = policy.get_profile(test_policy, node_name='foo')
    # empty tags get generated after `get_profile` is called
    test_enclaves = test_policy[0]
    test_enclave = test_enclaves[0]
    test_profiles = test_enclave[0]

    # check that a single enclave tag was created
    assert len(test_enclaves) == 1
    assert test_enclave.tag == 'enclave'
    assert test_enclave.attrib['path'] == '/foo'

    # check that a single profiles tag was created
    assert len(test_enclave) == 1
    assert test_profiles.tag == 'profiles'

    # check that a single profile tag was created
    assert len(test_profiles) == 1
    assert test_profiles[0] == test_profile
    assert test_profile.tag == 'profile'
    assert test_profile.attrib['ns'] == '/'
    assert test_profile.attrib['node'] == 'foo'
    assert len(test_profile) == 0


def test_get_profile_exists(test_policy_tree):
    """
    Test an XML tree with existing `enclaves`/`profiles`/`profile` tags.

    A lot of checks in this test are to ensure that the
    `get_profile` function does not alter an existing policy tree.
    """
    test_policy = test_policy_tree
    test_enclaves = test_policy.find(path='enclaves')
    test_enclave = test_enclaves.find(path=f'enclave[@path="/node_1"]')
    test_profiles = test_enclave.find(path='profiles')
    test_profile = policy.get_profile(test_policy, node_name='node_1')

    # check that a single enclaves tag exists
    assert test_policy[0] == test_enclaves
    assert len(test_enclaves) == 2  # check that 'enclaves' tree contains two children
    assert test_enclaves.tag == 'enclaves'

    # check that a single enclave tag exists
    assert test_enclaves[0] == test_enclave
    assert len(test_enclave) == 1  # check that 'enclave' tree contains one child ('profiles')
    assert test_enclave.tag == 'enclave'
    assert test_enclave.attrib['path'] == '/node_1'

    # check that a single profiles tag exists
    assert test_enclave[0] == test_profiles
    assert len(test_profiles) == 1  # one node per enclave, one profile tag for each
    assert test_profiles.tag == 'profiles'

    # check that a <profile node='node1'> tag exists as expected
    assert test_profiles.find(path=f'profile[@ns="/"][@node="node_1"]') == test_profile
    assert test_profile.tag == 'profile'
    assert test_profile.attrib['ns'] == '/'
    assert test_profile.attrib['node'] == 'node_1'
    assert len(test_profile) == 4  # four child tags in the <profile node="node_1> tree


def test_get_permissions_minimal():
    """Test a profile tree with no permissions tag."""
    test_empty_profile = etree.Element('profile', attrib={'ns': '/', 'node': 'foo'})
    test_permissions = policy.get_permissions(
        profile=test_empty_profile,
        permission_type='permission',
        rule_type='rule',
        rule_expression='ALLOW')

    assert len(test_empty_profile) == 1  # only one 'permissions' tag
    assert test_empty_profile.find(path='permissions[@rule="ALLOW"]') == test_permissions
    assert test_permissions.tag == 'permissions'
    assert test_permissions.attrib['rule'] == 'ALLOW'
    assert len(test_permissions) == 0  # no permissions added


def test_get_permissions_exists(test_policy_tree):
    """
    Test an XML tree with existing `enclaves`/`profiles`/`profile` tags.

    A lot of checks in this test are to ensure that the
    `get_profile` function does not alter an existing policy tree.
    """
    test_profile = test_policy_tree.find(
        path='enclaves/enclave[@path="/node_1"]/profiles/profile[@ns="/"][@node="node_1"]')
    test_permissions = policy.get_permissions(
        profile=test_profile,
        permission_type='topic',
        rule_type='publish',
        rule_expression='ALLOW')

    assert len(test_profile) == 4  # number of rule tags is unchanged
    assert test_profile.find(path='topics[@publish="ALLOW"]') == test_permissions
    assert test_permissions.tag == 'topics'
    assert test_permissions.attrib['publish'] == 'ALLOW'
    assert len(test_permissions) == 3  # number of publish topics is unchanged


def test_add_permissions_no_items(mocker):
    """
    Test that permissions are correctly added when no allowed items are provided.

    It checks that the `get_permissions` function is run 0 times.
    """
    get_permissions_mock = mocker.patch('nodl_to_policy.policy.get_permissions', autospec=True)
    policy.add_permissions(
        profile=etree.Element('foo'),
        node=nodl.types.Node(name='bar', executable='prog'),
        permission_type='fizz',
        rule_type='buzz',
        expressions=[])

    assert not get_permissions_mock.call_count


def test_add_permissions_minimal():
    """Test a profile tree with no permissions tag."""
    test_empty_profile = etree.Element('profile', attrib={'ns': '/', 'node': 'foo'})
    policy.add_permissions(
        profile=test_empty_profile,
        node=nodl.types.Node(name='node', executable='prog'),  # foo?
        permission_type='topic',
        rule_type='publish',
        expressions=['item'])

    test_permissions = test_empty_profile.find(path='topics[@publish="ALLOW"]')
    assert test_permissions.tag == 'topics'
    assert test_permissions.attrib['publish'] == 'ALLOW'
    assert len(test_permissions) == 1
    test_permission = test_permissions.find(path='topic')
    assert test_permission.tag == 'topic'
    assert test_permission.text == 'item'


def test_add_permissions_exists(test_policy_tree):
    """Test a profile tree with pre-existing permissions."""
    test_profile = test_policy_tree.find(
        path='enclaves/enclave[@path="/node_1"]/profiles/profile[@ns="/"][@node="node_1"]')

    policy.add_permissions(
        profile=test_profile,
        node=nodl.types.Node(name='node', executable='prog'),
        permission_type='topic',
        rule_type='publish',
        expressions=['item'])

    test_permissions = test_profile.find(path='topics[@publish="ALLOW"]')
    assert test_permissions.tag == 'topics'
    assert test_permissions.attrib['publish'] == 'ALLOW'
    assert len(test_permissions) == 4
    test_permission_items = test_permissions.findall(path='topic')
    assert 'item' in [item.text for item in test_permission_items]


def test_add_common_permissions_minimal(helpers, common_profile_tree):
    """Test addition of common permissions to an empty profile tree."""
    test_empty_profile = etree.Element('profile', attrib={'ns': '/', 'node': 'foo'})
    policy.add_common_permissions(
        profile=test_empty_profile,
        node=nodl.types.Node(name='node', executable='prog')  # foo
    )

    assert helpers.xml_trees_equal(common_profile_tree, test_empty_profile)


def test_add_common_permissions_exists(helpers, test_policy_tree):
    """Test addition of common permissions to a profile tree with pre-existing permission tags."""
    test_profile = test_policy_tree.find(
        path='enclaves/enclave[@path="/node_1"]/profiles/profile[@ns="/"][@node="node_1"]')
    policy.add_common_permissions(
        test_profile, node=nodl.types.Node(name='node', executable='prog'))

    assert helpers.xml_trees_equal(
        test_profile,
        test_policy_tree.find(
            path='enclaves/enclave[@path="/node_1"]/profiles/profile[@ns="/"][@node="node_1"]')
    )


def test_convert_to_policy_invalid(empty_nodl_path):
    """Test NoDL conversion with an invalid path."""
    with pytest.raises(nodl.errors.NoDLError) as _:
        policy.convert_to_policy(
            nodl_description=nodl.parse(empty_nodl_path))


def test_convert_to_policy(helpers, test_nodl_path, test_policy_tree):
    """Test NoDL conversion with a fully formed description."""
    test_nodl_description = nodl.parse(test_nodl_path)
    test_converted_policy = policy.convert_to_policy(test_nodl_description)

    policy_xsl_path = sros2.policy.get_policy_template('policy.xsl')
    policy_xsl = etree.XSLT(etree.parse(str(policy_xsl_path)))
    test_converted_policy = policy_xsl(test_converted_policy).getroot()

    assert helpers.xml_trees_equal(test_converted_policy, test_policy_tree)


def test_print_policy(capfd, test_policy_tree):
    """
    Test the policy printing functionality.

    This works by comparing the standard output to the expected string form of the policy XML.
    """
    # the `capfd` fixture captures `stdout`/`stderr`
    policy.print_policy(test_policy_tree)
    out, _ = capfd.readouterr()  # capture console output
    # assert that standard output is equivalent to pretty printed string form of policy XML tree
    assert out == etree.tostring(test_policy_tree, pretty_print=True).decode()


def test__get_topics_by_role_no_topics():
    """Test that `_get_topics_by_role` returns empty lists for an empty input."""
    # empty dict of topics should return two empty dicts
    test_publish_topics, test_subscribe_topics = policy._get_topics_by_role({})
    assert not test_publish_topics
    assert not test_subscribe_topics


def test__get_topics_by_role():
    """Test that `_get_topics_by_role` separates an input dict of topics correctly."""
    test_topics = {
        'foo': nodl.types.Topic(
            name='foo', message_type='footype', role=nodl.types.PubSubRole('publisher')),
        'bar': nodl.types.Topic(
            name='bar', message_type='bartype', role=nodl.types.PubSubRole('subscription')),
        'fizz': nodl.types.Topic(
            name='fizz', message_type='fizztype', role=nodl.types.PubSubRole('both')),
    }

    test_publish_topics_expected = {
        'foo': nodl.types.Topic(
            name='foo', message_type='footype', role=nodl.types.PubSubRole('publisher')),
        'fizz': nodl.types.Topic(
            name='fizz', message_type='fizztype', role=nodl.types.PubSubRole('both')),
    }

    test_subscribe_topics_expected = {
        'bar': nodl.types.Topic(
            name='bar', message_type='bartype', role=nodl.types.PubSubRole('subscription')),
        'fizz': nodl.types.Topic(
            name='fizz', message_type='fizztype', role=nodl.types.PubSubRole('both')),
    }

    test_subscribe_topics, test_publish_topics = policy._get_topics_by_role(test_topics)
    assert test_publish_topics == test_publish_topics_expected
    assert test_subscribe_topics == test_subscribe_topics_expected


def test__get_services_by_role_no_services():
    """Test that `_get_services_by_role` returns empty lists for an empty input."""
    # empty dict of services should return two empty dicts
    test_reply_services, test_request_services = policy._get_services_by_role({})
    assert not test_reply_services
    assert not test_request_services


def test__get_services_by_role():
    """Test that `_get_services_by_role` separates an input dict of services correctly."""
    test_services = {
        'foo': nodl.types.Service(
            name='foo', service_type='footype', role=nodl.types.ServerClientRole('server')),
        'bar': nodl.types.Service(
            name='bar', service_type='bartype', role=nodl.types.ServerClientRole('client')),
        'fizz': nodl.types.Service(
            name='fizz', service_type='fizztype', role=nodl.types.ServerClientRole('both')),
    }

    test_server_services_expected = {
        'foo': nodl.types.Service(
            name='foo', service_type='footype', role=nodl.types.ServerClientRole('server')),
        'fizz': nodl.types.Service(
            name='fizz', service_type='fizztype', role=nodl.types.ServerClientRole('both')),
    }

    test_client_services_expected = {
        'bar': nodl.types.Service(
            name='bar', service_type='bartype', role=nodl.types.ServerClientRole('client')),
        'fizz': nodl.types.Service(
            name='fizz', service_type='fizztype', role=nodl.types.ServerClientRole('both')),
    }

    test_server_services, test_client_services = policy._get_services_by_role(test_services)
    assert test_server_services == test_server_services_expected
    assert test_client_services == test_client_services_expected


def test__get_actions_by_role(mocker):
    """Test that `_get_actions_by_role` correctly calls `_get_services_by_role`."""
    get_services_mock = mocker.patch('nodl_to_policy.policy._get_services_by_role', autospec=True)

    policy._get_actions_by_role({})
    assert get_services_mock.call_count == 1
    assert not get_services_mock.call_args.args[0]
