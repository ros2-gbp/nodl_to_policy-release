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

from pathlib import Path

from lxml import etree
from lxml.builder import E
import pytest


fixtures_dir = 'fixtures'


@pytest.fixture
def test_nodl_path():
    return Path(__file__).parent / fixtures_dir / 'test.nodl.xml'


@pytest.fixture
def test_nodl_tree():
    nodl_path = Path(__file__).parent / fixtures_dir / 'test.nodl.xml'
    nodl_tree = etree.parse(str(nodl_path))
    nodl_tree.xinclude()
    return nodl_tree.getroot()


@pytest.fixture
def test_nodl_invalid_path():
    return Path(__file__).parent / fixtures_dir / 'test_invalid.nodl.xml'


@pytest.fixture
def test_policy_path():
    return Path(__file__).parent / fixtures_dir / 'test.policy.xml'


@pytest.fixture
def test_policy_tree():
    policy_path = Path(__file__).parent / fixtures_dir / 'test.policy.xml'
    policy_tree = etree.parse(str(policy_path))
    policy_tree.xinclude()
    return policy_tree.getroot()


@pytest.fixture
def common_profile_tree() -> etree._ElementTree:
    profile_path = Path(__file__).parent / fixtures_dir / 'common_profile.xml'
    profile_tree = etree.parse(str(profile_path))
    return profile_tree.getroot()


@pytest.fixture
def empty_nodl_path(tmp_path):
    nodl_tree = E.interface(version='1')
    nodl_path = tmp_path / 'empty.nodl.xml'
    etree.ElementTree(nodl_tree).write(str(nodl_path), pretty_print=True)
    return nodl_path


class Helpers:

    @staticmethod
    def text_equal(s1: str, s2: str) -> bool:
        """Accounting for whitespaces, return True if two pieces of text are equivalent."""
        if s1 == s2:
            return True
        elif not s1 and s2.isspace():
            return True
        elif not s2 and s1.isspace():
            return True
        elif s1.isspace() and s2.isspace():
            return True
        else:
            return False

    @staticmethod
    def xml_trees_equal(t1: etree._ElementTree, t2: etree._ElementTree) -> bool:
        """Check if two XML trees are equivalent to each other."""
        if not Helpers.text_equal(t1.tag, t2.tag):
            return False
        if not Helpers.text_equal(t1.text, t2.text):
            return False
        if not Helpers.text_equal(t1.tail, t2.tail):
            return False
        if t1.attrib != t2.attrib:
            return False
        if len(t1) != len(t2):
            return False
        return all(Helpers.xml_trees_equal(_t1, _t2) for _t1, _t2 in zip(t1, t2))


@pytest.fixture
def helpers():
    return Helpers
