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

import argparse

import nodl
from nodl_to_policy.verb import convert
import pytest


@pytest.fixture
def verb() -> convert.ConvertVerb:
    return convert.ConvertVerb()


@pytest.fixture
def parser(verb):
    parser = argparse.ArgumentParser()
    verb.add_arguments(parser)
    return parser


def test_accepts_valid_nodl_path(mocker, parser, test_nodl_path, verb):
    mocker.patch('nodl_to_policy.verb.convert.convert_to_policy')
    mocker.patch('nodl_to_policy.verb.convert.print_policy')

    args = parser.parse_args([str(test_nodl_path)])
    assert not verb.main(args=args)


def test_fails_no_nodl_file(mocker, parser, tmp_path, verb):
    mocker.patch('nodl_to_policy.verb.convert.pathlib.Path.cwd', return_value=tmp_path)

    args = parser.parse_args([''])
    assert verb.main(args=args)


def test_fails_sneaky_dir(mocker, parser, tmp_path, verb):
    sneakydir = tmp_path / 'test.nodl.xml'
    sneakydir.mkdir()

    args = parser.parse_args([str(tmp_path.resolve())])
    assert verb.main(args=args)


def test_accepts_valid_nodl(mocker, parser, test_nodl_path, verb):
    args = parser.parse_args([str(test_nodl_path)])

    assert not verb.main(args=args)


def test_fails_invalid_nodl(mocker, parser, test_nodl_invalid_path, verb):
    # Check that the NoDL parser throws with an invalid NoDL file
    mocker.patch(
        'nodl_to_policy.verb.convert.nodl.parse',
        side_effect=nodl.errors.InvalidNoDLError(mocker.MagicMock()),
    )
    args = parser.parse_args([str(test_nodl_invalid_path)])

    assert verb.main(args=args)
