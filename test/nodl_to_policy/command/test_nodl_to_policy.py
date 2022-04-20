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

import nodl_to_policy.command.nodl_to_policy
import pytest


@pytest.fixture
def command():
    return nodl_to_policy.command.nodl_to_policy.NoDLToPolicyCommand()


def test_add_arguments_sets_subparser(mocker, command):
    pass


def test_main(mocker, command):
    parser = mocker.MagicMock()
    args = mocker.MagicMock()

    # Returns `main` when a verb is provided
    assert command.main(parser=parser, args=args) == args._verb.main(args=args)

    # Prints help when no verb is provided
    del args._verb
    command._subparser = mocker.MagicMock()
    assert command.main(parser=parser, args=args) == 0

    command._subparser.print_help.assert_called_once()
