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
from typing import Any, List, Optional

from ros2cli.command import add_subparsers_on_demand
from ros2cli.command import CommandExtension


class NoDLToPolicyCommand(CommandExtension):
    """Convert node interface descriptions exported from packages."""

    def add_arguments(
            self, parser: argparse.ArgumentParser, cli_name: str, *, argv: Optional[List] = None):
        """Get verb extensions and let them add their arguments."""
        self._subparser = parser
        add_subparsers_on_demand(
            parser,
            cli_name,
            dest='_verb',
            group_name='nodl_to_policy.verb',
            required=False,
            argv=argv
        )

    def main(self, *, parser: argparse.ArgumentParser, args: Any) -> int:
        """Delegate to a verb's entrypoint, unless no verb was passed."""
        if not hasattr(args, '_verb'):
            # in case no verb was passed
            self._subparser.print_help()
            return 0
        extension = getattr(args, '_verb')

        # call the verb's main method
        return extension.main(args=args)
