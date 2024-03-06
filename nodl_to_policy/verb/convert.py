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
import pathlib
import sys

from argcomplete.completers import FilesCompleter
import nodl
from nodl._index import _FILE_EXTENSION as _NODL_FILE_EXTENSION
from nodl_to_policy.policy import (
    convert_to_policy,
    print_policy,
)
from ros2cli.verb import VerbExtension


class ConvertVerb(VerbExtension):
    """Convert NoDL XML documents to ROS 2 Access Control Policies."""

    def add_arguments(self, parser: argparse.ArgumentParser, cli_name: None = None) -> None:
        """Argument addition for the `convert` verb."""
        parser.add_argument(
            'nodl_file',
            help='Path of the input NoDL description XML (`.nodl.xml`) file.',
            type=pathlib.Path
        ).completer = FilesCompleter(  # type: ignore
            allowednames=[_NODL_FILE_EXTENSION], directories=False)

    def main(self, *, args: argparse.Namespace) -> int:
        """High level logic employed by the `convert` verb."""
        nodl_file_path = args.nodl_file
        if not nodl_file_path:
            print('No files to validate', file=sys.stderr)
            return 1

        if not nodl_file_path.is_file():
            print(f'{nodl_file_path} is not a file')
            return 1

        try:
            nodl_description = nodl.parse(path=nodl_file_path)
        except nodl.errors.InvalidNoDLError as e:
            print(f'Failed to parse {nodl_file_path}', file=sys.stderr)
            print(e, file=sys.stderr)
            return 1

        print_policy(convert_to_policy(nodl_description))

        return 0
