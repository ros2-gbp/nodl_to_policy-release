# nodl_to_policy

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build status](https://github.com/osrf/nodl_to_policy/actions/workflows/test.yml/badge.svg)](https://github.com/osrf/nodl_to_policy/actions/workflows/test.yml)

This repository contains tooling to generate a [ROS 2 Access Control Policy](https://design.ros2.org/articles/ros2_access_control_policies.html) from the [Node Interface Definition Language (NoDL)](https://github.com/ros2/design/pull/266) description of a ROS system (or that of a specific package), primarily to be used in conjunction with the `SROS2` utilities.

*Note*: This package targets ROS 2 Galactic Geochelone.

## Building

* Clone this repository to a ROS workspace: `git clone git@github.com:osrf/nodl_to_policy.git <ws/src>/nodl_to_policy`
* Install required dependencies: `rosdep install -yri --from-paths <ws/src> --rosdistro=galactic`
* Build with: `colcon build --symlink-install`

## Usage

### CLI

The `nodl_to_policy` package extends the ROS 2 CLI by adding a `nodl_to_policy` command, with an associated `convert` verb.
The expected use is as follows:

```bash
ros2 nodl_to_policy convert <path-to-NoDL-file (*.nodl.xml)>
```

Invoking the `convert` verb as above dumps the resulting access control policy in the console standard output.
If desired, this output can be redirected (`>`) to `<output>.policy.xml`.

### API

The NoDL &rarr; policy conversion method simply takes a NoDL description (type: `List[nodl.Node]`).
As such, the conversion API could be used programmatically as follows:

```python
from nodl_to_python.policy import convert_to_policy

# obtain a NoDL description, either through `nodl.parse(<nodl_file_path>)` or otherwise

policy = convert_to_policy(nodl_description)  # type(nodl_description) == List[nodl.Node]

# use policy, and/or output it using `nodl.dump_policy(policy, <output_stream>)`
```
