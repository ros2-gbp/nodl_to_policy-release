import os

from setuptools import setup


def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            if '.py' not in filename:
                paths.append(os.path.join('..', path, filename))
    return paths


extra_files = (
    package_files('nodl_to_policy/common')
)

package_name = 'nodl_to_policy'

setup(
    name=package_name,
    version='1.0.0',
    packages=[package_name],
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    author='Abrar Rahman Protyasha',
    author_email='abrar@openrobotics.org',
    maintainer='Abrar Rahman Protyasha',
    maintainer_email='abrar@openrobotics.org',
    url='https://github.com/osrf/nodl_to_policy',
    download_url='https://github.com/osrf/nodl_to_policy/releases',
    keywords=['ROS'],
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License 2.0',
        'Programming Language :: Python',
        'Topic :: Software Development',
    ],
    description='NoDL description to ROS 2 policy generator',
    long_description='Package to generate a ROS 2 Access Control Policy from \
    the NoDL description of a ROS system',
    license='Apache License 2.0',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
        ],
        'ros2cli.command': [
            'nodl_to_policy = nodl_to_policy.command.nodl_to_policy:NoDLToPolicyCommand',
        ],
        'nodl_to_policy.verb': [
            'convert = nodl_to_policy.verb.convert:ConvertVerb'
        ]
    },
    package_data={
        'nodl_to_policy': extra_files,
    },
)
