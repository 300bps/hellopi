from setuptools import setup

setup(
    name='hellopi',
    version='1.0',
    author='David Smith',
    author_email='x300bps@icloud.com',
    url='https://github.com/300bps/hellopi',
    license='MIT',
    description='A program to identify the ip address of Raspberry Pis (or other devices) added to the local area network.',
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    py_modules=["hellopi"],
    packages=['ipxray'],
    entry_points={'console_scripts': ['hellopi=hellopi:main']},
    keywords=['raspberry pi', 'networking', 'dhcp', 'ip', 'ip address', 'discovery',
              'device discovery', 'device', 'linux', 'windows'],
    classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: POSIX :: BSD",
            "Operating System :: POSIX :: Linux",
            "Operating System :: MacOS :: MacOS X",
            "Operating System :: Microsoft :: Windows",
            "Topic :: System :: Hardware",
            "Topic :: System :: Networking",
            "Topic :: System :: Networking :: Monitoring",
    ]
)
