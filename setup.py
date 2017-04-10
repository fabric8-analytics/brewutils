#!/usr/bin/python
import setuptools
setuptools.setup(
    name = 'brewutils',
    version = '1.0.2',
    packages = setuptools.find_packages(),
    scripts = ['brew-utils-cli'],
    # functools32 is an unspecified dependency of `jsonschema`
    install_requires = ['requests', 'unidiff', 'jsonschema', 'functools32'],
    include_package_data = True,
    author = 'Pavel Odvody',
    author_email = 'podvody@redhat.com',
    description = 'Brew CLI Utilities',
    license = 'GNU/GPLv2',
    keywords = 'brew cli',
    url = 'https://'
)
