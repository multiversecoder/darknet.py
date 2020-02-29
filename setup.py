import pathlib
from setuptools import setup

README = f"{pathlib.Path(__file__).parent}/README.md"

with open(README) as r:
    README = r.read()

setup(
    name='darknet.py',
    version='1.1',
    author='Adriano Romanazzo (multiversecoder)',
    description='darknet.py is a network application with no dependencies other than Python and Tor, useful to anonymize the traffic of linux servers and workstations.',
    long_description=README,
    long_description_content_type="text/markdown",
    author_email='pythonmultiverse@gmx.com',
    url='https://github.com/multiversecoder/darknet.py',
    scripts=['bin/darknet.py'],
    license='BSD 3-Clause License'
)
