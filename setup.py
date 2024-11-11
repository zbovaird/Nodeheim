# setup.py
from setuptools import setup, find_packages

setup(
    name="nodeheim",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'flask',
        'python-nmap',
        'ipaddress',
        'dataclasses',
        'python-dotenv',
    ],
)