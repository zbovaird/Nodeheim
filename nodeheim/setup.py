from setuptools import setup, find_packages

setup(
    name="nodeheim",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'splunk-sdk>=1.7.3',
        'networkx>=2.8.4',
        'matplotlib>=3.5.2',
        'numpy>=1.21.0'
    ],
    author="Your Name",
    description="Network scanning and analysis tool for Splunk",
    python_requires='>=3.8'
) 