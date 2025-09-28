#!/usr/bin/env python3
"""
Setup script for shellai package
"""

from setuptools import setup, find_packages
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read requirements
def read_requirements(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

install_requires = [
    'torch>=2.8.0',
    'transformers>=4.20.0',
    'psutil>=7.1.0',
]

test_requires = read_requirements('requirements.txt')

setup(
    name='shellai',
    version='0.1.0',
    author='micrictor',
    description='AI-powered shell command generation using local models',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/micrictor/shellai',
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: System :: Shells',
        'Topic :: Utilities',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',
    ],
    python_requires='>=3.8',
    install_requires=install_requires,
    extras_require={
        'dev': [
            'black',
            'flake8',
            'mypy',
            'pre-commit',
        ],
    },
    entry_points={
        'console_scripts': [
            'shellai=shellai:main',
            'ai=shellai:main',
        ],
    },
    keywords=['ai', 'shell', 'command-line', 'automation', 'llm'],
    project_urls={
        'Homepage': 'https://github.com/micrictor/shellai',
        'Repository': 'https://github.com/micrictor/shellai',
        'Issues': 'https://github.com/micrictor/shellai/issues',
    },
)