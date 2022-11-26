#-*- coding:utf-8 -*-
'''
Created on 2018-05-23

@author: ranyixu
'''

from setuptools import setup, find_packages

setup(
    name='aionmap',
    version='0.0.3',
    author='ranyixu',
    author_email='1015243376@qq.com',
    packages=find_packages(),
    include_package_data = True,
    zip_safe = False,
    keywords = ['nmap', 'asyncio'],
    install_requires = ["python-libnmap"],
    url='https://github.com/ranyixu/aionmap',
    description='A python nmap package seem to python-nmap(https://pypi.org/project/python-nmap/), but for asyncio',
    long_description = open('README.rst').read(),
    classifiers=[  
        "Intended Audience :: Developers",  
        "Operating System :: OS Independent",  
        "Topic :: System :: Networking",  
        "Topic :: Software Development :: Libraries :: Python Modules",  
        "Programming Language :: Python :: 3.4",  
        "Programming Language :: Python :: 3.5",  
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ]
)
