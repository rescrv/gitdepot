#!/usr/bin/python
from setuptools import setup, find_packages

setup(name = 'gitdepot',
      version = '0.1.31',
      description = 'A simple git repository management system',
      url = 'http://rescrv.net/',
      author = 'Robert Escriva',
      author_email = 'robert@rescrv.net',
      license = 'BSD',
      keywords = 'git',
      packages = find_packages(),
      install_requires = ['ply'],
      entry_points = {
          'console_scripts': ['gitdepot = gitdepot:main']
          }
      )
