from setuptools import setup

setup(name='dnssecscheck',
      version='0.1.0',
      packages=['dnsseccheck'],
      entry_points={
          'console_scripts': [
              'dnssec_check = dnsseccheck.dnssecchecks:main'
          ]
      },
    install_requires=[
          'dnspython',
      ],
      )