from setuptools import setup

setup(name='dnsseccheck',
      version='0.0.2',
      author="O. Schacher",
      author_email="oli@fuglu.org",
      description='Analyze DNSSEC configuration of a Zone and validate it against best current practises',
      url='https://github.com/gryphius/dnssecscore_backend',
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