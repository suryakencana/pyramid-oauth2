import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.txt')).read()
CHANGES = open(os.path.join(here, 'CHANGES.txt')).read()

requires = [
    'Pyramid>=1.1a4',
    'akhet>=1.0.2',
    'sqlahelper',
    'sqlalchemy-migrate'
    ]

setup(name='pyramid_oauth2',
      version='0.0',
      description='OAuth 2.0 Provider for Pyramid 1.x',
      long_description=README + '\n\n' +  CHANGES,
      classifiers=[
        "Development Status :: 1 - Planning",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        
        ],
      author='Kevin Van Wilder',
      author_email='kevin@tick.ee',
      url='http://code.google.com/p/pyramid-oauth2/',
      keywords='oauth2, oauth, pyramid, authorization, tokens, access',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires = requires
)