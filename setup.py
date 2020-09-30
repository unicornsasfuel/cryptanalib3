from setuptools import setup, find_packages

with open('README.md','r') as fh:
      long_description=fh.read()

setup(name='cryptanalib3',
      version='1.0.0b',
      description='A Python3 fork of the Cryptanalib cryptanalysis module from FeatherDuster',
      url='http://github.com/unicornsasfuel/cryptanalib3',
      author='Daniel "unicornfurnace" Crowley',
      license='BSD',
      long_description=long_description,
      long_description_content_type='text/markdown',
      packages=find_packages(exclude=['examples','tests']),
      install_requires=[
          'pycryptodome'
      ],
      python_requires='>=3.6',
      classifiers=[
         "Programming Language :: Python :: 3",
         "Operating System :: OS Independent"
      ],
      zip_safe=True)
