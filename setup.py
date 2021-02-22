from distutils.core import setup
try:
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

setup(
    name='trimafl-cov',
    version='0.0.1',
    author='Wei-Cheng Wu',
    author_email='wwu@isi.edu',
    license='BSD',
    platforms=['Linux'],
    packages=packages,
    install_requires=[
        'angr',
        'tracer',
        'bingraphvis',
        'cfg-explorer'
    ],
    description='trimAFL visualization',
    long_description='trimAFL CFG visualization',
    url='https://github.com/usc-isi-bass/afl-cov',
)
