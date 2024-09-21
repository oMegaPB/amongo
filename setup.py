from setuptools import setup

setup(
    name="amongo",
    version="0.3.2",
    install_requires=["pymongo", "attrs"],
    packages=['amongo'],
    description="small mongodb driver for local mongod",
    author="oMegaPB",
    url="https://github.com/oMegaPB/amongo",
)
