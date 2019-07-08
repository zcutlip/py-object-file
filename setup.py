from setuptools import setup, find_packages
about = {}
with open("pyobjfile/__about__.py") as fp:
    exec(fp.read(), about)

setup(name=about["__title__"],
      version=about["__version__"],
      description=about["__summary__"],
      url="https://github.com/zcutlip/py-object-file",
      packages=find_packages(),
      python_requires='>=2.7',
      install_requires=["py-dwarf"]
      )
