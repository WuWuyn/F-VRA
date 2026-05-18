from setuptools import setup, find_packages

setup(
    package_dir={"pyshare": "src"},
    packages=["pyshare"] + ["pyshare." + pkg for pkg in find_packages("src")],
)
