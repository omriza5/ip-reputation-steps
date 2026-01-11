from setuptools import setup, find_packages

setup(
    name="ip-reputation-checker",
    version="1.0.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "httpx>=0.27.0",
        "pydantic>=2.5.0",
    ],
)